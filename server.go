package socks5

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/things-go/go-socks5/bufferpool"
	"github.com/things-go/go-socks5/statute"
)

// GPool is used to implement custom goroutine pool default use goroutine
type GPool interface {
	Submit(f func()) error
}

// Interceptor is an interface that defines methods for intercepting
// SOCKS5 requests and responses.
type Interceptor interface {
	// OnRequest is called when a SOCKS5 request is intercepted.
	// The request parameter contains information about the intercepted request.
	// The src parameter is the connection that the request was received on.
	// The dst parameter is the connection that the request was sent on.
	// The method should return an error if the request should be rejected.
	// The method should return a non-nil byte slice if the request should be
	// modified. The byte slice will be sent to the client as the response.
	OnRequest(ctx context.Context, request []byte, src net.Conn, dst net.Conn) ([]byte, error)

	// OnResponse is called when a SOCKS5 response is intercepted.
	// The response parameter contains information about the intercepted response.
	// The src parameter is the connection that the response was sent on.
	// The dst parameter is the connection that the response was received on.
	// The method should return an error if the response should be rejected.
	// The method should return a non-nil byte slice if the response should be
	// modified. The byte slice will be sent to the client as the response.
	OnResponse(ctx context.Context, response []byte, src net.Conn, dst net.Conn) ([]byte, error)

	OnRequestEnd(ctx context.Context, src net.Conn, dst net.Conn) error
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	// authMethods can be provided to implement authentication
	// By default, "no-auth" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	authMethods []Authenticator
	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and authMethods is nil, then "no-auth" mode is enabled.
	credentials CredentialStore
	// resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	resolver NameResolver
	// rules is provided to enable custom logic around permitting
	// various commands. If not provided, NewPermitAll is used.
	rules RuleSet
	// rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	rewriter AddressRewriter
	// bindIP is used for bind or udp associate
	bindIP net.IP
	// logger can be used to provide a custom log target.
	// Defaults to io.Discard.
	logger Logger
	// Optional function for dialing out
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// buffer pool
	bufferPool bufferpool.BufPool
	// interceptor
	interceptor *Interceptor
	// goroutine pool
	gPool GPool
	// user's handle
	userConnectHandle   func(ctx context.Context, writer io.Writer, request *Request) error
	userBindHandle      func(ctx context.Context, writer io.Writer, request *Request) error
	userAssociateHandle func(ctx context.Context, writer io.Writer, request *Request) error

	// TLS certificate to use for TLS-based connections
	TLSRootCertificate *tls.Certificate
	// Private key to use for TLS-based connections
	TLSPrivateKey []byte
}

// NewServer creates a new Server
func NewServer(opts ...Option) *Server {
	srv := &Server{
		authMethods: []Authenticator{},
		bufferPool:  bufferpool.NewPool(32 * 1024),
		resolver:    DNSResolver{},
		rules:       NewPermitAll(),
		logger:      NewLogger(log.New(io.Discard, "socks5: ", log.LstdFlags)),
		dial: func(ctx context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		},
	}

	for _, opt := range opts {
		opt(srv)
	}

	// Ensure we have at least one authentication method enabled
	if (len(srv.authMethods) == 0) && srv.credentials != nil {
		srv.authMethods = []Authenticator{&UserPassAuthenticator{srv.credentials}}
	}
	if len(srv.authMethods) == 0 {
		srv.authMethods = []Authenticator{&NoAuthAuthenticator{}}
	}

	return srv
}

// ListenAndServe is used to create a listener and serve on it
func (sf *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return sf.Serve(l)
}

// Serve is used to serve connections from a listener
func (sf *Server) Serve(l net.Listener) error {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		sf.goFunc(func() {
			if err := sf.ServeConn(conn); err != nil {
			}
		})
	}
}

// ServeConn is used to serve a single connection.
func (sf *Server) ServeConn(conn net.Conn) error {
	var authContext *AuthContext

	defer conn.Close()

	bufConn := bufio.NewReader(conn)

	mr, err := statute.ParseMethodRequest(bufConn)
	if err != nil {
		return err
	}
	if mr.Ver != statute.VersionSocks5 {
		return statute.ErrNotSupportVersion
	}

	// Authenticate the connection
	userAddr := ""
	if conn.RemoteAddr() != nil {
		userAddr = conn.RemoteAddr().String()
	}
	authContext, err = sf.authenticate(conn, bufConn, userAddr, mr.Methods)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// The client request detail
	request, err := ParseRequest(conn)
	if err != nil {
		if errors.Is(err, statute.ErrUnrecognizedAddrType) {
			if err := SendReply(conn, statute.RepAddrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("failed to send reply %w", err)
			}
		}
		return fmt.Errorf("failed to read destination address, %w", err)
	}

	if request.Request.Command != statute.CommandConnect &&
		request.Request.Command != statute.CommandBind &&
		request.Request.Command != statute.CommandAssociate {
		if err := SendReply(conn, statute.RepCommandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply, %v", err)
		}
		return fmt.Errorf("unrecognized command[%d]", request.Request.Command)
	}

	request.AuthContext = authContext
	request.LocalAddr = conn.LocalAddr()
	request.RemoteAddr = conn.RemoteAddr()
	// Process the client request
	return sf.handleRequest(conn, request)
}

// authenticate is used to handle connection authentication
func (sf *Server) authenticate(conn io.Writer, bufConn io.Reader,
	userAddr string, methods []byte) (*AuthContext, error) {
	// Select a usable method
	for _, auth := range sf.authMethods {
		for _, method := range methods {
			if auth.GetCode() == method {
				return auth.Authenticate(bufConn, conn, userAddr)
			}
		}
	}
	// No usable method found
	conn.Write([]byte{statute.VersionSocks5, statute.MethodNoAcceptable}) //nolint: errcheck
	return nil, statute.ErrNoSupportedAuth
}

func (sf *Server) goFunc(f func()) {
	if sf.gPool == nil || sf.gPool.Submit(f) != nil {
		go f()
	}
}
