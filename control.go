// SPDX-License-Identifier: BSD-3-Clause

// Package control is the listener for a daemon's gRPC admin (control-plane)
// API: the port an operator's CLI talks to, as opposed to the one the
// daemon's users talk to.
//
// An admin API can reconfigure, drain or stop the daemon, so the question
// "who may reach it" has only two acceptable answers, and this package
// accepts no other:
//
//   - a unix socket, whose file mode is its access control: it is left at
//     0600, owned by the daemon's user, and nobody else can connect;
//   - TCP with mutual TLS: the client must present a certificate signed by
//     a CA the daemon names, and the daemon presents one signed by a CA the
//     client names.
//
// There is no plaintext TCP, and loopback is not an exception: any local
// user can connect to 127.0.0.1, so loopback without client certificates is
// an admin API open to every account on the machine.
//
// # Use
//
//	cfg := control.Config{Listen: "unix:///run/mydaemon/admin.sock"}
//	if err := cfg.Check(); err != nil { ... }   // at config load, no side effects
//	lis, opts, err := control.Listen(cfg)
//	gs := grpc.NewServer(opts...)
//	adminpb.RegisterAdminServer(gs, impl)
//	go gs.Serve(lis)
//
// and in a handler, for the audit line:
//
//	log.Printf("admin: %s called Drain", control.Caller(ctx))
//
// which prints "uid=1000" for a unix caller and "cn=ops-laptop" for an mTLS
// one.
package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Config says where the admin API listens.
type Config struct {
	// Listen is "unix:///abs/path.sock" or "host:port".
	Listen string

	// TLSCertFile and TLSKeyFile are the server's certificate and key, and
	// ClientCAFile the CA bundle client certificates must chain to. All three
	// are required together for TCP and forbidden for unix: a socket's
	// permissions are its access control.
	TLSCertFile, TLSKeyFile, ClientCAFile string
}

// endpoint is a parsed Listen or Target string.
type endpoint struct {
	unix bool
	path string // unix: absolute socket path
	addr string // tcp: host:port
}

// parseEndpoint accepts "unix:///abs", "unix:/abs" and "host:port". Any other
// scheme is refused rather than guessed at, and so is a relative socket path:
// a daemon's working directory is not a place anyone should have to know.
func parseEndpoint(s string) (endpoint, error) {
	if s == "" {
		return endpoint{}, errors.New("control: no listen address")
	}
	if rest, ok := strings.CutPrefix(s, "unix:"); ok {
		if r, ok := strings.CutPrefix(rest, "//"); ok {
			rest = r
		}
		rest = windowsDrivePath(runtime.GOOS, rest)
		if rest == "" {
			return endpoint{}, fmt.Errorf("control: %q names no socket path", s)
		}
		if !filepath.IsAbs(rest) {
			return endpoint{}, fmt.Errorf("control: socket path in %q is not absolute", s)
		}
		return endpoint{unix: true, path: filepath.Clean(rest)}, nil
	}
	if i := strings.Index(s, "://"); i >= 0 {
		return endpoint{}, fmt.Errorf("control: unknown scheme %q in %q (want unix:// or host:port)", s[:i], s)
	}
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return endpoint{}, fmt.Errorf("control: %q is neither unix:///path nor host:port: %v", s, err)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return endpoint{}, fmt.Errorf("control: port %q in %q is not a number from 0 to 65535", port, s)
	}
	return endpoint{addr: s}, nil
}

// windowsDrivePath turns "/C:/x" into "C:/x", so that "unix:///C:/x.sock"
// names an absolute path on Windows the way "unix:///x.sock" does elsewhere.
func windowsDrivePath(goos, p string) string {
	if goos == "windows" && len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		return p[1:]
	}
	return p
}

// checkTLS enforces "all three for TCP, none for unix".
func checkTLS(ep endpoint, what string, files [3]string, names [3]string) error {
	if ep.unix {
		var set []string
		for i, f := range files {
			if f != "" {
				set = append(set, names[i])
			}
		}
		if len(set) > 0 {
			return fmt.Errorf("control: %s is a unix socket, whose file mode is its access control; %s must be empty",
				what, strings.Join(set, ", "))
		}
		return nil
	}
	var missing []string
	for i, f := range files {
		if f == "" {
			missing = append(missing, names[i])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("control: %s is TCP, which requires mutual TLS (loopback included: any local user can reach it); missing %s",
			what, strings.Join(missing, ", "))
	}
	return nil
}

// Check refuses a Config that cannot be served safely, without touching the
// network or the filesystem, so that it can run when configuration is
// loaded: TCP without all three TLS files (loopback included), unix with any
// of them, a relative socket path, or an unknown scheme.
func (c Config) Check() error {
	_, err := c.check()
	return err
}

func (c Config) check() (endpoint, error) {
	ep, err := parseEndpoint(c.Listen)
	if err != nil {
		return ep, err
	}
	return ep, checkTLS(ep, fmt.Sprintf("listen address %q", c.Listen),
		[3]string{c.TLSCertFile, c.TLSKeyFile, c.ClientCAFile},
		[3]string{"TLSCertFile", "TLSKeyFile", "ClientCAFile"})
}

// Listen binds the admin listener and returns it with the grpc.ServerOptions
// (transport credentials) to pass to grpc.NewServer. It runs Check first.
//
// For unix, the socket is bound inside a fresh 0700 directory next to the
// requested path, chmod'ed to 0600 there, and only then hard-linked into
// place, so it is never reachable by another user, not even for the instant
// between bind and chmod — see bindUnix. The process umask is not touched:
// it is process-wide, and changing it around bind would silently change the
// mode of every file other goroutines create meanwhile. A socket file
// already at the path is removed only if nothing answers on it; a live one
// is an error naming the path, and anything that is not a socket is never
// removed. Closing the listener removes the socket file, if it is still the
// one this call created.
//
// For TCP, the server presents TLSCertFile/TLSKeyFile, requires and
// verifies a client certificate against ClientCAFile, and accepts TLS 1.2
// at the least (TLS 1.3 is negotiated whenever the client offers it).
func Listen(c Config) (net.Listener, []grpc.ServerOption, error) {
	ep, err := c.check()
	if err != nil {
		return nil, nil, err
	}
	if ep.unix {
		lis, err := listenUnix(ep.path)
		if err != nil {
			return nil, nil, err
		}
		return lis, []grpc.ServerOption{grpc.Creds(unixCreds{})}, nil
	}
	cfg, err := serverTLS(c)
	if err != nil {
		return nil, nil, err
	}
	lis, err := net.Listen("tcp", ep.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("control: %w", err)
	}
	return lis, []grpc.ServerOption{grpc.Creds(credentials.NewTLS(cfg))}, nil
}

func serverTLS(c Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("control: server certificate: %w", err)
	}
	pool, err := loadPool(c.ClientCAFile, "ClientCAFile")
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

func loadPool(file, name string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("control: %s: %w", name, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("control: %s %s holds no PEM certificate", name, file)
	}
	return pool, nil
}

// Caller says who made the RPC whose context this is, for an audit line:
// "cn=<subject CN>" for an mTLS client (the whole subject if its CN is
// empty), "uid=<uid>" for a unix client — read from the kernel when the
// connection was accepted (SO_PEERCRED on Linux, LOCAL_PEERCRED on darwin
// and FreeBSD) — or "unix" where the platform cannot say (Windows, and the
// BSDs without LOCAL_PEERCRED). It returns "unknown" when the context
// carries neither.
func Caller(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "unknown"
	}
	switch ai := p.AuthInfo.(type) {
	case credentials.TLSInfo:
		certs := ai.State.PeerCertificates
		if len(ai.State.VerifiedChains) > 0 && len(ai.State.VerifiedChains[0]) > 0 {
			certs = ai.State.VerifiedChains[0]
		}
		if len(certs) == 0 {
			return "unknown"
		}
		if cn := certs[0].Subject.CommonName; cn != "" {
			return "cn=" + cn
		}
		return "cn=" + certs[0].Subject.String()
	case unixAuthInfo:
		if ai.uidKnown {
			return "uid=" + strconv.FormatUint(uint64(ai.uid), 10)
		}
		return "unix"
	}
	return "unknown"
}

// ClientConfig says how to reach an admin API: for tests, CLIs, and the
// consumers' own tests.
type ClientConfig struct {
	// Target has the syntax of Config.Listen.
	Target string

	// CertFile and KeyFile are the client's certificate and key, and
	// ServerCAFile the CA that signed the server's certificate. All three are
	// required for TCP and forbidden for unix.
	CertFile, KeyFile, ServerCAFile string

	// ServerName is the name to verify the server's certificate against. It
	// defaults to the host in Target.
	ServerName string

	// ServerUID is, for a unix Target, a uid the server may run as besides
	// this process's own uid and root's, which are always accepted. Dial
	// checks who is listening on the socket (the kernel's peer credentials)
	// and refuses any other uid: a socket in a directory others can write may
	// have been bound by an impostor, which would otherwise receive the CLI's
	// commands. Forbidden for TCP, where the server's certificate is the
	// check. On a platform without peer credentials (Windows, and the BSDs
	// other than FreeBSD) the uid cannot be read and is not checked.
	ServerUID *uint32
}

// Dial returns a client connection to an admin API. As with grpc.NewClient,
// nothing is connected until the first RPC; what fails here is a
// configuration that could never work, and unreadable files.
//
// For a unix target, each connection is refused unless the process
// listening on the socket runs as this process's uid, as root, or as
// ClientConfig.ServerUID: the RPC then fails with an error naming the uid
// found.
func Dial(c ClientConfig, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	ep, err := parseEndpoint(c.Target)
	if err != nil {
		return nil, err
	}
	if err := checkTLS(ep, fmt.Sprintf("target %q", c.Target),
		[3]string{c.CertFile, c.KeyFile, c.ServerCAFile},
		[3]string{"CertFile", "KeyFile", "ServerCAFile"}); err != nil {
		return nil, err
	}
	if !ep.unix && c.ServerUID != nil {
		return nil, fmt.Errorf("control: target %q is TCP, where the server's certificate is the check; ServerUID must be nil", c.Target)
	}
	if ep.unix {
		path := ep.path
		base := []grpc.DialOption{
			grpc.WithTransportCredentials(unixCreds{serverUID: c.ServerUID}),
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			}),
		}
		// The dialer ignores the address; "localhost" is what gRPC itself
		// uses as the :authority of a unix target.
		return grpc.NewClient("passthrough:///localhost", append(base, opts...)...)
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("control: client certificate: %w", err)
	}
	pool, err := loadPool(c.ServerCAFile, "ServerCAFile")
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   c.ServerName,
	}
	base := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(cfg))}
	return grpc.NewClient("passthrough:///"+ep.addr, append(base, opts...)...)
}
