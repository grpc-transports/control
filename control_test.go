// SPDX-License-Identifier: BSD-3-Clause

package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

// ---- Check ----------------------------------------------------------------

func TestCheckMatrix(t *testing.T) {
	sock := "unix://" + filepath.ToSlash(absSock())
	cases := []struct {
		name            string
		cfg             Config
		ok              bool
		wantErrContains string
	}{
		// Allowed.
		{"unix triple slash", Config{Listen: sock}, true, ""},
		{"unix single slash", Config{Listen: "unix:" + strings.TrimPrefix(sock, "unix://")}, true, ""},
		{"tcp loopback with mTLS", Config{Listen: "127.0.0.1:8443", TLSCertFile: "c", TLSKeyFile: "k", ClientCAFile: "ca"}, true, ""},
		{"tcp all interfaces with mTLS", Config{Listen: ":8443", TLSCertFile: "c", TLSKeyFile: "k", ClientCAFile: "ca"}, true, ""},
		{"tcp ipv6 with mTLS", Config{Listen: "[::1]:0", TLSCertFile: "c", TLSKeyFile: "k", ClientCAFile: "ca"}, true, ""},

		// TCP without all three TLS files: loopback is not an exception.
		{"tcp loopback plaintext", Config{Listen: "127.0.0.1:8443"}, false, "loopback included"},
		{"tcp localhost plaintext", Config{Listen: "localhost:8443"}, false, "missing TLSCertFile, TLSKeyFile, ClientCAFile"},
		{"tcp ipv6 loopback plaintext", Config{Listen: "[::1]:8443"}, false, "requires mutual TLS"},
		{"tcp no client CA", Config{Listen: "127.0.0.1:8443", TLSCertFile: "c", TLSKeyFile: "k"}, false, "missing ClientCAFile"},
		{"tcp no key", Config{Listen: "127.0.0.1:8443", TLSCertFile: "c", ClientCAFile: "ca"}, false, "missing TLSKeyFile"},
		{"tcp no cert", Config{Listen: "127.0.0.1:8443", TLSKeyFile: "k", ClientCAFile: "ca"}, false, "missing TLSCertFile"},
		{"tcp only CA", Config{Listen: "127.0.0.1:8443", ClientCAFile: "ca"}, false, "missing TLSCertFile, TLSKeyFile"},

		// Unix with any TLS file.
		{"unix with cert", Config{Listen: sock, TLSCertFile: "c"}, false, "TLSCertFile must be empty"},
		{"unix with key", Config{Listen: sock, TLSKeyFile: "k"}, false, "TLSKeyFile must be empty"},
		{"unix with CA", Config{Listen: sock, ClientCAFile: "ca"}, false, "ClientCAFile must be empty"},
		{"unix with all three", Config{Listen: sock, TLSCertFile: "c", TLSKeyFile: "k", ClientCAFile: "ca"}, false, "TLSCertFile, TLSKeyFile, ClientCAFile must be empty"},

		// Unix path shape.
		{"unix relative", Config{Listen: "unix://admin.sock"}, false, "not absolute"},
		{"unix relative single", Config{Listen: "unix:admin.sock"}, false, "not absolute"},
		{"unix dot relative", Config{Listen: "unix://./admin.sock"}, false, "not absolute"},
		{"unix empty", Config{Listen: "unix://"}, false, "names no socket path"},
		{"unix bare", Config{Listen: "unix:"}, false, "names no socket path"},

		// Unknown schemes and malformed addresses.
		{"empty", Config{}, false, "no listen address"},
		{"unix-abstract", Config{Listen: "unix-abstract://x"}, false, "unknown scheme \"unix-abstract\""},
		{"https", Config{Listen: "https://127.0.0.1:8443", TLSCertFile: "c", TLSKeyFile: "k", ClientCAFile: "ca"}, false, "unknown scheme \"https\""},
		{"tcp scheme", Config{Listen: "tcp://127.0.0.1:8443"}, false, "unknown scheme \"tcp\""},
		{"dns scheme", Config{Listen: "dns:///localhost:8443"}, false, "unknown scheme \"dns\""},
		{"no port", Config{Listen: "127.0.0.1"}, false, "neither unix:///path nor host:port"},
		{"bare path", Config{Listen: "/run/admin.sock"}, false, "neither unix:///path nor host:port"},
		{"port not a number", Config{Listen: "127.0.0.1:http", TLSCertFile: "c", TLSKeyFile: "k", ClientCAFile: "ca"}, false, "not a number"},
		{"port too big", Config{Listen: "127.0.0.1:65536", TLSCertFile: "c", TLSKeyFile: "k", ClientCAFile: "ca"}, false, "not a number"},
		{"port empty", Config{Listen: "127.0.0.1:", TLSCertFile: "c", TLSKeyFile: "k", ClientCAFile: "ca"}, false, "not a number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Check()
			if tc.ok {
				if err != nil {
					t.Fatalf("Check(%+v) = %v, want nil", tc.cfg, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Check(%+v) = nil, want an error containing %q", tc.cfg, tc.wantErrContains)
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("Check(%+v) = %q, want it to contain %q", tc.cfg, err, tc.wantErrContains)
			}
		})
	}
}

// Check must not touch the filesystem: an allowed config naming files that
// do not exist passes, and a unix path in a directory that does not exist
// passes too — Listen is where those fail.
func TestCheckTouchesNothing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	for _, c := range []Config{
		{Listen: "unix://" + filepath.ToSlash(filepath.Join(missing, "a.sock"))},
		{Listen: "127.0.0.1:1", TLSCertFile: missing, TLSKeyFile: missing, ClientCAFile: missing},
	} {
		if err := c.Check(); err != nil {
			t.Errorf("Check(%+v) = %v", c, err)
		}
		if _, err := os.Stat(missing); !os.IsNotExist(err) {
			t.Fatalf("Check created %s", missing)
		}
	}
}

func TestWindowsDrivePath(t *testing.T) {
	for _, tc := range []struct{ goos, in, want string }{
		{"windows", "/C:/x.sock", "C:/x.sock"},
		{"windows", "/x.sock", "/x.sock"},
		{"windows", "/C", "/C"},
		{"linux", "/C:/x.sock", "/C:/x.sock"},
	} {
		if got := windowsDrivePath(tc.goos, tc.in); got != tc.want {
			t.Errorf("windowsDrivePath(%s, %q) = %q, want %q", tc.goos, tc.in, got, tc.want)
		}
	}
}

// ---- certificates ---------------------------------------------------------

type pki struct {
	dir                       string
	caFile                    string
	serverCert, serverKey     string
	clientCert, clientKey     string
	noCNCert, noCNKey         string
	otherCAFile               string
	strangerCert, strangerKey string
	ca                        *x509.Certificate
	caKey                     *ecdsa.PrivateKey
}

var serial int64 = 1

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newCA(t *testing.T, dir, name string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key := newKey(t)
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	file := filepath.Join(dir, name+".pem")
	writePEM(t, file, "CERTIFICATE", der)
	return cert, key, file
}

func issue(t *testing.T, dir, name string, subject pkix.Name, ca *x509.Certificate, caKey *ecdsa.PrivateKey, server bool) (string, string) {
	t.Helper()
	key := newKey(t)
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cf, kf := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	writePEM(t, cf, "CERTIFICATE", der)
	writePEM(t, kf, "PRIVATE KEY", kder)
	return cf, kf
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{dir: t.TempDir()}
	p.ca, p.caKey, p.caFile = newCA(t, p.dir, "admin-ca")
	p.serverCert, p.serverKey = issue(t, p.dir, "server", pkix.Name{CommonName: "daemon"}, p.ca, p.caKey, true)
	p.clientCert, p.clientKey = issue(t, p.dir, "client", pkix.Name{CommonName: "ops-laptop"}, p.ca, p.caKey, false)
	p.noCNCert, p.noCNKey = issue(t, p.dir, "nocn", pkix.Name{Organization: []string{"Ops"}, OrganizationalUnit: []string{"oncall"}}, p.ca, p.caKey, false)
	other, otherKey, otherFile := newCA(t, p.dir, "other-ca")
	p.otherCAFile = otherFile
	p.strangerCert, p.strangerKey = issue(t, p.dir, "stranger", pkix.Name{CommonName: "ops-laptop"}, other, otherKey, false)
	return p
}

// ---- a served health service that records Caller ----------------------------

type recorder struct {
	mu      sync.Mutex
	callers []string
	peers   []*peer.Peer
}

func (r *recorder) intercept(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	p, _ := peer.FromContext(ctx)
	r.mu.Lock()
	r.callers = append(r.callers, Caller(ctx))
	r.peers = append(r.peers, p)
	r.mu.Unlock()
	return h(ctx, req)
}

func (r *recorder) last(t *testing.T) (string, *peer.Peer) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.callers) == 0 {
		t.Fatal("no RPC reached the server")
	}
	return r.callers[len(r.callers)-1], r.peers[len(r.peers)-1]
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.callers)
}

func serve(t *testing.T, c Config) (net.Listener, *recorder) {
	t.Helper()
	lis, opts, err := Listen(c)
	if err != nil {
		t.Fatalf("Listen(%+v): %v", c, err)
	}
	rec := &recorder{}
	gs := grpc.NewServer(append(opts, grpc.UnaryInterceptor(rec.intercept))...)
	healthpb.RegisterHealthServer(gs, health.NewServer())
	done := make(chan struct{})
	go func() { defer close(done); gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); <-done })
	return lis, rec
}

func healthCheck(t *testing.T, cc *grpc.ClientConn) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
	if err == nil && resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health status %v", resp.GetStatus())
	}
	return err
}

func tcpServer(t *testing.T, p *pki) (string, *recorder) {
	t.Helper()
	lis, rec := serve(t, Config{Listen: "127.0.0.1:0", TLSCertFile: p.serverCert, TLSKeyFile: p.serverKey, ClientCAFile: p.caFile})
	return lis.Addr().String(), rec
}

// rawTLSClient dials with a hand-built TLS config, to present what Dial
// would never let a caller present.
func rawTLSClient(t *testing.T, addr string, cfg *tls.Config) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	return cc
}

func caPool(t *testing.T, file string) *x509.CertPool {
	t.Helper()
	pool, err := loadPool(file, "test CA")
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func keyPair(t *testing.T, cert, key string) tls.Certificate {
	t.Helper()
	kp, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// ---- mTLS -------------------------------------------------------------------

func TestMTLSRoundTrip(t *testing.T) {
	p := newPKI(t)
	addr, rec := tcpServer(t, p)

	cc, err := Dial(ClientConfig{Target: addr, CertFile: p.clientCert, KeyFile: p.clientKey, ServerCAFile: p.caFile})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if err := healthCheck(t, cc); err != nil {
		t.Fatalf("the right client certificate was refused: %v", err)
	}
	caller, pr := rec.last(t)
	if caller != "cn=ops-laptop" {
		t.Fatalf("Caller = %q, want cn=ops-laptop", caller)
	}
	st := pr.AuthInfo.(credentials.TLSInfo).State
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS %x, want 1.3 when both sides offer it", st.Version)
	}
}

func TestMTLSRefusals(t *testing.T) {
	p := newPKI(t)
	addr, rec := tcpServer(t, p)
	roots := caPool(t, p.caFile)

	t.Run("no client certificate", func(t *testing.T) {
		cc := rawTLSClient(t, addr, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
		if err := healthCheck(t, cc); err == nil {
			t.Fatal("a client with no certificate was served")
		}
	})
	t.Run("certificate from another CA", func(t *testing.T) {
		cc, err := Dial(ClientConfig{Target: addr, CertFile: p.strangerCert, KeyFile: p.strangerKey, ServerCAFile: p.caFile})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		if err := healthCheck(t, cc); err == nil {
			t.Fatal("a certificate from another CA, with the same CN, was served")
		}
	})
	t.Run("TLS 1.1", func(t *testing.T) {
		cc := rawTLSClient(t, addr, &tls.Config{
			RootCAs: roots, ServerName: "127.0.0.1", MaxVersion: tls.VersionTLS11,
			Certificates: []tls.Certificate{keyPair(t, p.clientCert, p.clientKey)},
		})
		if err := healthCheck(t, cc); err == nil {
			t.Fatal("TLS 1.1 was accepted")
		}
	})
	if n := rec.count(); n != 0 {
		t.Fatalf("%d refused RPCs reached the handler", n)
	}

	// Positive controls on the same server: the refusals above are about
	// what those clients presented, not a server that refuses everyone.
	t.Run("control: TLS 1.2 with the right certificate", func(t *testing.T) {
		cc := rawTLSClient(t, addr, &tls.Config{
			RootCAs: roots, ServerName: "127.0.0.1", MaxVersion: tls.VersionTLS12,
			Certificates: []tls.Certificate{keyPair(t, p.clientCert, p.clientKey)},
		})
		if err := healthCheck(t, cc); err != nil {
			t.Fatalf("TLS 1.2 with the right certificate was refused: %v", err)
		}
	})
	t.Run("control: certificate without a CN", func(t *testing.T) {
		cc, err := Dial(ClientConfig{Target: addr, CertFile: p.noCNCert, KeyFile: p.noCNKey, ServerCAFile: p.caFile, ServerName: "localhost"})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		if err := healthCheck(t, cc); err != nil {
			t.Fatal(err)
		}
		if caller, _ := rec.last(t); caller != "cn=OU=oncall,O=Ops" {
			t.Fatalf("Caller = %q, want the subject string", caller)
		}
	})
}

// The client verifies the server too: a server CA the client does not name
// is refused.
func TestDialVerifiesServer(t *testing.T) {
	p := newPKI(t)
	addr, rec := tcpServer(t, p)
	cc, err := Dial(ClientConfig{Target: addr, CertFile: p.clientCert, KeyFile: p.clientKey, ServerCAFile: p.otherCAFile})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if err := healthCheck(t, cc); err == nil {
		t.Fatal("a server certificate from an unnamed CA was trusted")
	}
	if rec.count() != 0 {
		t.Fatal("the RPC reached the server")
	}
}

func TestListenTCPErrors(t *testing.T) {
	p := newPKI(t)
	notPEM := filepath.Join(p.dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	good := Config{Listen: "127.0.0.1:0", TLSCertFile: p.serverCert, TLSKeyFile: p.serverKey, ClientCAFile: p.caFile}
	for name, tc := range map[string]struct {
		mut  func(*Config)
		want string
	}{
		"check":        {func(c *Config) { c.ClientCAFile = "" }, "missing ClientCAFile"},
		"missing cert": {func(c *Config) { c.TLSCertFile = filepath.Join(p.dir, "absent") }, "server certificate"},
		"key mismatch": {func(c *Config) { c.TLSKeyFile = p.clientKey }, "server certificate"},
		"missing CA":   {func(c *Config) { c.ClientCAFile = filepath.Join(p.dir, "absent") }, "ClientCAFile"},
		"CA not PEM":   {func(c *Config) { c.ClientCAFile = notPEM }, "holds no PEM certificate"},
		"address busy": {func(c *Config) { c.Listen = busy.Addr().String() }, "control:"},
	} {
		t.Run(name, func(t *testing.T) {
			c := good
			tc.mut(&c)
			lis, opts, err := Listen(c)
			if err == nil {
				lis.Close()
				t.Fatalf("Listen(%+v) succeeded", c)
			}
			if lis != nil || opts != nil {
				t.Fatal("a failed Listen returned a listener or options")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want %q", err, tc.want)
			}
		})
	}
	// Control: the unmutated config listens.
	lis, _, err := Listen(good)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	lis.Close()
}

func TestDialErrors(t *testing.T) {
	p := newPKI(t)
	notPEM := filepath.Join(p.dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := ClientConfig{Target: "127.0.0.1:1", CertFile: p.clientCert, KeyFile: p.clientKey, ServerCAFile: p.caFile}
	for name, tc := range map[string]struct {
		mut  func(*ClientConfig)
		want string
	}{
		"bad target":     {func(c *ClientConfig) { c.Target = "tcp://x:1" }, "unknown scheme"},
		"no cert":        {func(c *ClientConfig) { c.CertFile = "" }, "missing CertFile"},
		"unix with TLS":  {func(c *ClientConfig) { c.Target = "unix://" + filepath.ToSlash(absSock()) }, "CertFile, KeyFile, ServerCAFile must be empty"},
		"unreadable key": {func(c *ClientConfig) { c.KeyFile = filepath.Join(p.dir, "absent") }, "client certificate"},
		"missing CA":     {func(c *ClientConfig) { c.ServerCAFile = filepath.Join(p.dir, "absent") }, "ServerCAFile"},
		"CA not PEM":     {func(c *ClientConfig) { c.ServerCAFile = notPEM }, "holds no PEM certificate"},
	} {
		t.Run(name, func(t *testing.T) {
			c := good
			tc.mut(&c)
			cc, err := Dial(c)
			if err == nil {
				cc.Close()
				t.Fatalf("Dial(%+v) succeeded", c)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want %q", err, tc.want)
			}
		})
	}
	cc, err := Dial(good)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	cc.Close()
}

// ---- Caller ---------------------------------------------------------------

type otherAuth struct{}

func (otherAuth) AuthType() string { return "other" }

func TestCallerFallbacks(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "unverified"}}
	for name, tc := range map[string]struct {
		ctx  context.Context
		want string
	}{
		"no peer":          {context.Background(), "unknown"},
		"nil auth":         {peer.NewContext(context.Background(), &peer.Peer{}), "unknown"},
		"other auth":       {peer.NewContext(context.Background(), &peer.Peer{AuthInfo: otherAuth{}}), "unknown"},
		"tls no cert":      {peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{}}), "unknown"},
		"tls unverified":   {peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}}), "cn=unverified"},
		"tls empty chain":  {peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}, PeerCertificates: []*x509.Certificate{cert}}}}), "cn=unverified"},
		"unix unknown uid": {peer.NewContext(context.Background(), &peer.Peer{AuthInfo: unixAuthInfo{}}), "unix"},
		"unix uid":         {peer.NewContext(context.Background(), &peer.Peer{AuthInfo: unixAuthInfo{uid: 4242, uidKnown: true}}), "uid=4242"},
	} {
		if got := Caller(tc.ctx); got != tc.want {
			t.Errorf("%s: Caller = %q, want %q", name, got, tc.want)
		}
	}
}

func TestUnixCredsInterface(t *testing.T) {
	var c credentials.TransportCredentials = unixCreds{}
	if got := c.Info().SecurityProtocol; got != "unix" {
		t.Fatalf("SecurityProtocol = %q", got)
	}
	if _, ok := c.Clone().(unixCreds); !ok {
		t.Fatal("Clone returned another type")
	}
	if err := c.OverrideServerName("x"); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, ai, err := c.ServerHandshake(a)
	if err != nil {
		t.Fatal(err)
	}
	if ai.AuthType() != "unix" {
		t.Fatalf("AuthType = %q", ai.AuthType())
	}
	u := ai.(unixAuthInfo)
	if u.uidKnown {
		t.Fatal("a pipe claimed a peer uid")
	}
	if u.SecurityLevel != credentials.PrivacyAndIntegrity {
		t.Fatalf("SecurityLevel = %v", u.SecurityLevel)
	}
}

func TestDialServerUIDForbiddenForTCP(t *testing.T) {
	uid := uint32(1)
	_, err := Dial(ClientConfig{Target: "127.0.0.1:1", CertFile: "c", KeyFile: "k", ServerCAFile: "ca", ServerUID: &uid})
	if err == nil || !strings.Contains(err.Error(), "ServerUID must be nil") {
		t.Fatalf("ServerUID with a TCP target: %v, want a refusal", err)
	}
}
