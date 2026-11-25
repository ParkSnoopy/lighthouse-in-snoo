package acceptance_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/transport/v5/vnet"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/peer"
)

// vnetConstructMu guards Pion vnet.NewRouter/NewNet against an upstream unguarded
// macAddrCounter increment in github.com/pion/transport/v5/vnet when tests run in parallel.
var vnetConstructMu sync.Mutex

func newVNetRouter(t *testing.T, cfg *vnet.RouterConfig) *vnet.Router {
	t.Helper()
	vnetConstructMu.Lock()
	defer vnetConstructMu.Unlock()
	r, err := vnet.NewRouter(cfg)
	if err != nil {
		t.Fatalf("vnet.NewRouter: %v", err)
	}
	return r
}

func newVNetNIC(t *testing.T, staticIP string) *vnet.Net {
	t.Helper()
	vnetConstructMu.Lock()
	defer vnetConstructMu.Unlock()
	n, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{staticIP}})
	if err != nil {
		t.Fatalf("vnet.NewNet(%s): %v", staticIP, err)
	}
	return n
}

func allowAllConsent() peer.ConsentHandler {
	return peer.ConsentFunc(func(_ context.Context, _ *peer.IncomingRequest) peer.ConsentDecision {
		return peer.ConsentAllow
	})
}

func denyAllConsent() peer.ConsentHandler {
	return peer.ConsentFunc(func(_ context.Context, _ *peer.IncomingRequest) peer.ConsentDecision {
		return peer.ConsentDeny
	})
}

func blacklistAllConsent() peer.ConsentHandler {
	return peer.ConsentFunc(func(_ context.Context, _ *peer.IncomingRequest) peer.ConsentDecision {
		return peer.ConsentBlacklist
	})
}

type safeLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeLogBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeLogBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type testCA struct {
	serverTLS *tls.Config
	clientTLS *tls.Config
}

func generateTestPKI(t *testing.T, ips ...net.IP) testCA {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Lighthouse Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sanIPs := append([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, ips...)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost", "hub.lighthouse.test"},
		IPAddresses:  sanIPs,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return testCA{
		serverTLS: &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{leafDER},
				PrivateKey:  leafKey,
			}},
		},
		clientTLS: &tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			RootCAs:    pool,
		},
	}
}

type testMeshIdentities struct {
	peerA *identity.KeyPair
	peerB *identity.KeyPair
	peerC *identity.KeyPair
}

func newTestMeshIdentities(t *testing.T) testMeshIdentities {
	t.Helper()

	kpA, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kpB, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kpC, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Ensure deterministic PeerA < PeerB lexicographical ordering for glare tests.
	if kpA.PeerID > kpB.PeerID {
		kpA, kpB = kpB, kpA
	}

	return testMeshIdentities{
		peerA: kpA,
		peerB: kpB,
		peerC: kpC,
	}
}

func startTestHub(t *testing.T, network, listenAddr, stunsListenAddr string, stunsConn net.PacketConn, extraIPs ...net.IP) (*hub.Server, testCA, *safeLogBuffer, string, string) {
	t.Helper()

	pki := generateTestPKI(t, extraIPs...)
	logBuf := &safeLogBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	rawLn, err := net.Listen(network, listenAddr)
	if err != nil {
		t.Fatalf("listen %s %s: %v", network, listenAddr, err)
	}
	boundAddr := rawLn.Addr().String()
	wsURL := "wss://" + boundAddr + "/v1/signal"

	srv, err := hub.New(&hub.Config{
		HTTPSListener:   rawLn,
		TLSConfig:       pki.serverTLS,
		HubOrigin:       "wss://" + boundAddr,
		EnableSTUN:      stunsConn != nil || stunsListenAddr != "",
		STUNSListenAddr: stunsListenAddr,
		STUNSPacketConn: stunsConn,
		Logger:          logger,
	})
	if err != nil {
		_ = rawLn.Close()
		t.Fatalf("hub.New: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
	})

	var stunsURI string
	if srv.STUNSAddr() != nil {
		stunsURI = "stuns:" + srv.STUNSAddr().String()
	}
	return srv, pki, logBuf, wsURL, stunsURI
}

// authorizeOnPassphrase enables broadcast on target and joins callers on passphrase,
// waiting until the hub has propagated the broadcast snapshot so auto-ACL is active.
func authorizeOnPassphrase(t *testing.T, ctx context.Context, passphrase string, target *peer.Client, callers ...*peer.Client) {
	t.Helper()
	chID, err := target.SetBroadcast(ctx, true, passphrase, "peer")
	if err != nil {
		t.Fatalf("SetBroadcast(%s): %v", passphrase, err)
	}
	for _, c := range callers {
		if _, err := c.JoinChannel(ctx, passphrase); err != nil {
			t.Fatalf("JoinChannel(%s): %v", passphrase, err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		allSeen := true
		for _, c := range callers {
			found := false
			for _, dp := range c.DiscoveredPeers(chID) {
				if dp.PeerID == target.PeerID() {
					found = true
					break
				}
			}
			if !found {
				allSeen = false
				break
			}
		}
		if allSeen {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for hub auto-ACL broadcast propagation on %q", passphrase)
}
