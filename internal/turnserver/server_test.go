package turnserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v4"
	dtlsProtocol "github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/turn/v6"

	"lighthouse-in-snoo/internal/turnserver"
)

func makeTestTURNSCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
	}, pool
}

func TestTURNSDTLS13UDPAndInsecureOptIn(t *testing.T) {
	t.Parallel()

	// Reject plaintext UDP TURN unless AllowInsecure=true.
	if _, err := turnserver.New(turnserver.Config{
		UDPListenAddr: "127.0.0.1:0",
		SharedSecret:  "top-secret",
	}); !errors.Is(err, turnserver.ErrInsecureTURNProhibited) {
		t.Fatalf("expected ErrInsecureTURNProhibited, got %v", err)
	}

	srvTLS, roots := makeTestTURNSCert(t)
	srv, err := turnserver.New(turnserver.Config{
		DTLSListenAddr:   "127.0.0.1:0",
		TLSConfig:        srvTLS,
		SharedSecret:     "turn-shared-secret",
		Realm:            "lighthouse",
		RelayBindAddress: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("turnserver.New: %v", err)
	}
	defer srv.Close()

	// Connect over DTLS 1.3 / UDP, run STUN Binding AND TURN Allocate with HMAC REST creds.
	rawUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer rawUDP.Close()

	dtlsConn, err := dtls.Client(rawUDP, srv.DTLSAddr(),
		dtls.WithRootCAs(roots),
		dtls.WithServerName("127.0.0.1"),
		dtls.WithMinVersion(dtlsProtocol.Version1_3),
		dtls.WithMaxVersion(dtlsProtocol.Version1_3),
		dtls.WithFlightInterval(100*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer dtlsConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dtlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("DTLS 1.3 handshake to TURNS failed: %v", err)
	}

	user, pass, err := turnserver.GenerateCredentials("turn-shared-secret", "peer-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: srv.DTLSAddr().String(),
		Conn:           turn.NewSTUNConn(dtlsConn),
		Username:       user,
		Password:       pass,
		Realm:          "lighthouse",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}

	mapped, err := client.SendBindingRequest()
	if err != nil {
		t.Fatalf("SendBindingRequest over DTLS 1.3 TURNS failed: %v", err)
	}
	if mapped == nil {
		t.Fatal("expected non-nil mapped address from STUNS Binding")
	}

	relayConn, err := client.AllocateWithContext(ctx)
	if err != nil {
		t.Fatalf("Allocate over DTLS 1.3 TURNS failed: %v", err)
	}
	defer relayConn.Close()

	if srv.AllocationCount() != 1 {
		t.Fatalf("AllocationCount = %d; want 1", srv.AllocationCount())
	}
}
