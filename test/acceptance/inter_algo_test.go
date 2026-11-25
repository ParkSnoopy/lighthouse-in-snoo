package acceptance_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/peer"
)

func generateTLSSigner(t *testing.T, algo identity.Algorithm) (crypto.Signer, x509.SignatureAlgorithm) {
	t.Helper()
	switch algo {
	case identity.AlgorithmEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return priv, x509.PureEd25519
	case identity.AlgorithmNISTP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return priv, x509.ECDSAWithSHA256
	case identity.AlgorithmNISTP384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return priv, x509.ECDSAWithSHA384
	case identity.AlgorithmNISTP521:
		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return priv, x509.ECDSAWithSHA512
	case identity.AlgorithmRSA:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return priv, x509.SHA256WithRSAPSS
	default:
		t.Fatalf("unsupported TLS cert algorithm %q", algo)
		return nil, 0
	}
}

func generateInterAlgoPKI(t *testing.T, caAlgo, leafAlgo identity.Algorithm) testCA {
	t.Helper()

	caKey, caSigAlgo := generateTLSSigner(t, caAlgo)
	leafKey, _ := generateTLSSigner(t, leafAlgo)

	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Lighthouse CA (" + string(caAlgo) + ")"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    caSigAlgo,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create CA (%s): %v", caAlgo, err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "localhost"},
		DNSNames:           []string{"localhost"},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: caSigAlgo,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create leaf (%s signed by %s): %v", leafAlgo, caAlgo, err)
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

// TestInterKeyAlgorithmSigningTLS13AndDTLS13Matrix verifies end-to-end interoperability
// across all 6 identity signing algorithms (ed25519, ed448, nistp-256, nistp-384, nistp-521, rsa),
// cross-algorithm TLS 1.3 CA/leaf certificates on the Hub, and cross-algorithm DTLS 1.3
// certificates between Offerer and Answerer peers.
func TestInterKeyAlgorithmSigningTLS13AndDTLS13Matrix(t *testing.T) {
	t.Parallel()

	matrix := []struct {
		name      string
		hubCA     identity.Algorithm
		hubLeaf   identity.Algorithm
		peerAID   identity.Algorithm
		peerADTLS identity.Algorithm
		peerBID   identity.Algorithm
		peerBDTLS identity.Algorithm
	}{
		{
			name:      "TLS=rsa->ed25519_A=ed25519/ed25519_B=rsa/rsa",
			hubCA:     identity.AlgorithmRSA,
			hubLeaf:   identity.AlgorithmEd25519,
			peerAID:   identity.AlgorithmEd25519,
			peerADTLS: identity.AlgorithmEd25519,
			peerBID:   identity.AlgorithmRSA,
			peerBDTLS: identity.AlgorithmRSA,
		},
		{
			name:      "TLS=p521->p256_A=p256/p256_B=ed448/p384",
			hubCA:     identity.AlgorithmNISTP521,
			hubLeaf:   identity.AlgorithmNISTP256,
			peerAID:   identity.AlgorithmNISTP256,
			peerADTLS: identity.AlgorithmNISTP256,
			peerBID:   identity.AlgorithmEd448,
			peerBDTLS: identity.AlgorithmNISTP384,
		},
		{
			name:      "TLS=ed25519->rsa_A=p384/p384_B=p521/p521",
			hubCA:     identity.AlgorithmEd25519,
			hubLeaf:   identity.AlgorithmRSA,
			peerAID:   identity.AlgorithmNISTP384,
			peerADTLS: identity.AlgorithmNISTP384,
			peerBID:   identity.AlgorithmNISTP521,
			peerBDTLS: identity.AlgorithmNISTP521,
		},
		{
			name:      "TLS=p256->p521_A=ed448/ed25519_B=p256/rsa",
			hubCA:     identity.AlgorithmNISTP256,
			hubLeaf:   identity.AlgorithmNISTP521,
			peerAID:   identity.AlgorithmEd448,
			peerADTLS: identity.AlgorithmEd25519,
			peerBID:   identity.AlgorithmNISTP256,
			peerBDTLS: identity.AlgorithmRSA,
		},
		{
			name:      "TLS=p384->p384_A=rsa/p521_B=ed25519/p256",
			hubCA:     identity.AlgorithmNISTP384,
			hubLeaf:   identity.AlgorithmNISTP384,
			peerAID:   identity.AlgorithmRSA,
			peerADTLS: identity.AlgorithmNISTP521,
			peerBID:   identity.AlgorithmEd25519,
			peerBDTLS: identity.AlgorithmNISTP256,
		},
	}

	genKey := func(t *testing.T, algo identity.Algorithm) *identity.KeyPair {
		t.Helper()
		opts := identity.KeyGenOptions{Algorithm: algo}
		if algo == identity.AlgorithmRSA {
			opts.RSABits = 2048
		}
		kp, err := identity.GenerateKeyPairWithOptions(opts)
		if err != nil {
			t.Fatalf("generate %s: %v", algo, err)
		}
		return kp
	}

	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			peerA := genKey(t, tc.peerAID)
			peerB := genKey(t, tc.peerBID)

			pki := generateInterAlgoPKI(t, tc.hubCA, tc.hubLeaf)
			rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			boundAddr := rawLn.Addr().String()
			wsURL := "wss://" + boundAddr + "/v1/signal"

			srv, err := hub.New(&hub.Config{
				HTTPSListener:   rawLn,
				TLSConfig:       pki.serverTLS,
				HubOrigin:       "wss://" + boundAddr,
				EnableSTUN:      true,
				STUNSListenAddr: "127.0.0.1:0",
			})
			if err != nil {
				_ = rawLn.Close()
				t.Fatalf("hub.New: %v", err)
			}
			defer srv.Close()

			stunURI := "stuns:" + srv.STUNSAddr().String()
			sessBCh := make(chan *peer.Session, 1)

			clientA, err := peer.NewClient(&peer.Config{
				KeyPair:           peerA,
				SignalingURL:      wsURL,
				TLSConfig:         pki.clientTLS,
				STUNServerURI:     stunURI,
				NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
				IncludeLoopback:   true,
				DTLSCertAlgorithm: tc.peerADTLS,
				DTLSRSABits:       2048,
				Consent:           allowAllConsent(),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer clientA.Close()

			clientB, err := peer.NewClient(&peer.Config{
				KeyPair:           peerB,
				SignalingURL:      wsURL,
				TLSConfig:         pki.clientTLS,
				STUNServerURI:     stunURI,
				NetworkTypes:      []webrtc.NetworkType{webrtc.NetworkTypeUDP4},
				IncludeLoopback:   true,
				DTLSCertAlgorithm: tc.peerBDTLS,
				DTLSRSABits:       2048,
				Consent:           allowAllConsent(),
				OnSession:         func(s *peer.Session) { sessBCh <- s },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer clientB.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			if err := clientA.Register(ctx); err != nil {
				t.Fatalf("Register A (%s): %v", tc.peerAID, err)
			}
			if err := clientB.Register(ctx); err != nil {
				t.Fatalf("Register B (%s): %v", tc.peerBID, err)
			}
			if _, err := clientA.ProbeSTUNS(ctx); err != nil {
				t.Fatalf("ProbeSTUNS (%s CA -> %s leaf): %v", tc.hubCA, tc.hubLeaf, err)
			}

			sessA, err := clientA.Connect(ctx, peerB.PeerID)
			if err != nil {
				t.Fatalf("Connect failed: %v", err)
			}
			var sessB *peer.Session
			select {
			case sessB = <-sessBCh:
			case <-ctx.Done():
				t.Fatal("timeout waiting for responder session B")
			}

			diagA := sessA.Diagnostics()
			diagB := sessB.Diagnostics()
			if diagA.DTLSVersion != peer.ExpectedDTLS13HexVersion || diagB.DTLSVersion != peer.ExpectedDTLS13HexVersion {
				t.Fatalf("expected DTLS 1.3 (FEFC) on both peers, got A=%q B=%q", diagA.DTLSVersion, diagB.DTLSVersion)
			}

			ping := []byte("ping-" + tc.name)
			pong := []byte("pong-" + tc.name)
			if err := sessA.Send(ctx, ping); err != nil {
				t.Fatalf("Send A->B: %v", err)
			}
			if got := <-sessB.Messages(); !bytes.Equal(got, ping) {
				t.Fatalf("A->B payload mismatch: %q", string(got))
			}
			if err := sessB.Send(ctx, pong); err != nil {
				t.Fatalf("Send B->A: %v", err)
			}
			if got := <-sessA.Messages(); !bytes.Equal(got, pong) {
				t.Fatalf("B->A payload mismatch: %q", string(got))
			}
			t.Logf("Verified %s: DTLS=%s Cipher=%s", tc.name, diagA.DTLSVersion, diagA.DTLSCipher)
		})
	}
}
