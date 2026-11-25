package peer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/pion/webrtc/v5"

	"lighthouse-in-snoo/pkg/identity"
)

// generateEphemeralDTLSCertificate creates a per-PeerConnection self-signed X.509
// certificate compatible with DTLS 1.3 (ECDSA P-256/P-384/P-521, Ed25519, or RSA).
// When algo is empty or ed448 (which has no X.509 DTLS 1.3 certificate profile in Go/Pion),
// it defaults to ephemeral ECDSA P-256 while the peer's identity key authenticates its SHA-256 fingerprint.
func generateEphemeralDTLSCertificate(algo identity.Algorithm, rsaBits int) (webrtc.Certificate, error) {
	if algo == "" || algo == identity.AlgorithmEd448 {
		algo = identity.AlgorithmNISTP256
	}

	var (
		priv    crypto.Signer
		sigAlgo x509.SignatureAlgorithm
		err     error
	)

	switch algo {
	case identity.AlgorithmEd25519:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		sigAlgo = x509.PureEd25519
	case identity.AlgorithmNISTP256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sigAlgo = x509.ECDSAWithSHA256
	case identity.AlgorithmNISTP384:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		sigAlgo = x509.ECDSAWithSHA384
	case identity.AlgorithmNISTP521:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		sigAlgo = x509.ECDSAWithSHA512
	case identity.AlgorithmRSA:
		bits := rsaBits
		if bits == 0 {
			bits = 2048
		}
		if bits < identity.MinRSABits || bits > identity.MaxRSABits {
			return webrtc.Certificate{}, fmt.Errorf("%w: %d", identity.ErrInvalidKeyBits, bits)
		}
		priv, err = rsa.GenerateKey(rand.Reader, bits)
		sigAlgo = x509.SHA256WithRSAPSS
	default:
		return webrtc.Certificate{}, fmt.Errorf("%w: %q", identity.ErrUnsupportedAlgorithm, algo)
	}
	if err != nil {
		return webrtc.Certificate{}, fmt.Errorf("generate ephemeral dtls key (%s): %w", algo, err)
	}

	maxSerial := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return webrtc.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            pkix.Name{CommonName: "lighthouse-webrtc"},
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: sigAlgo,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return webrtc.Certificate{}, fmt.Errorf("create ephemeral dtls cert (%s): %w", algo, err)
	}
	x509Cert, err := x509.ParseCertificate(der)
	if err != nil {
		return webrtc.Certificate{}, err
	}
	return webrtc.CertificateFromX509(priv, x509Cert), nil
}
