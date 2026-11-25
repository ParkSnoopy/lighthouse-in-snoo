package hub

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"lighthouse-in-snoo/pkg/identity"
)

const (
	// DefaultTLSDir is the default directory where auto-generated hub TLS cert/key files are persisted.
	DefaultTLSDir = "/etc/lighthouse"

	// DefaultTLSCertFilename is the persisted PEM certificate filename inside TLSDir.
	DefaultTLSCertFilename = "tls.crt"

	// DefaultTLSKeyFilename is the persisted PEM private key filename inside TLSDir.
	DefaultTLSKeyFilename = "tls.key"

	// DefaultTLSAlgorithm is the default key algorithm for auto-generated hub TLS 1.3 certificates.
	DefaultTLSAlgorithm = identity.AlgorithmEd25519
)

// ParseTLSAlgorithm parses and validates a TLS 1.3 server certificate key algorithm.
// Supported values: ed25519 (default), nistp-256, nistp-384, nistp-521, rsa.
func ParseTLSAlgorithm(raw string) (identity.Algorithm, error) {
	algo, err := identity.ParseAlgorithm(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q (supported TLS algorithms: ed25519, nistp-256, nistp-384, nistp-521, rsa)", identity.ErrUnsupportedAlgorithm, raw)
	}
	if algo == identity.AlgorithmEd448 {
		return "", fmt.Errorf("%w: %q is not supported for X.509 TLS 1.3 certificates (supported: ed25519, nistp-256, nistp-384, nistp-521, rsa)", identity.ErrUnsupportedAlgorithm, raw)
	}
	return algo, nil
}

type resolvedTLS struct {
	config    *tls.Config
	algorithm identity.Algorithm
	persisted bool
}

func buildTLS13Config(cfg *Config, canonicalOrigin string) (*resolvedTLS, error) {
	var (
		base      *tls.Config
		algo      identity.Algorithm
		persisted bool
	)
	switch {
	case cfg.TLSConfig != nil:
		base = cfg.TLSConfig.Clone()
		if len(base.Certificates) > 0 {
			algo = detectCertAlgorithm(&base.Certificates[0])
		}
	case cfg.TLSCertFile != "" || cfg.TLSKeyFile != "":
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, errors.New("hub: both TLS certificate and key paths are required")
		}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load hub TLS keypair: %w", err)
		}
		algo = detectCertAlgorithm(&cert)
		persisted = true
		base = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		}
	case cfg.AutoTLS:
		cert, resolvedAlgo, wasPersisted, err := loadOrGenerateAutoTLS(cfg, canonicalOrigin)
		if err != nil {
			return nil, err
		}
		algo = resolvedAlgo
		persisted = wasPersisted
		base = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		}
	default:
		return nil, errors.New("hub: TLS certificate/key or AutoTLS is required")
	}
	base.MinVersion = tls.VersionTLS13
	base.MaxVersion = tls.VersionTLS13
	return &resolvedTLS{
		config:    base,
		algorithm: algo,
		persisted: persisted,
	}, nil
}

func loadOrGenerateAutoTLS(cfg *Config, canonicalOrigin string) (cert tls.Certificate, algo identity.Algorithm, persisted bool, err error) {
	algo, err = ParseTLSAlgorithm(string(cfg.TLSAlgorithm))
	if err != nil {
		return tls.Certificate{}, "", false, err
	}
	if cfg.TLSRSABits != 0 && algo != identity.AlgorithmRSA {
		return tls.Certificate{}, "", false, fmt.Errorf("%w: --tls-rsa-bits is only valid for rsa", identity.ErrInvalidKeyBits)
	}
	if algo == identity.AlgorithmRSA && cfg.TLSRSABits != 0 {
		if cfg.TLSRSABits < identity.MinRSABits || cfg.TLSRSABits > identity.MaxRSABits || cfg.TLSRSABits%8 != 0 {
			return tls.Certificate{}, "", false, fmt.Errorf("%w: %d (must be %d..%d bits, multiple of 8)", identity.ErrInvalidKeyBits, cfg.TLSRSABits, identity.MinRSABits, identity.MaxRSABits)
		}
	}

	if cfg.TLSDir != "" {
		certPath := filepath.Join(cfg.TLSDir, DefaultTLSCertFilename)
		keyPath := filepath.Join(cfg.TLSDir, DefaultTLSKeyFilename)
		if filesExist(certPath, keyPath) {
			loaded, loadErr := tls.LoadX509KeyPair(certPath, keyPath)
			if loadErr != nil {
				return tls.Certificate{}, "", false, fmt.Errorf("load persisted hub TLS keypair: %w", loadErr)
			}
			loadedAlgo := detectCertAlgorithm(&loaded)
			if loadedAlgo == "" {
				loadedAlgo = algo
			}
			return loaded, loadedAlgo, true, nil
		}

		cert, certPEM, keyPEM, genErr := generateSelfSignedServerCert(canonicalOrigin, cfg.TURNPublicIP, algo, cfg.TLSRSABits)
		if genErr != nil {
			return tls.Certificate{}, "", false, genErr
		}
		if saveErr := persistTLSPair(cfg.TLSDir, certPath, keyPath, certPEM, keyPEM); saveErr != nil {
			cfg.Logger.Warn("tls cert directory not writable; using ephemeral in-memory certificate",
				"dir", cfg.TLSDir,
				"tls_algo", string(algo),
				"err", saveErr,
			)
			return cert, algo, false, nil
		}
		return cert, algo, true, nil
	}

	cert, _, _, err = generateSelfSignedServerCert(canonicalOrigin, cfg.TURNPublicIP, algo, cfg.TLSRSABits)
	if err != nil {
		return tls.Certificate{}, "", false, err
	}
	return cert, algo, false, nil
}

func filesExist(certPath, keyPath string) bool {
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	return true
}

func persistTLSPair(dir, certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func generateSelfSignedServerCert(
	canonicalOrigin string,
	extraIP net.IP,
	algo identity.Algorithm,
	rsaBits int,
) (cert tls.Certificate, certPEM, keyPEM []byte, err error) {
	priv, sigAlgo, err := generateTLSKey(algo, rsaBits)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	dnsNames := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}
	if u, parseErr := url.Parse(canonicalOrigin); parseErr == nil {
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			ips = appendUniqueIP(ips, ip)
		} else if host != "" && host != "localhost" {
			dnsNames = append(dnsNames, host)
		}
	}
	if extraIP != nil {
		ips = appendUniqueIP(ips, extraIP)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "lighthouse-hub"},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    sigAlgo,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("create self-signed TLS cert: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("marshal TLS private key: %w", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, certPEM, keyPEM, nil
}

func appendUniqueIP(ips []net.IP, candidate net.IP) []net.IP {
	for _, existing := range ips {
		if existing.Equal(candidate) {
			return ips
		}
	}
	return append(ips, candidate)
}

func generateTLSKey(algo identity.Algorithm, rsaBits int) (crypto.Signer, x509.SignatureAlgorithm, error) {
	switch algo {
	case "", identity.AlgorithmEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, 0, fmt.Errorf("generate ed25519 TLS key: %w", err)
		}
		return priv, x509.PureEd25519, nil
	case identity.AlgorithmNISTP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, 0, fmt.Errorf("generate nistp-256 TLS key: %w", err)
		}
		return priv, x509.ECDSAWithSHA256, nil
	case identity.AlgorithmNISTP384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, 0, fmt.Errorf("generate nistp-384 TLS key: %w", err)
		}
		return priv, x509.ECDSAWithSHA384, nil
	case identity.AlgorithmNISTP521:
		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, 0, fmt.Errorf("generate nistp-521 TLS key: %w", err)
		}
		return priv, x509.ECDSAWithSHA512, nil
	case identity.AlgorithmRSA:
		bits := rsaBits
		if bits == 0 {
			bits = identity.DefaultRSABits
		}
		if bits < identity.MinRSABits || bits > identity.MaxRSABits || bits%8 != 0 {
			return nil, 0, fmt.Errorf("%w: %d (must be %d..%d bits, multiple of 8)", identity.ErrInvalidKeyBits, bits, identity.MinRSABits, identity.MaxRSABits)
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, 0, fmt.Errorf("generate rsa-%d TLS key: %w", bits, err)
		}
		return priv, x509.SHA256WithRSAPSS, nil
	default:
		return nil, 0, fmt.Errorf("%w: %q", identity.ErrUnsupportedAlgorithm, algo)
	}
}

func detectCertAlgorithm(cert *tls.Certificate) identity.Algorithm {
	if cert == nil {
		return ""
	}
	var pub crypto.PublicKey
	switch {
	case cert.Leaf != nil:
		pub = cert.Leaf.PublicKey
	case len(cert.Certificate) > 0:
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			pub = leaf.PublicKey
		}
	case cert.PrivateKey != nil:
		if signer, ok := cert.PrivateKey.(crypto.Signer); ok {
			pub = signer.Public()
		}
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return identity.AlgorithmEd25519
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return identity.AlgorithmNISTP256
		case elliptic.P384():
			return identity.AlgorithmNISTP384
		case elliptic.P521():
			return identity.AlgorithmNISTP521
		}
	case *rsa.PublicKey:
		return identity.AlgorithmRSA
	}
	return ""
}
