package identity

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/ed448"

	"lighthouse-in-snoo/internal/jcs"
)

const (
	// DomainRegisterV1 is the domain separator for hub registration proofs.
	DomainRegisterV1 = "LIGHTHOUSE-REGISTER-V1\x00"
	// DomainMembershipV1 is the domain separator for offline authority membership records.
	DomainMembershipV1 = "LIGHTHOUSE-MEMBERSHIP-V1\x00"

	// PeerIDEncodedLen is the base64url (unpadded) length of a 32-byte SHA-256 digest.
	PeerIDEncodedLen = 43

	// DefaultRSABits is the default RSA modulus size when generating RSA keys.
	DefaultRSABits = 3072
	// MinRSABits is the minimum accepted RSA modulus bit length.
	MinRSABits = 2048
	// MaxRSABits is the maximum accepted RSA modulus bit length.
	MaxRSABits = 8192
)

// Algorithm identifies a supported asymmetric signing algorithm for peer/authority identities.
type Algorithm string

const (
	AlgorithmEd25519  Algorithm = "ed25519"
	AlgorithmEd448    Algorithm = "ed448"
	AlgorithmNISTP256 Algorithm = "nistp-256"
	AlgorithmNISTP384 Algorithm = "nistp-384"
	AlgorithmNISTP521 Algorithm = "nistp-521"
	AlgorithmRSA      Algorithm = "rsa"
)

var (
	ErrUnsupportedAlgorithm = errors.New("identity: unsupported key algorithm")
	ErrInvalidKeyBits       = errors.New("identity: invalid RSA key size")
	ErrInvalidPublicKey     = errors.New("identity: invalid public key")
	ErrInvalidPrivateKey    = errors.New("identity: invalid private key")
	ErrInvalidPeerID        = errors.New("identity: invalid peer_id")
	ErrPeerIDMismatch       = errors.New("identity: peer_id does not match public key")
	ErrUntrustedPeer        = errors.New("identity: untrusted peer identity")
	ErrRevokedPeer          = errors.New("identity: peer identity is revoked")
	ErrMembershipExpired    = errors.New("identity: membership record expired or not yet valid")
	ErrUnauthorizedPair     = errors.New("identity: peer pair denied by ACL")
	ErrInvalidProof         = errors.New("identity: invalid signature proof")
	ErrInvalidOrigin        = errors.New("identity: invalid hub origin")
	ErrInsecureFilePerms    = errors.New("identity: key file permissions are too permissive")
)

// ParseAlgorithm normalizes user-supplied algorithm names and aliases.
func ParseAlgorithm(raw string) (Algorithm, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "ed25519":
		return AlgorithmEd25519, nil
	case "ed448":
		return AlgorithmEd448, nil
	case "nistp-256", "nistp256", "p-256", "p256", "secp256r1", "ecdsa-p256":
		return AlgorithmNISTP256, nil
	case "nistp-384", "nistp384", "p-384", "p384", "secp384r1", "ecdsa-p384":
		return AlgorithmNISTP384, nil
	case "nistp-521", "nistp521", "p-521", "p521", "secp521r1", "ecdsa-p521":
		return AlgorithmNISTP521, nil
	case "rsa", "rsa-pss":
		return AlgorithmRSA, nil
	default:
		return "", fmt.Errorf("%w: %q (supported: ed25519, ed448, nistp-256, nistp-384, nistp-521, rsa)", ErrUnsupportedAlgorithm, raw)
	}
}

// KeyGenOptions configures asymmetric identity key generation.
type KeyGenOptions struct {
	Algorithm Algorithm
	RSABits   int // Optional for AlgorithmRSA (default 3072, range 2048..8192).
}

// PublicKey is an immutable multi-algorithm identity public key.
type PublicKey struct {
	Algorithm Algorithm
	raw       []byte // Raw 32B (Ed25519), 57B (Ed448), or PKIX SPKI DER (ECDSA/RSA).
	key       crypto.PublicKey
}

// IsZero reports whether the PublicKey is uninitialized.
func (p PublicKey) IsZero() bool {
	return p.Algorithm == "" || len(p.raw) == 0 || p.key == nil
}

// Equal reports whether p and other represent the exact same algorithm and key material.
func (p PublicKey) Equal(other PublicKey) bool {
	return p.Algorithm == other.Algorithm && bytes.Equal(p.raw, other.raw)
}

// BitLen returns the modulus bit size for RSA keys, or 0 for non-RSA keys.
func (p PublicKey) BitLen() int {
	if rk, ok := p.key.(*rsa.PublicKey); ok {
		return rk.N.BitLen()
	}
	return 0
}

// PeerID derives the unpadded base64url SHA-256 peer_id for p.
// For Ed25519, this is SHA-256 over the raw 32-byte public key (Section 3).
// For other algorithms, the hash is domain-separated by "<algorithm>\x00" || canonical_bytes.
func (p PublicKey) PeerID() (string, error) {
	return PeerIDFromPublicKey(p)
}

// Encode serializes p into its canonical wire string representation.
// Ed25519 keys encode as raw 32-byte unpadded base64url; other algorithms prefix "<algo>:".
func (p PublicKey) Encode() string {
	return EncodePublicKey(p)
}

// Verify checks a raw signature over message using p's algorithm.
func (p PublicKey) Verify(message, signature []byte) bool {
	if p.IsZero() || len(signature) == 0 {
		return false
	}
	switch p.Algorithm {
	case AlgorithmEd25519:
		pub, ok := p.key.(ed25519.PublicKey)
		return ok && len(signature) == ed25519.SignatureSize && ed25519.Verify(pub, message, signature)
	case AlgorithmEd448:
		pub, ok := p.key.(ed448.PublicKey)
		return ok && len(signature) == ed448.SignatureSize && ed448.Verify(pub, message, signature, "")
	case AlgorithmNISTP256:
		pub, ok := p.key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		sum := sha256.Sum256(message)
		return ecdsa.VerifyASN1(pub, sum[:], signature)
	case AlgorithmNISTP384:
		pub, ok := p.key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		sum := sha512.Sum384(message)
		return ecdsa.VerifyASN1(pub, sum[:], signature)
	case AlgorithmNISTP521:
		pub, ok := p.key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		sum := sha512.Sum512(message)
		return ecdsa.VerifyASN1(pub, sum[:], signature)
	case AlgorithmRSA:
		pub, ok := p.key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		sum := sha256.Sum256(message)
		err := rsa.VerifyPSS(pub, crypto.SHA256, sum[:], signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
		return err == nil
	default:
		return false
	}
}

// VerifyBase64URL decodes a canonical unpadded base64url signature and verifies it over message.
func (p PublicKey) VerifyBase64URL(message []byte, sigBase64 string) error {
	if sigBase64 == "" {
		return ErrInvalidProof
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil || len(sig) == 0 || base64.RawURLEncoding.EncodeToString(sig) != sigBase64 {
		return ErrInvalidProof
	}
	if !p.Verify(message, sig) {
		return ErrInvalidProof
	}
	return nil
}

// KeyPair holds a peer or authority asymmetric identity key pair.
type KeyPair struct {
	Algorithm  Algorithm
	PeerID     string
	PublicKey  PublicKey
	PrivateKey crypto.Signer
}

type storedKeyFile struct {
	Version    int       `json:"v"`
	Algorithm  Algorithm `json:"algorithm,omitempty"`
	PeerID     string    `json:"peer_id"`
	PublicKey  string    `json:"public_key"`
	PrivateKey string    `json:"private_key"`
}

// Sign signs message using kp's algorithm and private key.
func (kp *KeyPair) Sign(message []byte) ([]byte, error) {
	if kp == nil || kp.PrivateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	switch kp.Algorithm {
	case AlgorithmEd25519:
		priv, ok := kp.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivateKey
		}
		return ed25519.Sign(priv, message), nil
	case AlgorithmEd448:
		priv, ok := kp.PrivateKey.(ed448.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivateKey
		}
		return ed448.Sign(priv, message, ""), nil
	case AlgorithmNISTP256:
		priv, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivateKey
		}
		sum := sha256.Sum256(message)
		return ecdsa.SignASN1(rand.Reader, priv, sum[:])
	case AlgorithmNISTP384:
		priv, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivateKey
		}
		sum := sha512.Sum384(message)
		return ecdsa.SignASN1(rand.Reader, priv, sum[:])
	case AlgorithmNISTP521:
		priv, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivateKey
		}
		sum := sha512.Sum512(message)
		return ecdsa.SignASN1(rand.Reader, priv, sum[:])
	case AlgorithmRSA:
		priv, ok := kp.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivateKey
		}
		sum := sha256.Sum256(message)
		return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, sum[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// SignBase64URL signs message and encodes the signature as unpadded base64url.
func (kp *KeyPair) SignBase64URL(message []byte) (string, error) {
	sig, err := kp.Sign(message)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// GenerateKeyPair creates a fresh default Ed25519 identity key pair and derives its peer_id.
func GenerateKeyPair() (*KeyPair, error) {
	return GenerateKeyPairWithOptions(KeyGenOptions{Algorithm: AlgorithmEd25519})
}

// GenerateKeyPairWithOptions creates a fresh identity key pair using the requested algorithm.
func GenerateKeyPairWithOptions(opts KeyGenOptions) (*KeyPair, error) {
	algo := opts.Algorithm
	if algo == "" {
		algo = AlgorithmEd25519
	}
	if opts.RSABits != 0 && algo != AlgorithmRSA {
		return nil, fmt.Errorf("%w: --bits is only valid for rsa keys", ErrInvalidKeyBits)
	}

	switch algo {
	case AlgorithmEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		return buildKeyPair(AlgorithmEd25519, pub, priv)

	case AlgorithmEd448:
		pub, priv, err := ed448.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed448 key: %w", err)
		}
		return buildKeyPair(AlgorithmEd448, pub, priv)

	case AlgorithmNISTP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate nistp-256 key: %w", err)
		}
		return buildKeyPair(AlgorithmNISTP256, &priv.PublicKey, priv)

	case AlgorithmNISTP384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate nistp-384 key: %w", err)
		}
		return buildKeyPair(AlgorithmNISTP384, &priv.PublicKey, priv)

	case AlgorithmNISTP521:
		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate nistp-521 key: %w", err)
		}
		return buildKeyPair(AlgorithmNISTP521, &priv.PublicKey, priv)

	case AlgorithmRSA:
		bits := opts.RSABits
		if bits == 0 {
			bits = DefaultRSABits
		}
		if bits < MinRSABits || bits > MaxRSABits || bits%8 != 0 {
			return nil, fmt.Errorf("%w: %d (must be %d..%d bits, multiple of 8)", ErrInvalidKeyBits, bits, MinRSABits, MaxRSABits)
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("generate rsa-%d key: %w", bits, err)
		}
		return buildKeyPair(AlgorithmRSA, &priv.PublicKey, priv)

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algo)
	}
}

func buildKeyPair(algo Algorithm, pub crypto.PublicKey, priv crypto.Signer) (*KeyPair, error) {
	wrappedPub, err := wrapPublicKey(algo, pub)
	if err != nil {
		return nil, err
	}
	id, err := PeerIDFromPublicKey(wrappedPub)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Algorithm:  algo,
		PeerID:     id,
		PublicKey:  wrappedPub,
		PrivateKey: priv,
	}, nil
}

func wrapPublicKey(algo Algorithm, pub crypto.PublicKey) (PublicKey, error) {
	switch algo {
	case AlgorithmEd25519:
		ep, ok := pub.(ed25519.PublicKey)
		if !ok || len(ep) != ed25519.PublicKeySize {
			return PublicKey{}, ErrInvalidPublicKey
		}
		raw := append([]byte(nil), ep...)
		return PublicKey{Algorithm: AlgorithmEd25519, raw: raw, key: ed25519.PublicKey(raw)}, nil

	case AlgorithmEd448:
		ep, ok := pub.(ed448.PublicKey)
		if !ok || len(ep) != ed448.PublicKeySize {
			return PublicKey{}, ErrInvalidPublicKey
		}
		raw := append([]byte(nil), ep...)
		return PublicKey{Algorithm: AlgorithmEd448, raw: raw, key: ed448.PublicKey(raw)}, nil

	case AlgorithmNISTP256, AlgorithmNISTP384, AlgorithmNISTP521:
		ep, ok := pub.(*ecdsa.PublicKey)
		if !ok || ep == nil || ep.Curve != curveForAlgorithm(algo) {
			return PublicKey{}, ErrInvalidPublicKey
		}
		spki, err := x509.MarshalPKIXPublicKey(ep)
		if err != nil {
			return PublicKey{}, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
		}
		return PublicKey{Algorithm: algo, raw: spki, key: ep}, nil

	case AlgorithmRSA:
		rp, ok := pub.(*rsa.PublicKey)
		if !ok || rp == nil || rp.N == nil || rp.N.BitLen() < MinRSABits || rp.N.BitLen() > MaxRSABits {
			return PublicKey{}, ErrInvalidPublicKey
		}
		spki, err := x509.MarshalPKIXPublicKey(rp)
		if err != nil {
			return PublicKey{}, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
		}
		return PublicKey{Algorithm: AlgorithmRSA, raw: spki, key: rp}, nil

	default:
		return PublicKey{}, ErrUnsupportedAlgorithm
	}
}

func curveForAlgorithm(algo Algorithm) elliptic.Curve {
	switch algo {
	case AlgorithmNISTP256:
		return elliptic.P256()
	case AlgorithmNISTP384:
		return elliptic.P384()
	case AlgorithmNISTP521:
		return elliptic.P521()
	default:
		return nil
	}
}

// KeyPairFromSeed derives a deterministic Ed25519 identity key pair from a 32-byte seed.
func KeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrInvalidPrivateKey
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return buildKeyPair(AlgorithmEd25519, pub, priv)
}

// PeerIDFromPublicKey returns the unpadded base64url SHA-256 peer_id for pub.
func PeerIDFromPublicKey(pub PublicKey) (string, error) {
	if pub.IsZero() {
		return "", ErrInvalidPublicKey
	}
	if pub.Algorithm == AlgorithmEd25519 {
		if len(pub.raw) != ed25519.PublicKeySize {
			return "", ErrInvalidPublicKey
		}
		sum := sha256.Sum256(pub.raw)
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	}

	h := sha256.New()
	_, _ = h.Write([]byte(pub.Algorithm))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(pub.raw)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// ValidatePeerID checks syntactic validity of an unpadded base64url SHA-256 peer_id.
func ValidatePeerID(peerID string) error {
	if len(peerID) != PeerIDEncodedLen {
		return ErrInvalidPeerID
	}
	decoded, err := base64.RawURLEncoding.DecodeString(peerID)
	if err != nil || len(decoded) != sha256.Size {
		return ErrInvalidPeerID
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != peerID {
		return ErrInvalidPeerID
	}
	return nil
}

// EncodePublicKey encodes pub into canonical string form.
// Ed25519 emits raw 32-byte unpadded base64url; other algorithms emit "<algo>:<base64url>".
func EncodePublicKey(pub PublicKey) string {
	if pub.IsZero() {
		return ""
	}
	b64 := base64.RawURLEncoding.EncodeToString(pub.raw)
	if pub.Algorithm == AlgorithmEd25519 {
		return b64
	}
	return string(pub.Algorithm) + ":" + b64
}

// DecodePublicKey decodes a canonical public_key string into a validated PublicKey.
func DecodePublicKey(encoded string) (PublicKey, error) {
	if encoded == "" {
		return PublicKey{}, ErrInvalidPublicKey
	}

	algo := AlgorithmEd25519
	b64 := encoded
	if colon := strings.IndexByte(encoded, ':'); colon >= 0 {
		parsedAlgo, err := ParseAlgorithm(encoded[:colon])
		if err != nil {
			return PublicKey{}, ErrInvalidPublicKey
		}
		algo = parsedAlgo
		b64 = encoded[colon+1:]
	}

	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != b64 {
		return PublicKey{}, ErrInvalidPublicKey
	}

	switch algo {
	case AlgorithmEd25519:
		if len(raw) != ed25519.PublicKeySize {
			return PublicKey{}, ErrInvalidPublicKey
		}
		return PublicKey{Algorithm: AlgorithmEd25519, raw: raw, key: ed25519.PublicKey(raw)}, nil

	case AlgorithmEd448:
		if len(raw) != ed448.PublicKeySize {
			return PublicKey{}, ErrInvalidPublicKey
		}
		return PublicKey{Algorithm: AlgorithmEd448, raw: raw, key: ed448.PublicKey(raw)}, nil

	case AlgorithmNISTP256, AlgorithmNISTP384, AlgorithmNISTP521:
		parsed, err := x509.ParsePKIXPublicKey(raw)
		if err != nil {
			return PublicKey{}, ErrInvalidPublicKey
		}
		ecPub, ok := parsed.(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != curveForAlgorithm(algo) {
			return PublicKey{}, ErrInvalidPublicKey
		}
		canonDER, err := x509.MarshalPKIXPublicKey(ecPub)
		if err != nil || !bytes.Equal(canonDER, raw) {
			return PublicKey{}, ErrInvalidPublicKey
		}
		return PublicKey{Algorithm: algo, raw: raw, key: ecPub}, nil

	case AlgorithmRSA:
		parsed, err := x509.ParsePKIXPublicKey(raw)
		if err != nil {
			return PublicKey{}, ErrInvalidPublicKey
		}
		rsaPub, ok := parsed.(*rsa.PublicKey)
		if !ok || rsaPub.N == nil || rsaPub.N.BitLen() < MinRSABits || rsaPub.N.BitLen() > MaxRSABits || rsaPub.E < 3 || rsaPub.E%2 == 0 {
			return PublicKey{}, ErrInvalidPublicKey
		}
		canonDER, err := x509.MarshalPKIXPublicKey(rsaPub)
		if err != nil || !bytes.Equal(canonDER, raw) {
			return PublicKey{}, ErrInvalidPublicKey
		}
		return PublicKey{Algorithm: AlgorithmRSA, raw: raw, key: rsaPub}, nil

	default:
		return PublicKey{}, ErrUnsupportedAlgorithm
	}
}

// Save writes the identity key pair to path with 0600 permissions.
func (kp *KeyPair) Save(path string) error {
	if kp == nil || kp.PrivateKey == nil {
		return ErrInvalidPrivateKey
	}
	privBytes, err := marshalPrivateKey(kp.Algorithm, kp.PrivateKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	payload, err := json.MarshalIndent(storedKeyFile{
		Version:    1,
		Algorithm:  kp.Algorithm,
		PeerID:     kp.PeerID,
		PublicKey:  EncodePublicKey(kp.PublicKey),
		PrivateKey: base64.RawURLEncoding.EncodeToString(privBytes),
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit key file: %w", err)
	}
	return nil
}

func marshalPrivateKey(algo Algorithm, priv crypto.Signer) ([]byte, error) {
	switch algo {
	case AlgorithmEd25519:
		ep, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivateKey
		}
		return ep.Seed(), nil
	case AlgorithmEd448:
		ep, ok := priv.(ed448.PrivateKey)
		if !ok {
			return nil, ErrInvalidPrivateKey
		}
		return ep.Seed(), nil
	case AlgorithmNISTP256, AlgorithmNISTP384, AlgorithmNISTP521, AlgorithmRSA:
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("marshal pkcs8 key: %w", err)
		}
		return der, nil
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func unmarshalPrivateKey(algo Algorithm, raw []byte) (*KeyPair, error) {
	switch algo {
	case AlgorithmEd25519:
		return KeyPairFromSeed(raw)
	case AlgorithmEd448:
		if len(raw) != ed448.SeedSize {
			return nil, ErrInvalidPrivateKey
		}
		priv := ed448.NewKeyFromSeed(raw)
		pub := priv.Public().(ed448.PublicKey)
		return buildKeyPair(AlgorithmEd448, pub, priv)
	case AlgorithmNISTP256, AlgorithmNISTP384, AlgorithmNISTP521:
		parsed, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return nil, ErrInvalidPrivateKey
		}
		ecPriv, ok := parsed.(*ecdsa.PrivateKey)
		if !ok || ecPriv.Curve != curveForAlgorithm(algo) {
			return nil, ErrInvalidPrivateKey
		}
		return buildKeyPair(algo, &ecPriv.PublicKey, ecPriv)
	case AlgorithmRSA:
		parsed, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return nil, ErrInvalidPrivateKey
		}
		rsaPriv, ok := parsed.(*rsa.PrivateKey)
		if !ok || rsaPriv.N == nil || rsaPriv.N.BitLen() < MinRSABits || rsaPriv.N.BitLen() > MaxRSABits {
			return nil, ErrInvalidPrivateKey
		}
		return buildKeyPair(AlgorithmRSA, &rsaPriv.PublicKey, rsaPriv)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// LoadKeyPair reads a persistent identity key pair and verifies 0600 permissions.
func LoadKeyPair(path string) (*KeyPair, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %04o", ErrInsecureFilePerms, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	var sf storedKeyFile
	if err := jcs.UnmarshalStrict(raw, &sf); err != nil {
		return nil, err
	}
	if sf.Version != 1 {
		return nil, fmt.Errorf("%w: unsupported key version %d", ErrInvalidPrivateKey, sf.Version)
	}
	algo := sf.Algorithm
	if algo == "" {
		algo = AlgorithmEd25519
	}
	privBytes, err := base64.RawURLEncoding.DecodeString(sf.PrivateKey)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	kp, err := unmarshalPrivateKey(algo, privBytes)
	if err != nil {
		return nil, err
	}
	if sf.PeerID != kp.PeerID || sf.PublicKey != EncodePublicKey(kp.PublicKey) {
		return nil, ErrPeerIDMismatch
	}
	return kp, nil
}

// LoadOrGenerateKeyPair loads an existing key pair or creates an Ed25519 one if absent.
func LoadOrGenerateKeyPair(path string) (*KeyPair, error) {
	return LoadOrGenerateKeyPairWithOptions(path, KeyGenOptions{Algorithm: AlgorithmEd25519})
}

// LoadOrGenerateKeyPairWithOptions loads an existing key pair or generates one with opts if absent.
func LoadOrGenerateKeyPairWithOptions(path string, opts KeyGenOptions) (*KeyPair, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		kp, genErr := GenerateKeyPairWithOptions(opts)
		if genErr != nil {
			return nil, genErr
		}
		if saveErr := kp.Save(path); saveErr != nil {
			return nil, saveErr
		}
		return kp, nil
	}
	return LoadKeyPair(path)
}

// CanonicalizeOrigin normalizes a hub WSS/HTTPS URL to canonical "wss://host[:port]" form.
func CanonicalizeOrigin(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", ErrInvalidOrigin
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "wss" && scheme != "https" {
		return "", ErrInvalidOrigin
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", ErrInvalidOrigin
	}
	port := u.Port()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" || port == "443" {
		return "wss://" + host, nil
	}
	return "wss://" + host + ":" + port, nil
}

type registerChallengeDoc struct {
	Challenge string `json:"challenge"`
	HubOrigin string `json:"hub_origin"`
	PeerID    string `json:"peer_id"`
}

// SignRegistrationChallenge signs the domain-separated registration proof over
// peer_id, challenge, and canonical hub_origin (Section 3).
func (kp *KeyPair) SignRegistrationChallenge(challenge, hubOrigin string) (string, error) {
	origin, err := CanonicalizeOrigin(hubOrigin)
	if err != nil {
		return "", err
	}
	if challenge == "" {
		return "", ErrInvalidProof
	}
	canon, err := jcs.MarshalCanonical(registerChallengeDoc{
		Challenge: challenge,
		HubOrigin: origin,
		PeerID:    kp.PeerID,
	})
	if err != nil {
		return "", err
	}
	msg := make([]byte, 0, len(DomainRegisterV1)+len(canon))
	msg = append(msg, DomainRegisterV1...)
	msg = append(msg, canon...)
	return kp.SignBase64URL(msg)
}

// VerifyRegistrationChallenge verifies a peer's registration challenge proof.
func VerifyRegistrationChallenge(pub PublicKey, peerID, challenge, hubOrigin, proof string) error {
	derivedID, err := PeerIDFromPublicKey(pub)
	if err != nil {
		return err
	}
	if derivedID != peerID {
		return ErrPeerIDMismatch
	}
	origin, err := CanonicalizeOrigin(hubOrigin)
	if err != nil {
		return err
	}
	canon, err := jcs.MarshalCanonical(registerChallengeDoc{
		Challenge: challenge,
		HubOrigin: origin,
		PeerID:    peerID,
	})
	if err != nil {
		return err
	}
	msg := make([]byte, 0, len(DomainRegisterV1)+len(canon))
	msg = append(msg, DomainRegisterV1...)
	msg = append(msg, canon...)
	return pub.VerifyBase64URL(msg, proof)
}

// MembershipRecord is a peer membership assertion signed by an offline authority.
type MembershipRecord struct {
	Version      int      `json:"v"`
	PeerID       string   `json:"peer_id"`
	PublicKey    string   `json:"public_key"`
	IssuedAt     int64    `json:"issued_at"`
	ExpiresAt    int64    `json:"expires_at"`
	AllowedPeers []string `json:"allowed_peers,omitempty"`
	Issuer       string   `json:"issuer"`
	Sig          string   `json:"sig"`
}

type unsignedMembershipRecord struct {
	Version      int      `json:"v"`
	PeerID       string   `json:"peer_id"`
	PublicKey    string   `json:"public_key"`
	IssuedAt     int64    `json:"issued_at"`
	ExpiresAt    int64    `json:"expires_at"`
	AllowedPeers []string `json:"allowed_peers,omitempty"`
	Issuer       string   `json:"issuer"`
}

// IssueMembership signs a MembershipRecord using an offline authority KeyPair.
func IssueMembership(authority *KeyPair, peerPub PublicKey, issuedAt, expiresAt int64, allowedPeers []string) (*MembershipRecord, error) {
	peerID, err := PeerIDFromPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	pubEnc := EncodePublicKey(peerPub)
	unsigned := unsignedMembershipRecord{
		Version:      1,
		PeerID:       peerID,
		PublicKey:    pubEnc,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
		AllowedPeers: slices.Clone(allowedPeers),
		Issuer:       authority.PeerID,
	}
	canon, err := jcs.MarshalCanonical(unsigned)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, len(DomainMembershipV1)+len(canon))
	msg = append(msg, DomainMembershipV1...)
	msg = append(msg, canon...)
	sigEnc, err := authority.SignBase64URL(msg)
	if err != nil {
		return nil, err
	}
	return &MembershipRecord{
		Version:      unsigned.Version,
		PeerID:       unsigned.PeerID,
		PublicKey:    unsigned.PublicKey,
		IssuedAt:     unsigned.IssuedAt,
		ExpiresAt:    unsigned.ExpiresAt,
		AllowedPeers: unsigned.AllowedPeers,
		Issuer:       unsigned.Issuer,
		Sig:          sigEnc,
	}, nil
}

// VerifyMembershipRecord validates a signed MembershipRecord against a map of
// trusted offline authority public keys (keyed by authority ID).
func VerifyMembershipRecord(rec *MembershipRecord, authorities map[string]PublicKey, now time.Time, skew time.Duration) (PublicKey, error) {
	if rec == nil || rec.Version != 1 {
		return PublicKey{}, ErrUntrustedPeer
	}
	pub, err := DecodePublicKey(rec.PublicKey)
	if err != nil {
		return PublicKey{}, err
	}
	derivedID, err := PeerIDFromPublicKey(pub)
	if err != nil {
		return PublicKey{}, err
	}
	if derivedID != rec.PeerID {
		return PublicKey{}, ErrPeerIDMismatch
	}
	authPub, ok := authorities[rec.Issuer]
	if !ok {
		return PublicKey{}, ErrUntrustedPeer
	}
	nowUnix := now.Unix()
	skewSec := int64(skew / time.Second)
	if rec.ExpiresAt+skewSec < nowUnix || rec.IssuedAt-skewSec > nowUnix || rec.ExpiresAt <= rec.IssuedAt {
		return PublicKey{}, ErrMembershipExpired
	}
	unsigned := unsignedMembershipRecord{
		Version:      rec.Version,
		PeerID:       rec.PeerID,
		PublicKey:    rec.PublicKey,
		IssuedAt:     rec.IssuedAt,
		ExpiresAt:    rec.ExpiresAt,
		AllowedPeers: rec.AllowedPeers,
		Issuer:       rec.Issuer,
	}
	canon, err := jcs.MarshalCanonical(unsigned)
	if err != nil {
		return PublicKey{}, err
	}
	msg := make([]byte, 0, len(DomainMembershipV1)+len(canon))
	msg = append(msg, DomainMembershipV1...)
	msg = append(msg, canon...)
	if err := authPub.VerifyBase64URL(msg, rec.Sig); err != nil {
		return PublicKey{}, ErrInvalidProof
	}
	return pub, nil
}

// TrustedPeerEntry binds a peer_id to its canonical public_key string in config.
type TrustedPeerEntry struct {
	PeerID    string `json:"peer_id"`
	PublicKey string `json:"public_key"`
}

// ACLRule authorizes communication between PeerA and PeerB (bidirectional by default).
type ACLRule struct {
	PeerA          string `json:"peer_a"`
	PeerB          string `json:"peer_b"`
	Unidirectional bool   `json:"unidirectional,omitempty"`
}

// PolicyConfig represents the serialized trust and authorization policy file.
type PolicyConfig struct {
	Version            int                `json:"v"`
	TrustedAuthorities []string           `json:"trusted_authorities,omitempty"`
	TrustedPeers       []TrustedPeerEntry `json:"trusted_peers,omitempty"`
	Memberships        []MembershipRecord `json:"memberships,omitempty"`
	ACLRules           []ACLRule          `json:"acl_rules,omitempty"`
	RevokedPeers       []string           `json:"revoked_peers,omitempty"`
}

// VerifiedPeer stores verified identity material for an authorized peer.
type VerifiedPeer struct {
	PeerID     string
	PublicKey  PublicKey
	Membership *MembershipRecord
}

// TrustVerifier enforces independent peer trust, membership validity, revocations,
// and default-deny connection ACLs on either a Hub or a Peer.
type TrustVerifier struct {
	mu             sync.RWMutex
	authorities    map[string]PublicKey
	pinnedPeers    map[string]PublicKey
	memberships    map[string]*MembershipRecord
	aclAllowed     map[[2]string]bool
	aclWildcard    map[string]bool
	hasExplicitACL bool
	revoked        map[string]struct{}
	clockSkew      time.Duration
	nowFunc        func() time.Time
}

// NewTrustVerifier builds a validated TrustVerifier from PolicyConfig.
func NewTrustVerifier(cfg PolicyConfig, clockSkew time.Duration) (*TrustVerifier, error) {
	tv := &TrustVerifier{
		authorities: make(map[string]PublicKey),
		pinnedPeers: make(map[string]PublicKey),
		memberships: make(map[string]*MembershipRecord),
		aclAllowed:  make(map[[2]string]bool),
		aclWildcard: make(map[string]bool),
		revoked:     make(map[string]struct{}),
		clockSkew:   clockSkew,
		nowFunc:     time.Now,
	}
	if err := tv.Reload(cfg); err != nil {
		return nil, err
	}
	return tv, nil
}

// SetClock overrides the time source (used for deterministic expiry testing).
func (tv *TrustVerifier) SetClock(nowFunc func() time.Time) {
	tv.mu.Lock()
	defer tv.mu.Unlock()
	tv.nowFunc = nowFunc
}

// Reload atomically validates and replaces the active trust and ACL policy.
func (tv *TrustVerifier) Reload(cfg PolicyConfig) error {
	if cfg.Version != 0 && cfg.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", cfg.Version)
	}
	authorities := make(map[string]PublicKey, len(cfg.TrustedAuthorities))
	for _, enc := range cfg.TrustedAuthorities {
		pub, err := DecodePublicKey(enc)
		if err != nil {
			return fmt.Errorf("invalid authority key: %w", err)
		}
		id, err := PeerIDFromPublicKey(pub)
		if err != nil {
			return err
		}
		authorities[id] = pub
	}

	pinned := make(map[string]PublicKey, len(cfg.TrustedPeers))
	for _, tp := range cfg.TrustedPeers {
		pub, err := DecodePublicKey(tp.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid trusted peer key for %s: %w", tp.PeerID, err)
		}
		derived, err := PeerIDFromPublicKey(pub)
		if err != nil {
			return err
		}
		if tp.PeerID != "" && tp.PeerID != derived {
			return fmt.Errorf("%w: %s", ErrPeerIDMismatch, tp.PeerID)
		}
		pinned[derived] = pub
	}

	memberships := make(map[string]*MembershipRecord, len(cfg.Memberships))
	for i := range cfg.Memberships {
		rec := cfg.Memberships[i]
		if _, err := VerifyMembershipRecord(&rec, authorities, time.Unix(rec.IssuedAt, 0), tv.clockSkew); err != nil {
			return fmt.Errorf("invalid preloaded membership for %s: %w", rec.PeerID, err)
		}
		recCopy := rec
		memberships[rec.PeerID] = &recCopy
	}

	aclAllowed := make(map[[2]string]bool, len(cfg.ACLRules)*2)
	aclWildcard := make(map[string]bool)
	for _, rule := range cfg.ACLRules {
		if rule.PeerA == "" || rule.PeerB == "" || rule.PeerA == rule.PeerB {
			return fmt.Errorf("invalid ACL rule (%q, %q)", rule.PeerA, rule.PeerB)
		}
		if rule.PeerB == "*" {
			if err := ValidatePeerID(rule.PeerA); err != nil {
				return err
			}
			aclWildcard[rule.PeerA] = true
			continue
		}
		if err := ValidatePeerID(rule.PeerA); err != nil {
			return err
		}
		if err := ValidatePeerID(rule.PeerB); err != nil {
			return err
		}
		aclAllowed[[2]string{rule.PeerA, rule.PeerB}] = true
		if !rule.Unidirectional {
			aclAllowed[[2]string{rule.PeerB, rule.PeerA}] = true
		}
	}

	revoked := make(map[string]struct{}, len(cfg.RevokedPeers))
	for _, pid := range cfg.RevokedPeers {
		if err := ValidatePeerID(pid); err != nil {
			return err
		}
		revoked[pid] = struct{}{}
	}

	tv.mu.Lock()
	tv.authorities = authorities
	tv.pinnedPeers = pinned
	tv.memberships = memberships
	tv.aclAllowed = aclAllowed
	tv.aclWildcard = aclWildcard
	tv.hasExplicitACL = len(cfg.ACLRules) > 0
	tv.revoked = revoked
	tv.mu.Unlock()
	return nil
}

// LoadPolicyFile loads a PolicyConfig strictly from disk.
func LoadPolicyFile(path string) (PolicyConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PolicyConfig{}, fmt.Errorf("read policy file %s: %w", path, err)
	}
	var cfg PolicyConfig
	if err := jcs.UnmarshalStrict(raw, &cfg); err != nil {
		return PolicyConfig{}, fmt.Errorf("parse policy file %s: %w", path, err)
	}
	return cfg, nil
}

// VerifyPeer authenticates a peer's identity and membership against pinned keys
// or offline-authority-signed membership records, enforcing revocation checks.
func (tv *TrustVerifier) VerifyPeer(peerID string, pub PublicKey, rec *MembershipRecord) (*VerifiedPeer, error) {
	if err := ValidatePeerID(peerID); err != nil {
		return nil, err
	}
	tv.mu.RLock()
	defer tv.mu.RUnlock()

	if _, isRevoked := tv.revoked[peerID]; isRevoked {
		return nil, ErrRevokedPeer
	}

	now := tv.nowFunc()

	if pub.IsZero() {
		if p, ok := tv.pinnedPeers[peerID]; ok {
			pub = p
		} else if m, ok := tv.memberships[peerID]; ok && rec == nil {
			rec = m
		}
	}

	if !pub.IsZero() {
		derived, err := PeerIDFromPublicKey(pub)
		if err != nil {
			return nil, err
		}
		if derived != peerID {
			return nil, ErrPeerIDMismatch
		}
	}

	if rec == nil {
		if storedRec, ok := tv.memberships[peerID]; ok {
			rec = storedRec
		}
	}

	if rec != nil {
		recPub, err := VerifyMembershipRecord(rec, tv.authorities, now, tv.clockSkew)
		if err != nil {
			return nil, err
		}
		if rec.PeerID != peerID {
			return nil, ErrPeerIDMismatch
		}
		if !pub.IsZero() && !pub.Equal(recPub) {
			return nil, ErrPeerIDMismatch
		}
		recCopy := *rec
		return &VerifiedPeer{
			PeerID:     peerID,
			PublicKey:  recPub,
			Membership: &recCopy,
		}, nil
	}

	if pinnedPub, ok := tv.pinnedPeers[peerID]; ok {
		if !pub.IsZero() && !pub.Equal(pinnedPub) {
			return nil, ErrPeerIDMismatch
		}
		return &VerifiedPeer{
			PeerID:    peerID,
			PublicKey: pinnedPub,
		}, nil
	}

	return nil, ErrUntrustedPeer
}

// CacheVerifiedPeer records an authority-verified peer membership in memory.
func (tv *TrustVerifier) CacheVerifiedPeer(vp *VerifiedPeer) {
	if vp == nil || vp.Membership == nil {
		return
	}
	tv.mu.Lock()
	defer tv.mu.Unlock()
	recCopy := *vp.Membership
	tv.memberships[vp.PeerID] = &recCopy
}

// IsRevoked reports whether peerID is currently revoked.
func (tv *TrustVerifier) IsRevoked(peerID string) bool {
	tv.mu.RLock()
	defer tv.mu.RUnlock()
	_, ok := tv.revoked[peerID]
	return ok
}

// AuthorizePair enforces the default-deny connection ACL between fromPeer and toPeer.
func (tv *TrustVerifier) AuthorizePair(fromPeer, toPeer string, fromRec, toRec *MembershipRecord) error {
	if fromPeer == "" || toPeer == "" || fromPeer == toPeer {
		return ErrUnauthorizedPair
	}
	if err := ValidatePeerID(fromPeer); err != nil {
		return ErrUnauthorizedPair
	}
	if err := ValidatePeerID(toPeer); err != nil {
		return ErrUnauthorizedPair
	}

	tv.mu.RLock()
	defer tv.mu.RUnlock()

	if _, bad := tv.revoked[fromPeer]; bad {
		return ErrRevokedPeer
	}
	if _, bad := tv.revoked[toPeer]; bad {
		return ErrRevokedPeer
	}

	if fromRec == nil {
		fromRec = tv.memberships[fromPeer]
	}
	if toRec == nil {
		toRec = tv.memberships[toPeer]
	}

	if fromRec != nil && len(fromRec.AllowedPeers) > 0 && !peerListAllows(fromRec.AllowedPeers, toPeer) {
		return ErrUnauthorizedPair
	}
	if toRec != nil && len(toRec.AllowedPeers) > 0 && !peerListAllows(toRec.AllowedPeers, fromPeer) {
		return ErrUnauthorizedPair
	}

	if tv.hasExplicitACL {
		if tv.aclAllowed[[2]string{fromPeer, toPeer}] {
			return nil
		}
		if tv.aclWildcard[fromPeer] && (tv.aclWildcard[toPeer] || tv.aclAllowed[[2]string{toPeer, fromPeer}]) {
			return nil
		}
		return ErrUnauthorizedPair
	}

	if fromRec != nil && len(fromRec.AllowedPeers) > 0 && peerListAllows(fromRec.AllowedPeers, toPeer) &&
		toRec != nil && len(toRec.AllowedPeers) > 0 && peerListAllows(toRec.AllowedPeers, fromPeer) {
		return nil
	}

	return ErrUnauthorizedPair
}

func peerListAllows(allowed []string, target string) bool {
	for _, p := range allowed {
		if p == "*" || p == target {
			return true
		}
	}
	return false
}
