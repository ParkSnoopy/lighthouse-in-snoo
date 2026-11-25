package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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

	"lighthouse-in-snoo/internal/jcs"
)

const (
	// DomainRegisterV1 is the domain separator for hub registration proofs.
	DomainRegisterV1 = "LIGHTHOUSE-REGISTER-V1\x00"
	// DomainMembershipV1 is the domain separator for offline authority membership records.
	DomainMembershipV1 = "LIGHTHOUSE-MEMBERSHIP-V1\x00"

	// PeerIDEncodedLen is the base64url (unpadded) length of a 32-byte SHA-256 digest.
	PeerIDEncodedLen = 43
)

var (
	ErrInvalidPublicKey  = errors.New("identity: invalid Ed25519 public key")
	ErrInvalidPrivateKey = errors.New("identity: invalid Ed25519 private key")
	ErrInvalidPeerID     = errors.New("identity: invalid peer_id")
	ErrPeerIDMismatch    = errors.New("identity: peer_id does not match public key")
	ErrUntrustedPeer     = errors.New("identity: untrusted peer identity")
	ErrRevokedPeer       = errors.New("identity: peer identity is revoked")
	ErrMembershipExpired = errors.New("identity: membership record expired or not yet valid")
	ErrUnauthorizedPair  = errors.New("identity: peer pair denied by ACL")
	ErrInvalidProof      = errors.New("identity: invalid signature proof")
	ErrInvalidOrigin     = errors.New("identity: invalid hub origin")
	ErrInsecureFilePerms = errors.New("identity: key file permissions are too permissive")
)

// KeyPair holds a peer or authority Ed25519 identity key pair.
type KeyPair struct {
	PeerID     string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

type storedKeyFile struct {
	Version    int    `json:"v"`
	PeerID     string `json:"peer_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// GenerateKeyPair creates a fresh Ed25519 identity key pair and derives its peer_id.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	id, err := PeerIDFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PeerID:     id,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// KeyPairFromSeed derives a deterministic Ed25519 identity key pair from a 32-byte seed.
func KeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrInvalidPrivateKey
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	id, err := PeerIDFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PeerID:     id,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// PeerIDFromPublicKey returns the unpadded base64url encoding of SHA-256 over
// the raw 32-byte Ed25519 public key (Section 3).
func PeerIDFromPublicKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", ErrInvalidPublicKey
	}
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
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
	// Reject non-canonical base64url trailing bits.
	if base64.RawURLEncoding.EncodeToString(decoded) != peerID {
		return ErrInvalidPeerID
	}
	return nil
}

// EncodePublicKey encodes a 32-byte Ed25519 public key as unpadded base64url.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// DecodePublicKey decodes an unpadded base64url 32-byte Ed25519 public key.
func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	if base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, ErrInvalidPublicKey
	}
	return ed25519.PublicKey(raw), nil
}

// Save writes the identity key pair to path with 0600 permissions.
func (kp *KeyPair) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	payload, err := json.MarshalIndent(storedKeyFile{
		Version:    1,
		PeerID:     kp.PeerID,
		PublicKey:  EncodePublicKey(kp.PublicKey),
		PrivateKey: base64.RawURLEncoding.EncodeToString(kp.PrivateKey.Seed()),
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

// LoadKeyPair reads a persistent Ed25519 identity key pair and verifies 0600 permissions.
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
	seed, err := base64.RawURLEncoding.DecodeString(sf.PrivateKey)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	if sf.PeerID != kp.PeerID || sf.PublicKey != EncodePublicKey(kp.PublicKey) {
		return nil, ErrPeerIDMismatch
	}
	return kp, nil
}

// LoadOrGenerateKeyPair loads an existing key pair or creates and saves one if absent.
func LoadOrGenerateKeyPair(path string) (*KeyPair, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		kp, genErr := GenerateKeyPair()
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
	sig := ed25519.Sign(kp.PrivateKey, msg)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyRegistrationChallenge verifies a peer's registration challenge proof.
func VerifyRegistrationChallenge(pub ed25519.PublicKey, peerID, challenge, hubOrigin, proof string) error {
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
	sig, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != proof {
		return ErrInvalidProof
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
	if !ed25519.Verify(pub, msg, sig) {
		return ErrInvalidProof
	}
	return nil
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
func IssueMembership(authority *KeyPair, peerPub ed25519.PublicKey, issuedAt, expiresAt int64, allowedPeers []string) (*MembershipRecord, error) {
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
	sig := ed25519.Sign(authority.PrivateKey, msg)
	return &MembershipRecord{
		Version:      unsigned.Version,
		PeerID:       unsigned.PeerID,
		PublicKey:    unsigned.PublicKey,
		IssuedAt:     unsigned.IssuedAt,
		ExpiresAt:    unsigned.ExpiresAt,
		AllowedPeers: unsigned.AllowedPeers,
		Issuer:       unsigned.Issuer,
		Sig:          base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// VerifyMembershipRecord validates a signed MembershipRecord against a map of
// trusted offline authority public keys (keyed by authority ID).
func VerifyMembershipRecord(rec *MembershipRecord, authorities map[string]ed25519.PublicKey, now time.Time, skew time.Duration) (ed25519.PublicKey, error) {
	if rec == nil || rec.Version != 1 {
		return nil, ErrUntrustedPeer
	}
	pub, err := DecodePublicKey(rec.PublicKey)
	if err != nil {
		return nil, err
	}
	derivedID, err := PeerIDFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if derivedID != rec.PeerID {
		return nil, ErrPeerIDMismatch
	}
	authPub, ok := authorities[rec.Issuer]
	if !ok {
		return nil, ErrUntrustedPeer
	}
	nowUnix := now.Unix()
	skewSec := int64(skew / time.Second)
	if rec.ExpiresAt+skewSec < nowUnix || rec.IssuedAt-skewSec > nowUnix || rec.ExpiresAt <= rec.IssuedAt {
		return nil, ErrMembershipExpired
	}
	sig, err := base64.RawURLEncoding.DecodeString(rec.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != rec.Sig {
		return nil, ErrInvalidProof
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
		return nil, err
	}
	msg := make([]byte, 0, len(DomainMembershipV1)+len(canon))
	msg = append(msg, DomainMembershipV1...)
	msg = append(msg, canon...)
	if !ed25519.Verify(authPub, msg, sig) {
		return nil, ErrInvalidProof
	}
	return pub, nil
}

// TrustedPeerEntry binds a peer_id to its raw 32-byte Ed25519 public key in config.
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
	PublicKey  ed25519.PublicKey
	Membership *MembershipRecord
}

// TrustVerifier enforces independent peer trust, membership validity, revocations,
// and default-deny connection ACLs on either a Hub or a Peer.
type TrustVerifier struct {
	mu             sync.RWMutex
	authorities    map[string]ed25519.PublicKey
	pinnedPeers    map[string]ed25519.PublicKey
	memberships    map[string]*MembershipRecord
	aclAllowed     map[[2]string]bool
	aclWildcard    map[string]bool // peer -> allowed with any other trusted peer if configured explicitly
	hasExplicitACL bool
	revoked        map[string]struct{}
	clockSkew      time.Duration
	nowFunc        func() time.Time
}

// NewTrustVerifier builds a validated TrustVerifier from PolicyConfig.
func NewTrustVerifier(cfg PolicyConfig, clockSkew time.Duration) (*TrustVerifier, error) {
	tv := &TrustVerifier{
		authorities: make(map[string]ed25519.PublicKey),
		pinnedPeers: make(map[string]ed25519.PublicKey),
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
	authorities := make(map[string]ed25519.PublicKey, len(cfg.TrustedAuthorities))
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

	pinned := make(map[string]ed25519.PublicKey, len(cfg.TrustedPeers))
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
		// Validate signature structurally at load time (using IssuedAt+1 for time check if valid).
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
func (tv *TrustVerifier) VerifyPeer(peerID string, pub ed25519.PublicKey, rec *MembershipRecord) (*VerifiedPeer, error) {
	if err := ValidatePeerID(peerID); err != nil {
		return nil, err
	}
	tv.mu.RLock()
	defer tv.mu.RUnlock()

	if _, isRevoked := tv.revoked[peerID]; isRevoked {
		return nil, ErrRevokedPeer
	}

	now := tv.nowFunc()

	// Resolve public key if caller didn't pass one (e.g. lookup of pre-provisioned peer).
	if len(pub) == 0 {
		if p, ok := tv.pinnedPeers[peerID]; ok {
			pub = p
		} else if m, ok := tv.memberships[peerID]; ok && rec == nil {
			rec = m
		}
	}

	if len(pub) > 0 {
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
		if len(pub) > 0 && !pub.Equal(recPub) {
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
		if len(pub) > 0 && !pub.Equal(pinnedPub) {
			return nil, ErrPeerIDMismatch
		}
		return &VerifiedPeer{
			PeerID:    peerID,
			PublicKey: pinnedPub,
		}, nil
	}

	return nil, ErrUntrustedPeer
}

// CacheVerifiedPeer records an authority-verified peer membership in memory so
// subsequent lookups/verifications can inspect it (still re-checking expiry & revocation).
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
// Both peers must be non-identical, non-revoked, and explicitly authorized by
// configured ACL rules and/or signed membership AllowedPeers constraints.
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

	// If a membership record scopes allowed_peers, enforce it strictly.
	if fromRec != nil && len(fromRec.AllowedPeers) > 0 && !peerListAllows(fromRec.AllowedPeers, toPeer) {
		return ErrUnauthorizedPair
	}
	if toRec != nil && len(toRec.AllowedPeers) > 0 && !peerListAllows(toRec.AllowedPeers, fromPeer) {
		return ErrUnauthorizedPair
	}

	// Local ACL rules take precedence when configured; if no static ACL rules are
	// present, both peers must carry membership records that explicitly authorize the pair.
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
