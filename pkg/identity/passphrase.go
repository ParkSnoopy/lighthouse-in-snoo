package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"lighthouse-in-snoo/internal/jcs"
)

const (
	// ChannelIDEncodedLen is the base64url (unpadded) length of a 32-byte passphrase channel token.
	ChannelIDEncodedLen = 43

	domainHubAuthV2 = "LIGHTHOUSE-HUB-AUTH-V2\x00"
	domainTunIPv4V2 = "LIGHTHOUSE-TUN-IPV4-V2\x00"

	argonTime    uint32 = 1
	argonMemory  uint32 = 16 * 1024 // 16 MiB: brute-force resistant yet responsive in interactive UI.
	argonThreads uint8  = 2
)

var (
	channelSalt = []byte("LIGHTHOUSE-CHANNEL-V2")
	hubKeySalt  = []byte("LIGHTHOUSE-HUB-KEY-V2")
)

// ChannelKeys holds the passphrase-derived broadcast bucket ID and metadata encryption key.
// The raw passphrase is never transmitted over the network.
type ChannelKeys struct {
	ChannelID string
	AuthKey   [chacha20poly1305.KeySize]byte
}

// BroadcastMeta carries user-visible metadata sealed end to end under a passphrase channel key.
type BroadcastMeta struct {
	DisplayName string `json:"display_name,omitempty"`
	VirtualIP   string `json:"virtual_ip,omitempty"`
}

// DeriveChannelKeys derives an opaque hub routing ChannelID and a client-side AEAD AuthKey
// from an offline shared broadcast passphrase.
func DeriveChannelKeys(passphrase string) (ChannelKeys, error) {
	if strings.TrimSpace(passphrase) == "" {
		return ChannelKeys{}, ErrEmptyPassphrase
	}
	derived := argon2.IDKey([]byte(passphrase), channelSalt, argonTime, argonMemory, argonThreads, 64)
	var keys ChannelKeys
	keys.ChannelID = base64.RawURLEncoding.EncodeToString(derived[:32])
	copy(keys.AuthKey[:], derived[32:64])
	return keys, nil
}

// ValidateChannelID validates that id is a canonical 32-byte unpadded base64url channel token.
func ValidateChannelID(id string) error {
	if len(id) != ChannelIDEncodedLen {
		return ErrInvalidChannelID
	}
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(decoded) != 32 {
		return ErrInvalidChannelID
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != id {
		return ErrInvalidChannelID
	}
	return nil
}

// SealBroadcastMeta encrypts BroadcastMeta with XChaCha20-Poly1305 bound to (peerID, channelID).
func SealBroadcastMeta(authKey [chacha20poly1305.KeySize]byte, peerID, channelID string, meta BroadcastMeta) (string, error) {
	if err := ValidatePeerID(peerID); err != nil {
		return "", err
	}
	if err := ValidateChannelID(channelID); err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(authKey[:])
	if err != nil {
		return "", err
	}
	plain, err := jcs.MarshalCanonical(meta)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	aad := []byte(peerID + "\x00" + channelID)
	sealed := aead.Seal(nonce, nonce, plain, aad)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// OpenBroadcastMeta decrypts and authenticates sealed broadcast metadata using authKey.
func OpenBroadcastMeta(authKey [chacha20poly1305.KeySize]byte, peerID, channelID, sealed string) (BroadcastMeta, error) {
	if sealed == "" {
		return BroadcastMeta{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) <= chacha20poly1305.NonceSizeX {
		return BroadcastMeta{}, ErrInvalidSealedMeta
	}
	aead, err := chacha20poly1305.NewX(authKey[:])
	if err != nil {
		return BroadcastMeta{}, err
	}
	nonce := raw[:chacha20poly1305.NonceSizeX]
	ciphertext := raw[chacha20poly1305.NonceSizeX:]
	aad := []byte(peerID + "\x00" + channelID)
	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return BroadcastMeta{}, ErrInvalidSealedMeta
	}
	var meta BroadcastMeta
	if err := jcs.UnmarshalStrict(plain, &meta); err != nil {
		return BroadcastMeta{}, ErrInvalidSealedMeta
	}
	return meta, nil
}

// DeriveHubKey derives a 32-byte MAC key from an optional offline hub passphrase.
func DeriveHubKey(passphrase string) ([32]byte, error) {
	var out [32]byte
	if strings.TrimSpace(passphrase) == "" {
		return out, ErrEmptyPassphrase
	}
	raw := argon2.IDKey([]byte(passphrase), hubKeySalt, argonTime, argonMemory, argonThreads, 32)
	copy(out[:], raw)
	return out, nil
}

// SignHubPassphraseProof computes a challenge-bound HMAC proof for a hub passphrase
// without transmitting the passphrase itself.
func SignHubPassphraseProof(passphrase, challenge, hubOrigin, peerID string) (string, error) {
	key, err := DeriveHubKey(passphrase)
	if err != nil {
		return "", err
	}
	return SignHubPassphraseProofWithKey(key, challenge, hubOrigin, peerID)
}

// SignHubPassphraseProofWithKey computes the challenge-bound HMAC proof from a pre-derived hub key.
func SignHubPassphraseProofWithKey(hubKey [32]byte, challenge, hubOrigin, peerID string) (string, error) {
	origin, err := CanonicalizeOrigin(hubOrigin)
	if err != nil {
		return "", err
	}
	if challenge == "" {
		return "", ErrInvalidProof
	}
	if err := ValidatePeerID(peerID); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, hubKey[:])
	_, _ = mac.Write([]byte(domainHubAuthV2))
	_, _ = mac.Write([]byte(challenge))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(origin))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(peerID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHubPassphraseProofWithKey validates a challenge-bound hub passphrase proof in constant time.
func VerifyHubPassphraseProofWithKey(hubKey [32]byte, challenge, hubOrigin, peerID, proof string) error {
	if proof == "" {
		return ErrInvalidProof
	}
	expected, err := SignHubPassphraseProofWithKey(hubKey, challenge, hubOrigin, peerID)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(expected), []byte(proof)) {
		return ErrInvalidProof
	}
	return nil
}

// VirtualIPv4FromPeerID deterministically derives a unique RFC 6598 (100.64.0.0/10)
// TUN IPv4 address bound to peerID.
func VirtualIPv4FromPeerID(peerID string) (netip.Addr, error) {
	if err := ValidatePeerID(peerID); err != nil {
		return netip.Addr{}, err
	}
	sum := sha256.Sum256([]byte(domainTunIPv4V2 + peerID))
	b1 := 64 + (sum[0] & 0x3F)
	b2 := sum[1]
	b3 := sum[2]
	switch b3 {
	case 0:
		b3 = 1
	case 255:
		b3 = 254
	}
	if b1 == 64 && b2 == 0 && b3 == 1 {
		b3 = 2
	}
	return netip.AddrFrom4([4]byte{100, b1, b2, b3}), nil
}

// Blacklist stores locally blocked peer_ids enforced client-side.
type Blacklist struct {
	mu    sync.RWMutex
	peers map[string]struct{}
}

type storedBlacklistFile struct {
	Version int      `json:"v"`
	Peers   []string `json:"blacklisted_peers"`
}

// NewBlacklist creates an empty thread-safe local peer blacklist.
func NewBlacklist() *Blacklist {
	return &Blacklist{peers: make(map[string]struct{})}
}

// LoadBlacklist reads a persisted local blacklist JSON file, returning an empty blacklist if absent.
func LoadBlacklist(path string) (*Blacklist, error) {
	bl := NewBlacklist()
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return bl, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat blacklist: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o", ErrInsecureFilePerms, path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read blacklist: %w", err)
	}
	var sf storedBlacklistFile
	if err := jcs.UnmarshalStrict(raw, &sf); err != nil {
		return nil, fmt.Errorf("parse blacklist: %w", err)
	}
	if sf.Version != 1 {
		return nil, fmt.Errorf("unsupported blacklist version %d", sf.Version)
	}
	for _, pid := range sf.Peers {
		if err := ValidatePeerID(pid); err != nil {
			return nil, err
		}
		bl.peers[pid] = struct{}{}
	}
	return bl, nil
}

// Add inserts peerID into the blacklist.
func (b *Blacklist) Add(peerID string) error {
	if err := ValidatePeerID(peerID); err != nil {
		return err
	}
	b.mu.Lock()
	b.peers[peerID] = struct{}{}
	b.mu.Unlock()
	return nil
}

// Remove deletes peerID from the blacklist.
func (b *Blacklist) Remove(peerID string) {
	b.mu.Lock()
	delete(b.peers, peerID)
	b.mu.Unlock()
}

// Contains reports whether peerID is blacklisted.
func (b *Blacklist) Contains(peerID string) bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	_, ok := b.peers[peerID]
	b.mu.RUnlock()
	return ok
}

// List returns a deterministic sorted snapshot of all blacklisted peer_ids.
func (b *Blacklist) List() []string {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	out := make([]string, 0, len(b.peers))
	for pid := range b.peers {
		out = append(out, pid)
	}
	b.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Save atomically persists the blacklist to path with 0600 permissions.
func (b *Blacklist) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create blacklist dir: %w", err)
	}
	payload, err := json.MarshalIndent(storedBlacklistFile{
		Version: 1,
		Peers:   b.List(),
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return fmt.Errorf("write blacklist: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit blacklist: %w", err)
	}
	return nil
}
