package identity_test

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lighthouse-in-snoo/pkg/identity"
)

func TestKeyPairPersistenceAndPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "peer.key")

	kp, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := identity.ValidatePeerID(kp.PeerID); err != nil {
		t.Fatalf("ValidatePeerID: %v", err)
	}
	if err := kp.Save(keyFile); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := identity.LoadKeyPair(keyFile)
	if err != nil {
		t.Fatalf("LoadKeyPair: %v", err)
	}
	if loaded.PeerID != kp.PeerID || !loaded.PublicKey.Equal(kp.PublicKey) {
		t.Fatalf("loaded key mismatch")
	}

	// Relaxing permissions to 0644 MUST be rejected.
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := identity.LoadKeyPair(keyFile); !errors.Is(err, identity.ErrInsecureFilePerms) {
		t.Fatalf("expected ErrInsecureFilePerms, got %v", err)
	}
}

func TestRegistrationChallengeProof(t *testing.T) {
	t.Parallel()

	kp, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	challenge := "0123456789abcdef0123456789abcdef0123456789a"
	proof, err := kp.SignRegistrationChallenge(challenge, "https://Hub.Example.com:443/v1/signal")
	if err != nil {
		t.Fatalf("SignRegistrationChallenge: %v", err)
	}

	// Canonical wss://hub.example.com matches https://Hub.Example.com:443.
	if err := identity.VerifyRegistrationChallenge(kp.PublicKey, kp.PeerID, challenge, "wss://hub.example.com", proof); err != nil {
		t.Fatalf("VerifyRegistrationChallenge failed: %v", err)
	}

	// Different hub origin MUST fail verification.
	if err := identity.VerifyRegistrationChallenge(kp.PublicKey, kp.PeerID, challenge, "wss://evil.example.com", proof); !errors.Is(err, identity.ErrInvalidProof) {
		t.Fatalf("expected ErrInvalidProof for wrong origin, got %v", err)
	}
}

func TestOfflineAuthorityMembershipAndACL(t *testing.T) {
	t.Parallel()

	authKP, _ := identity.GenerateKeyPair()
	peerA, _ := identity.GenerateKeyPair()
	peerB, _ := identity.GenerateKeyPair()
	peerC, _ := identity.GenerateKeyPair()

	now := time.Unix(1_795_560_000, 0)
	recA, err := identity.IssueMembership(authKP, peerA.PublicKey, now.Unix()-60, now.Unix()+3600, []string{peerB.PeerID})
	if err != nil {
		t.Fatal(err)
	}
	recB, err := identity.IssueMembership(authKP, peerB.PublicKey, now.Unix()-60, now.Unix()+3600, []string{peerA.PeerID})
	if err != nil {
		t.Fatal(err)
	}
	recC, err := identity.IssueMembership(authKP, peerC.PublicKey, now.Unix()-60, now.Unix()+3600, []string{peerA.PeerID})
	if err != nil {
		t.Fatal(err)
	}

	tv, err := identity.NewTrustVerifier(identity.PolicyConfig{
		Version:            1,
		TrustedAuthorities: []string{identity.EncodePublicKey(authKP.PublicKey)},
		ACLRules: []identity.ACLRule{
			{PeerA: peerA.PeerID, PeerB: peerB.PeerID},
		},
	}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tv.SetClock(func() time.Time { return now })

	if _, err := tv.VerifyPeer(peerA.PeerID, peerA.PublicKey, recA); err != nil {
		t.Fatalf("VerifyPeer A: %v", err)
	}
	if err := tv.AuthorizePair(peerA.PeerID, peerB.PeerID, recA, recB); err != nil {
		t.Fatalf("AuthorizePair A<->B: %v", err)
	}
	if err := tv.AuthorizePair(peerA.PeerID, peerC.PeerID, recA, recC); !errors.Is(err, identity.ErrUnauthorizedPair) {
		t.Fatalf("expected unauthorized pair for A<->C, got %v", err)
	}

	// Advance clock beyond expiry + skew.
	tv.SetClock(func() time.Time { return now.Add(2 * time.Hour) })
	if _, err := tv.VerifyPeer(peerA.PeerID, peerA.PublicKey, recA); !errors.Is(err, identity.ErrMembershipExpired) {
		t.Fatalf("expected ErrMembershipExpired, got %v", err)
	}

	// Revocation check.
	tv.SetClock(func() time.Time { return now })
	if err := tv.Reload(identity.PolicyConfig{
		Version:            1,
		TrustedAuthorities: []string{identity.EncodePublicKey(authKP.PublicKey)},
		ACLRules:           []identity.ACLRule{{PeerA: peerA.PeerID, PeerB: peerB.PeerID}},
		RevokedPeers:       []string{peerB.PeerID},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tv.VerifyPeer(peerB.PeerID, ed25519.PublicKey(peerB.PublicKey), recB); !errors.Is(err, identity.ErrRevokedPeer) {
		t.Fatalf("expected ErrRevokedPeer, got %v", err)
	}
}
