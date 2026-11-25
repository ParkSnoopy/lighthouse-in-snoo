package identity_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if _, err := tv.VerifyPeer(peerB.PeerID, peerB.PublicKey, recB); !errors.Is(err, identity.ErrRevokedPeer) {
		t.Fatalf("expected ErrRevokedPeer, got %v", err)
	}
}

func TestMultiAlgorithmKeyGenSaveSignAndVerify(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		algoInput  string
		wantAlgo   identity.Algorithm
		rsaBits    int
		wantPrefix string
	}{
		{"ed25519 default", "ed25519", identity.AlgorithmEd25519, 0, ""},
		{"ed448", "ed448", identity.AlgorithmEd448, 0, "ed448:"},
		{"nistp-256", "nistp-256", identity.AlgorithmNISTP256, 0, "nistp-256:"},
		{"nistp-384 alias", "p384", identity.AlgorithmNISTP384, 0, "nistp-384:"},
		{"nistp-521", "nistp-521", identity.AlgorithmNISTP521, 0, "nistp-521:"},
		{"rsa 2048", "rsa", identity.AlgorithmRSA, 2048, "rsa:"},
	}

	// Generate an Ed448 authority to cross-sign memberships for every peer algorithm.
	authKP, err := identity.GenerateKeyPairWithOptions(identity.KeyGenOptions{Algorithm: identity.AlgorithmEd448})
	if err != nil {
		t.Fatalf("generate ed448 authority: %v", err)
	}

	dir := t.TempDir()
	now := time.Now()
	authorities := map[string]identity.PublicKey{authKP.PeerID: authKP.PublicKey}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			algo, err := identity.ParseAlgorithm(tc.algoInput)
			if err != nil {
				t.Fatalf("ParseAlgorithm(%q): %v", tc.algoInput, err)
			}
			if algo != tc.wantAlgo {
				t.Fatalf("ParseAlgorithm(%q) = %q; want %q", tc.algoInput, algo, tc.wantAlgo)
			}

			kp, err := identity.GenerateKeyPairWithOptions(identity.KeyGenOptions{
				Algorithm: algo,
				RSABits:   tc.rsaBits,
			})
			if err != nil {
				t.Fatalf("GenerateKeyPairWithOptions(%s): %v", algo, err)
			}
			if kp.Algorithm != tc.wantAlgo {
				t.Fatalf("got algo %q; want %q", kp.Algorithm, tc.wantAlgo)
			}
			if err := identity.ValidatePeerID(kp.PeerID); err != nil {
				t.Fatalf("ValidatePeerID(%s): %v", algo, err)
			}

			encPub := identity.EncodePublicKey(kp.PublicKey)
			if tc.wantPrefix == "" && strings.Contains(encPub, ":") {
				t.Fatalf("expected unprefixed base64url for ed25519, got %q", encPub)
			}
			if tc.wantPrefix != "" && !strings.HasPrefix(encPub, tc.wantPrefix) {
				t.Fatalf("expected prefix %q, got %q", tc.wantPrefix, encPub)
			}

			decodedPub, err := identity.DecodePublicKey(encPub)
			if err != nil {
				t.Fatalf("DecodePublicKey(%s): %v", algo, err)
			}
			if !decodedPub.Equal(kp.PublicKey) {
				t.Fatalf("decoded public key mismatch for %s", algo)
			}

			keyFile := filepath.Join(dir, string(algo)+"-"+strings.ReplaceAll(tc.name, " ", "_")+".key")
			if err := kp.Save(keyFile); err != nil {
				t.Fatalf("Save(%s): %v", algo, err)
			}
			loaded, err := identity.LoadKeyPair(keyFile)
			if err != nil {
				t.Fatalf("LoadKeyPair(%s): %v", algo, err)
			}
			if loaded.PeerID != kp.PeerID || !loaded.PublicKey.Equal(kp.PublicKey) || loaded.Algorithm != kp.Algorithm {
				t.Fatalf("reloaded keypair mismatch for %s", algo)
			}

			// Registration proof round-trip + tamper check.
			challenge := "0123456789abcdef0123456789abcdef0123456789a"
			proof, err := loaded.SignRegistrationChallenge(challenge, "wss://hub.example.com")
			if err != nil {
				t.Fatalf("SignRegistrationChallenge(%s): %v", algo, err)
			}
			if err := identity.VerifyRegistrationChallenge(decodedPub, kp.PeerID, challenge, "wss://hub.example.com", proof); err != nil {
				t.Fatalf("VerifyRegistrationChallenge(%s): %v", algo, err)
			}
			if err := identity.VerifyRegistrationChallenge(decodedPub, kp.PeerID, challenge, "wss://other.example.com", proof); !errors.Is(err, identity.ErrInvalidProof) {
				t.Fatalf("expected ErrInvalidProof on wrong origin for %s, got %v", algo, err)
			}

			// Cross-algorithm offline authority membership issuance & verification.
			rec, err := identity.IssueMembership(authKP, decodedPub, now.Unix()-60, now.Unix()+3600, []string{"*"})
			if err != nil {
				t.Fatalf("IssueMembership(%s): %v", algo, err)
			}
			verifiedPub, err := identity.VerifyMembershipRecord(rec, authorities, now, 30*time.Second)
			if err != nil {
				t.Fatalf("VerifyMembershipRecord(%s): %v", algo, err)
			}
			if !verifiedPub.Equal(kp.PublicKey) {
				t.Fatalf("verified membership public key mismatch for %s", algo)
			}
		})
	}

	t.Run("reject weak RSA bits and unsupported algorithms", func(t *testing.T) {
		t.Parallel()
		if _, err := identity.ParseAlgorithm("md5-rsa"); !errors.Is(err, identity.ErrUnsupportedAlgorithm) {
			t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
		}
		if _, err := identity.GenerateKeyPairWithOptions(identity.KeyGenOptions{Algorithm: identity.AlgorithmRSA, RSABits: 1024}); !errors.Is(err, identity.ErrInvalidKeyBits) {
			t.Fatalf("expected ErrInvalidKeyBits for 1024-bit RSA, got %v", err)
		}
		if _, err := identity.GenerateKeyPairWithOptions(identity.KeyGenOptions{Algorithm: identity.AlgorithmEd448, RSABits: 2048}); !errors.Is(err, identity.ErrInvalidKeyBits) {
			t.Fatalf("expected ErrInvalidKeyBits when --bits passed for ed448, got %v", err)
		}
	})
}
