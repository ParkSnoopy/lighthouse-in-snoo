package identity_test

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	dir := t.TempDir()

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

func TestChannelPassphraseDerivationAndSealedMeta(t *testing.T) {
	t.Parallel()

	if _, err := identity.DeriveChannelKeys("   "); !errors.Is(err, identity.ErrEmptyPassphrase) {
		t.Fatalf("expected ErrEmptyPassphrase, got %v", err)
	}

	k1, err := identity.DeriveChannelKeys("offline-shared-secret")
	if err != nil {
		t.Fatalf("DeriveChannelKeys: %v", err)
	}
	k2, err := identity.DeriveChannelKeys("offline-shared-secret")
	if err != nil {
		t.Fatalf("DeriveChannelKeys repeat: %v", err)
	}
	if k1.ChannelID != k2.ChannelID || k1.AuthKey != k2.AuthKey {
		t.Fatal("DeriveChannelKeys is not deterministic")
	}
	if err := identity.ValidateChannelID(k1.ChannelID); err != nil {
		t.Fatalf("ValidateChannelID: %v", err)
	}

	other, err := identity.DeriveChannelKeys("different-secret")
	if err != nil {
		t.Fatal(err)
	}
	if other.ChannelID == k1.ChannelID {
		t.Fatal("distinct passphrases produced identical channel IDs")
	}

	kp, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherKP, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := identity.SealBroadcastMeta(k1.AuthKey, kp.PeerID, k1.ChannelID, identity.BroadcastMeta{DisplayName: "alice-workstation"})
	if err != nil {
		t.Fatalf("SealBroadcastMeta: %v", err)
	}
	if strings.Contains(sealed, "alice-workstation") {
		t.Fatal("sealed broadcast metadata leaked plaintext display name")
	}

	got, err := identity.OpenBroadcastMeta(k1.AuthKey, kp.PeerID, k1.ChannelID, sealed)
	if err != nil || got.DisplayName != "alice-workstation" {
		t.Fatalf("OpenBroadcastMeta = %+v, %v; want alice-workstation", got, err)
	}

	// Wrong passphrase key MUST fail AEAD decryption.
	if _, err := identity.OpenBroadcastMeta(other.AuthKey, kp.PeerID, k1.ChannelID, sealed); err == nil {
		t.Fatal("expected OpenBroadcastMeta to fail with wrong passphrase")
	}
	// Swapped peer_id (AAD mismatch) MUST fail AEAD decryption.
	if _, err := identity.OpenBroadcastMeta(k1.AuthKey, otherKP.PeerID, k1.ChannelID, sealed); err == nil {
		t.Fatal("expected OpenBroadcastMeta to fail on peer_id AAD mismatch")
	}
}

func TestHubPassphraseChallengeProof(t *testing.T) {
	t.Parallel()

	kp, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := identity.DeriveHubKey("private-hub-passphrase")
	if err != nil {
		t.Fatalf("DeriveHubKey: %v", err)
	}
	challenge := "0123456789abcdef0123456789abcdef0123456789a"
	proof, err := identity.SignHubPassphraseProof("private-hub-passphrase", challenge, "wss://hub.example.com", kp.PeerID)
	if err != nil {
		t.Fatalf("SignHubPassphraseProof: %v", err)
	}

	if err := identity.VerifyHubPassphraseProofWithKey(hubKey, challenge, "wss://hub.example.com", kp.PeerID, proof); err != nil {
		t.Fatalf("VerifyHubPassphraseProofWithKey: %v", err)
	}

	wrongKey, _ := identity.DeriveHubKey("wrong-passphrase")
	if err := identity.VerifyHubPassphraseProofWithKey(wrongKey, challenge, "wss://hub.example.com", kp.PeerID, proof); !errors.Is(err, identity.ErrInvalidProof) {
		t.Fatalf("expected ErrInvalidProof for wrong passphrase, got %v", err)
	}
	if err := identity.VerifyHubPassphraseProofWithKey(hubKey, challenge, "wss://evil.example.com", kp.PeerID, proof); !errors.Is(err, identity.ErrInvalidProof) {
		t.Fatalf("expected ErrInvalidProof for wrong origin, got %v", err)
	}
	if err := identity.VerifyHubPassphraseProofWithKey(hubKey, "other-challenge-value-0123456789abcdef0123456", "wss://hub.example.com", kp.PeerID, proof); !errors.Is(err, identity.ErrInvalidProof) {
		t.Fatalf("expected ErrInvalidProof for wrong challenge, got %v", err)
	}
}

func TestVirtualIPv4FromPeerIDAndBlacklistPersistence(t *testing.T) {
	t.Parallel()

	kpA, _ := identity.GenerateKeyPair()
	kpB, _ := identity.GenerateKeyPair()

	defaultCIDR := netip.MustParsePrefix("10.88.0.0/16")
	if identity.DefaultVirtualCIDR() != defaultCIDR {
		t.Fatalf("DefaultVirtualCIDR() = %s; want %s", identity.DefaultVirtualCIDR(), defaultCIDR)
	}
	ipA, err := identity.VirtualIPv4FromPeerID(kpA.PeerID)
	if err != nil {
		t.Fatalf("VirtualIPv4FromPeerID: %v", err)
	}
	if !defaultCIDR.Contains(ipA) {
		t.Fatalf("virtual IP %s outside default 10.88.0.0/16", ipA)
	}
	if ipA == netip.MustParseAddr("10.88.0.0") || ipA == netip.MustParseAddr("10.88.255.255") {
		t.Fatalf("virtual IP %s must not be network or broadcast", ipA)
	}
	ipARepeat, err := identity.VirtualIPv4FromPeerID(kpA.PeerID)
	if err != nil || ipARepeat != ipA {
		t.Fatalf("VirtualIPv4FromPeerID not deterministic: %v vs %v (%v)", ipA, ipARepeat, err)
	}
	if _, err := identity.VirtualIPv4FromPeerID("bad-peer-id"); err == nil {
		t.Fatal("expected error for invalid peer ID")
	}

	// Custom CIDR parsing, normalization, and usable-host derivation.
	norm, err := identity.ParseVirtualCIDR(" 10.99.5.42/24 ")
	if err != nil || norm != netip.MustParsePrefix("10.99.5.0/24") {
		t.Fatalf("ParseVirtualCIDR normalization = (%s, %v); want 10.99.5.0/24", norm, err)
	}
	for _, cidrStr := range []string{"10.99.5.0/24", "172.20.0.0/16", "100.64.0.0/10", "10.1.2.0/30"} {
		pfx, parseErr := identity.ParseVirtualCIDR(cidrStr)
		if parseErr != nil {
			t.Fatalf("ParseVirtualCIDR(%q): %v", cidrStr, parseErr)
		}
		derived, dErr := identity.VirtualIPv4InPrefix(kpA.PeerID, pfx)
		if dErr != nil {
			t.Fatalf("VirtualIPv4InPrefix(%q): %v", cidrStr, dErr)
		}
		if !pfx.Contains(derived) || derived == pfx.Addr() {
			t.Fatalf("derived %s invalid for %s", derived, pfx)
		}
	}
	for _, bad := range []string{"", "not-a-cidr", "10.88.0.0/31", "10.88.0.1/32", "0.0.0.0/0", "fd00::/64"} {
		if _, err := identity.ParseVirtualCIDR(bad); err == nil {
			t.Fatalf("expected ParseVirtualCIDR(%q) error", bad)
		}
	}

	blPath := filepath.Join(t.TempDir(), "blacklist.json")
	bl, err := identity.LoadBlacklist(blPath)
	if err != nil {
		t.Fatalf("LoadBlacklist missing file: %v", err)
	}
	if err := bl.Add(kpB.PeerID); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !bl.Contains(kpB.PeerID) || bl.Contains(kpA.PeerID) {
		t.Fatal("unexpected blacklist membership")
	}
	if err := bl.Save(blPath); err != nil {
		t.Fatalf("Save blacklist: %v", err)
	}

	reloaded, err := identity.LoadBlacklist(blPath)
	if err != nil {
		t.Fatalf("reload blacklist: %v", err)
	}
	if !reloaded.Contains(kpB.PeerID) || len(reloaded.List()) != 1 {
		t.Fatalf("reloaded blacklist mismatch: %v", reloaded.List())
	}

	if err := os.Chmod(blPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.LoadBlacklist(blPath); !errors.Is(err, identity.ErrInsecureFilePerms) {
		t.Fatalf("expected ErrInsecureFilePerms for 0644 blacklist, got %v", err)
	}

	reloaded.Remove(kpB.PeerID)
	if reloaded.Contains(kpB.PeerID) {
		t.Fatal("Remove did not delete peer from blacklist")
	}
}
