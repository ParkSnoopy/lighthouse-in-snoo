package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"lighthouse-in-snoo/internal/store"
	"lighthouse-in-snoo/pkg/identity"
)

func TestSQLitePolicyPersistence(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open sqlite: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	authKP, _ := identity.GenerateKeyPair()
	peerA, _ := identity.GenerateKeyPair()
	peerB, _ := identity.GenerateKeyPair()

	if err := st.AddTrustedAuthority(ctx, identity.EncodePublicKey(authKP.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := st.AddTrustedPeer(ctx, peerB.PeerID, identity.EncodePublicKey(peerB.PublicKey)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	recA, err := identity.IssueMembership(authKP, peerA.PublicKey, now-10, now+3600, []string{peerB.PeerID})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMembership(ctx, *recA); err != nil {
		t.Fatal(err)
	}
	if err := st.AddACLRule(ctx, peerA.PeerID, peerB.PeerID, false); err != nil {
		t.Fatal(err)
	}

	merged, err := st.LoadPolicy(ctx, identity.PolicyConfig{Version: 1})
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	tv, err := identity.NewTrustVerifier(merged, 30*time.Second)
	if err != nil {
		t.Fatalf("NewTrustVerifier: %v", err)
	}
	if _, err := tv.VerifyPeer(peerA.PeerID, peerA.PublicKey, nil); err != nil {
		t.Fatalf("VerifyPeer A from sqlite: %v", err)
	}
	if err := tv.AuthorizePair(peerA.PeerID, peerB.PeerID, nil, nil); err != nil {
		t.Fatalf("AuthorizePair A<->B from sqlite: %v", err)
	}

	// Revoke B and reload.
	if err := st.RevokePeer(ctx, peerB.PeerID); err != nil {
		t.Fatal(err)
	}
	merged2, err := st.LoadPolicy(ctx, identity.PolicyConfig{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := tv.Reload(merged2); err != nil {
		t.Fatal(err)
	}
	if !tv.IsRevoked(peerB.PeerID) {
		t.Fatal("expected peerB to be revoked")
	}
}
