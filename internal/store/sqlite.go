package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"lighthouse-in-snoo/internal/jcs"
	"lighthouse-in-snoo/pkg/identity"
)

// Store persists optional administrative membership, trust, ACL, and revocation state
// in SQLite (Section 8). Active peer presence and negotiations are never stored here.
type Store struct {
	db *sql.DB
}

// Open opens or initializes the SQLite administrative policy database at dbPath.
func Open(dbPath string) (*Store, error) {
	if dbPath != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
			return nil, fmt.Errorf("create sqlite dir: %w", err)
		}
	}
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	if dbPath == ":memory:" {
		dsn = ":memory:"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying SQLite handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS trusted_authorities (
	authority_id TEXT PRIMARY KEY,
	public_key   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS trusted_peers (
	peer_id    TEXT PRIMARY KEY,
	public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
	peer_id     TEXT PRIMARY KEY,
	record_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS acl_rules (
	peer_a         TEXT NOT NULL,
	peer_b         TEXT NOT NULL,
	unidirectional INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (peer_a, peer_b)
);
CREATE TABLE IF NOT EXISTS revoked_peers (
	peer_id    TEXT PRIMARY KEY,
	revoked_at INTEGER NOT NULL
);`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate sqlite schema: %w", err)
	}
	return nil
}

// AddTrustedAuthority stores an offline authority public key.
func (s *Store) AddTrustedAuthority(ctx context.Context, pubKeyBase64 string) error {
	pub, err := identity.DecodePublicKey(pubKeyBase64)
	if err != nil {
		return err
	}
	id, err := identity.PeerIDFromPublicKey(pub)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO trusted_authorities(authority_id, public_key) VALUES (?, ?)
		 ON CONFLICT(authority_id) DO UPDATE SET public_key = excluded.public_key`,
		id, pubKeyBase64,
	)
	return err
}

// AddTrustedPeer stores a pinned peer public key.
func (s *Store) AddTrustedPeer(ctx context.Context, peerID, pubKeyBase64 string) error {
	pub, err := identity.DecodePublicKey(pubKeyBase64)
	if err != nil {
		return err
	}
	derived, err := identity.PeerIDFromPublicKey(pub)
	if err != nil {
		return err
	}
	if peerID != "" && peerID != derived {
		return identity.ErrPeerIDMismatch
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO trusted_peers(peer_id, public_key) VALUES (?, ?)
		 ON CONFLICT(peer_id) DO UPDATE SET public_key = excluded.public_key`,
		derived, pubKeyBase64,
	)
	return err
}

// UpsertMembership stores a signed MembershipRecord.
func (s *Store) UpsertMembership(ctx context.Context, rec identity.MembershipRecord) error {
	if err := identity.ValidatePeerID(rec.PeerID); err != nil {
		return err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO memberships(peer_id, record_json) VALUES (?, ?)
		 ON CONFLICT(peer_id) DO UPDATE SET record_json = excluded.record_json`,
		rec.PeerID, string(raw),
	)
	return err
}

// AddACLRule stores an ACL authorization rule.
func (s *Store) AddACLRule(ctx context.Context, peerA, peerB string, unidirectional bool) error {
	if err := identity.ValidatePeerID(peerA); err != nil {
		return err
	}
	if peerB != "*" {
		if err := identity.ValidatePeerID(peerB); err != nil {
			return err
		}
	}
	uni := 0
	if unidirectional {
		uni = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO acl_rules(peer_a, peer_b, unidirectional) VALUES (?, ?, ?)
		 ON CONFLICT(peer_a, peer_b) DO UPDATE SET unidirectional = excluded.unidirectional`,
		peerA, peerB, uni,
	)
	return err
}

// RevokePeer marks a peer_id as revoked in persistent state.
func (s *Store) RevokePeer(ctx context.Context, peerID string) error {
	if err := identity.ValidatePeerID(peerID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO revoked_peers(peer_id, revoked_at) VALUES (?, ?)
		 ON CONFLICT(peer_id) DO NOTHING`,
		peerID, time.Now().Unix(),
	)
	return err
}

// LoadPolicy merges base PolicyConfig with persistent records stored in SQLite.
func (s *Store) LoadPolicy(ctx context.Context, base identity.PolicyConfig) (identity.PolicyConfig, error) {
	merged := identity.PolicyConfig{
		Version:            1,
		TrustedAuthorities: append([]string(nil), base.TrustedAuthorities...),
		TrustedPeers:       append([]identity.TrustedPeerEntry(nil), base.TrustedPeers...),
		Memberships:        append([]identity.MembershipRecord(nil), base.Memberships...),
		ACLRules:           append([]identity.ACLRule(nil), base.ACLRules...),
		RevokedPeers:       append([]string(nil), base.RevokedPeers...),
	}

	authRows, err := s.db.QueryContext(ctx, `SELECT public_key FROM trusted_authorities ORDER BY authority_id`)
	if err != nil {
		return identity.PolicyConfig{}, err
	}
	defer authRows.Close()
	for authRows.Next() {
		var pk string
		if err := authRows.Scan(&pk); err != nil {
			return identity.PolicyConfig{}, err
		}
		merged.TrustedAuthorities = append(merged.TrustedAuthorities, pk)
	}
	if err := authRows.Err(); err != nil {
		return identity.PolicyConfig{}, err
	}

	peerRows, err := s.db.QueryContext(ctx, `SELECT peer_id, public_key FROM trusted_peers ORDER BY peer_id`)
	if err != nil {
		return identity.PolicyConfig{}, err
	}
	defer peerRows.Close()
	for peerRows.Next() {
		var tp identity.TrustedPeerEntry
		if err := peerRows.Scan(&tp.PeerID, &tp.PublicKey); err != nil {
			return identity.PolicyConfig{}, err
		}
		merged.TrustedPeers = append(merged.TrustedPeers, tp)
	}
	if err := peerRows.Err(); err != nil {
		return identity.PolicyConfig{}, err
	}

	memRows, err := s.db.QueryContext(ctx, `SELECT record_json FROM memberships ORDER BY peer_id`)
	if err != nil {
		return identity.PolicyConfig{}, err
	}
	defer memRows.Close()
	for memRows.Next() {
		var raw string
		if err := memRows.Scan(&raw); err != nil {
			return identity.PolicyConfig{}, err
		}
		var rec identity.MembershipRecord
		if err := jcs.UnmarshalStrict([]byte(raw), &rec); err != nil {
			return identity.PolicyConfig{}, err
		}
		merged.Memberships = append(merged.Memberships, rec)
	}
	if err := memRows.Err(); err != nil {
		return identity.PolicyConfig{}, err
	}

	aclRows, err := s.db.QueryContext(ctx, `SELECT peer_a, peer_b, unidirectional FROM acl_rules ORDER BY peer_a, peer_b`)
	if err != nil {
		return identity.PolicyConfig{}, err
	}
	defer aclRows.Close()
	for aclRows.Next() {
		var r identity.ACLRule
		var uni int
		if err := aclRows.Scan(&r.PeerA, &r.PeerB, &uni); err != nil {
			return identity.PolicyConfig{}, err
		}
		r.Unidirectional = uni != 0
		merged.ACLRules = append(merged.ACLRules, r)
	}
	if err := aclRows.Err(); err != nil {
		return identity.PolicyConfig{}, err
	}

	revRows, err := s.db.QueryContext(ctx, `SELECT peer_id FROM revoked_peers ORDER BY peer_id`)
	if err != nil {
		return identity.PolicyConfig{}, err
	}
	defer revRows.Close()
	for revRows.Next() {
		var pid string
		if err := revRows.Scan(&pid); err != nil {
			return identity.PolicyConfig{}, err
		}
		merged.RevokedPeers = append(merged.RevokedPeers, pid)
	}
	if err := revRows.Err(); err != nil {
		return identity.PolicyConfig{}, err
	}

	return merged, nil
}
