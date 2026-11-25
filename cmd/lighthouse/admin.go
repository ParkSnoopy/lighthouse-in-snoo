package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"lighthouse-in-snoo/internal/cli"
	"lighthouse-in-snoo/internal/store"
	"lighthouse-in-snoo/pkg/identity"
)

func newAdminCommand() *cli.Command {
	admin := &cli.Command{
		Name:       "admin",
		ShortAbout: "Manage Ed25519 keys, offline memberships, and SQLite policy state",
		LongAbout:  "Offline trust authority and administrative policy utilities for key generation, membership issuance, ACL management, and peer revocation.",
	}

	admin.AddSubcommand(newKeygenCommand())
	admin.AddSubcommand(newIssueMembershipCommand())
	admin.AddSubcommand(newSQLiteACLCommand())
	admin.AddSubcommand(newSQLiteRevokeCommand())
	return admin
}

func newKeygenCommand() *cli.Command {
	var (
		outPath string
		algoStr string
		rsaBits int
	)
	cmd := &cli.Command{
		Name:       "keygen",
		ShortAbout: "Generate an asymmetric identity or authority key pair",
		LongAbout:  "Generate a new identity or authority key pair (ed25519, ed448, nistp-256, nistp-384, nistp-521, or rsa), save it with 0600 permissions, and print its algorithm, peer_id, and public_key.",
		Examples: []string{
			"lighthouse admin keygen --out authority.key",
			"lighthouse admin keygen --algo ed448 --out peer-ed448.key",
			"lighthouse admin keygen --algo nistp-384 -o peer-p384.key",
			"lighthouse admin keygen --algo rsa --bits 3072 --out peer-rsa.key",
		},
		Run: func(ctx *cli.Context) error {
			algo, err := identity.ParseAlgorithm(algoStr)
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return &cli.ExitError{Code: 2, Err: err}
			}
			kp, err := identity.GenerateKeyPairWithOptions(identity.KeyGenOptions{
				Algorithm: algo,
				RSABits:   rsaBits,
			})
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			if err := kp.Save(outPath); err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			summary := map[string]any{
				"algorithm":  string(kp.Algorithm),
				"peer_id":    kp.PeerID,
				"public_key": identity.EncodePublicKey(kp.PublicKey),
			}
			if bits := kp.PublicKey.BitLen(); bits > 0 {
				summary["bits"] = bits
			}
			raw, _ := json.MarshalIndent(summary, "", "  ")
			fmt.Fprintln(ctx.Stdout, string(raw))
			return nil
		},
	}
	cmd.StringOpt(&outPath, cli.Option{
		Long:      "out",
		Short:     'o',
		ValueName: "PATH",
		ShortHelp: "Output key file path (0600)",
		LongHelp:  "Destination file path for the generated key JSON (created with 0600 permissions)",
		Required:  true,
	})
	cmd.StringOpt(&algoStr, cli.Option{
		Long:      "algo",
		Short:     'a',
		ValueName: "ALGO",
		ShortHelp: "Key algorithm (ed25519, ed448, nistp-256, nistp-384, nistp-521, rsa)",
		LongHelp:  "Asymmetric signing algorithm: ed25519, ed448, nistp-256, nistp-384, nistp-521, or rsa",
		Default:   "ed25519",
	})
	cmd.IntOpt(&rsaBits, cli.Option{
		Long:      "bits",
		Short:     'b',
		ValueName: "BITS",
		ShortHelp: "RSA modulus bit length (2048..8192, default 3072 for rsa)",
		LongHelp:  "Modulus size in bits when --algo rsa is selected (e.g. 2048, 3072, 4096; default 3072)",
	})
	return cmd
}

func newIssueMembershipCommand() *cli.Command {
	var (
		authKeyPath string
		peerPubEnc  string
		ttl         time.Duration
		allowCSV    string
		outPath     string
	)
	cmd := &cli.Command{
		Name:       "issue-membership",
		ShortAbout: "Sign an offline-authority MembershipRecord for a peer",
		LongAbout:  "Sign an RFC 8785 JCS MembershipRecord binding a peer's Ed25519 public key, validity window, and optional allowed_peers scope using an offline authority key.",
		Examples: []string{
			"lighthouse admin issue-membership --authority authority.key --peer-pub <PUB> --allow <PEER_B_ID> --ttl 720h --out peer-a.json",
		},
		Run: func(ctx *cli.Context) error {
			authKP, err := identity.LoadKeyPair(authKeyPath)
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			peerPub, err := identity.DecodePublicKey(peerPubEnc)
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			var allowed []string
			if strings.TrimSpace(allowCSV) != "" {
				for _, part := range strings.Split(allowCSV, ",") {
					if p := strings.TrimSpace(part); p != "" {
						allowed = append(allowed, p)
					}
				}
			}
			now := time.Now().Unix()
			rec, err := identity.IssueMembership(authKP, peerPub, now, now+int64(ttl/time.Second), allowed)
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			raw, err := json.MarshalIndent(rec, "", "  ")
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			if outPath != "" {
				if err := os.WriteFile(outPath, raw, 0o644); err != nil {
					fmt.Fprintln(ctx.Stderr, err)
					return err
				}
			}
			fmt.Fprintln(ctx.Stdout, string(raw))
			return nil
		},
	}

	cmd.StringOpt(&authKeyPath, cli.Option{
		Long:      "authority",
		Short:     'a',
		ValueName: "PATH",
		ShortHelp: "Offline authority key file path",
		LongHelp:  "Path to the 0600 Ed25519 private key file of the offline trust authority",
		Required:  true,
	})
	cmd.StringOpt(&peerPubEnc, cli.Option{
		Long:      "peer-pub",
		ValueName: "BASE64URL",
		ShortHelp: "Peer base64url Ed25519 public key",
		LongHelp:  "Unpadded base64url encoding of the target peer's 32-byte raw Ed25519 public key",
		Required:  true,
	})
	cmd.DurationOpt(&ttl, cli.Option{
		Long:      "ttl",
		Short:     't',
		ValueName: "DURATION",
		ShortHelp: "Membership validity duration",
		LongHelp:  "Duration from current UTC time until the signed MembershipRecord expires",
		Default:   "720h",
	})
	cmd.StringOpt(&allowCSV, cli.Option{
		Long:      "allow",
		ValueName: "PEER_IDS",
		ShortHelp: "Comma-separated allowed peer_ids or '*'",
		LongHelp:  "Optional comma-separated list of authorized remote peer_ids (or '*') embedded in the certificate",
	})
	cmd.StringOpt(&outPath, cli.Option{
		Long:      "out",
		Short:     'o',
		ValueName: "PATH",
		ShortHelp: "Optional output JSON file path",
		LongHelp:  "Write the signed MembershipRecord JSON to this path in addition to stdout",
	})
	return cmd
}

func newSQLiteACLCommand() *cli.Command {
	var (
		dbPath string
		peerA  string
		peerB  string
		unidir bool
	)
	cmd := &cli.Command{
		Name:       "sqlite-acl",
		ShortAbout: "Add a pairwise ACL rule to the hub SQLite state database",
		LongAbout:  "Persist an explicit peer-pair ACL authorization rule into the hub's SQLite administrative state database.",
		Examples: []string{
			"lighthouse admin sqlite-acl --db /var/lib/lighthouse/state.db --peer-a <ID_A> --peer-b <ID_B>",
		},
		Run: func(ctx *cli.Context) error {
			st, err := store.Open(dbPath)
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			defer st.Close()
			if err := st.AddACLRule(context.Background(), peerA, peerB, unidir); err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			return nil
		},
	}

	cmd.StringOpt(&dbPath, cli.Option{
		Long:      "db",
		Short:     'd',
		ValueName: "PATH",
		ShortHelp: "SQLite state database path",
		Required:  true,
	})
	cmd.StringOpt(&peerA, cli.Option{
		Long:      "peer-a",
		ValueName: "PEER_ID",
		ShortHelp: "First peer_id",
		Required:  true,
	})
	cmd.StringOpt(&peerB, cli.Option{
		Long:      "peer-b",
		ValueName: "PEER_ID",
		ShortHelp: "Second peer_id (or '*')",
		Required:  true,
	})
	cmd.BoolOpt(&unidir, cli.Option{
		Long:      "unidirectional",
		Short:     'u',
		ShortHelp: "Allow only peer-a -> peer-b",
		LongHelp:  "Restrict rule to directional peer-a -> peer-b authorization instead of symmetric bidirectional access",
	})
	return cmd
}

func newSQLiteRevokeCommand() *cli.Command {
	var (
		dbPath string
		peerID string
	)
	cmd := &cli.Command{
		Name:       "sqlite-revoke",
		ShortAbout: "Revoke a peer_id in the hub SQLite state database",
		LongAbout:  "Record a peer_id as revoked in SQLite; send SIGHUP to a running lighthouse hub to apply immediately.",
		Examples: []string{
			"lighthouse admin sqlite-revoke --db /var/lib/lighthouse/state.db --peer-id <PEER_ID>",
		},
		Run: func(ctx *cli.Context) error {
			st, err := store.Open(dbPath)
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			defer st.Close()
			if err := st.RevokePeer(context.Background(), peerID); err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			return nil
		},
	}

	cmd.StringOpt(&dbPath, cli.Option{
		Long:      "db",
		Short:     'd',
		ValueName: "PATH",
		ShortHelp: "SQLite state database path",
		Required:  true,
	})
	cmd.StringOpt(&peerID, cli.Option{
		Long:      "peer-id",
		ValueName: "PEER_ID",
		ShortHelp: "Peer ID to revoke",
		Required:  true,
	})
	return cmd
}
