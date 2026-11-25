package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"lighthouse-in-snoo/internal/store"
	"lighthouse-in-snoo/pkg/identity"
)

func runAdmin(args []string) {
	if len(args) < 1 {
		adminUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "keygen":
		cmdKeygen(args[1:])
	case "issue-membership":
		cmdIssueMembership(args[1:])
	case "sqlite-acl":
		cmdSQLiteACL(args[1:])
	case "sqlite-revoke":
		cmdSQLiteRevoke(args[1:])
	default:
		adminUsage()
		os.Exit(2)
	}
}

func adminUsage() {
	fmt.Fprintln(os.Stderr, "Usage: lighthouse admin <keygen|issue-membership|sqlite-acl|sqlite-revoke> [flags]")
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outPath := fs.String("out", "", "Output key JSON path (0600)")
	_ = fs.Parse(args)
	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	kp, err := identity.GenerateKeyPair()
	if err != nil {
		fatal(err)
	}
	if err := kp.Save(*outPath); err != nil {
		fatal(err)
	}
	summary, _ := json.MarshalIndent(map[string]string{
		"peer_id":    kp.PeerID,
		"public_key": identity.EncodePublicKey(kp.PublicKey),
	}, "", "  ")
	fmt.Println(string(summary))
}

func cmdIssueMembership(args []string) {
	fs := flag.NewFlagSet("issue-membership", flag.ExitOnError)
	authKeyPath := fs.String("authority", "", "Authority key file path")
	peerPubEnc := fs.String("peer-pub", "", "Peer base64url Ed25519 public key")
	ttl := fs.Duration("ttl", 720*time.Hour, "Membership validity duration")
	allowCSV := fs.String("allow", "", "Comma-separated allowed peer_ids or '*'")
	outPath := fs.String("out", "", "Optional output file path")
	_ = fs.Parse(args)

	if *authKeyPath == "" || *peerPubEnc == "" {
		fmt.Fprintln(os.Stderr, "-authority and -peer-pub are required")
		os.Exit(2)
	}
	authKP, err := identity.LoadKeyPair(*authKeyPath)
	if err != nil {
		fatal(err)
	}
	peerPub, err := identity.DecodePublicKey(*peerPubEnc)
	if err != nil {
		fatal(err)
	}
	var allowed []string
	if strings.TrimSpace(*allowCSV) != "" {
		for _, part := range strings.Split(*allowCSV, ",") {
			if p := strings.TrimSpace(part); p != "" {
				allowed = append(allowed, p)
			}
		}
	}
	now := time.Now().Unix()
	rec, err := identity.IssueMembership(authKP, peerPub, now, now+int64((*ttl)/time.Second), allowed)
	if err != nil {
		fatal(err)
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		fatal(err)
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, raw, 0o644); err != nil {
			fatal(err)
		}
	}
	fmt.Println(string(raw))
}

func cmdSQLiteACL(args []string) {
	fs := flag.NewFlagSet("sqlite-acl", flag.ExitOnError)
	dbPath := fs.String("db", "", "SQLite state DB path")
	peerA := fs.String("peer-a", "", "First peer_id")
	peerB := fs.String("peer-b", "", "Second peer_id")
	unidir := fs.Bool("unidirectional", false, "Allow only peer-a -> peer-b")
	_ = fs.Parse(args)

	if *dbPath == "" || *peerA == "" || *peerB == "" {
		fmt.Fprintln(os.Stderr, "-db, -peer-a, and -peer-b are required")
		os.Exit(2)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fatal(err)
	}
	defer st.Close()
	if err := st.AddACLRule(context.Background(), *peerA, *peerB, *unidir); err != nil {
		fatal(err)
	}
}

func cmdSQLiteRevoke(args []string) {
	fs := flag.NewFlagSet("sqlite-revoke", flag.ExitOnError)
	dbPath := fs.String("db", "", "SQLite state DB path")
	peerID := fs.String("peer-id", "", "Peer ID to revoke")
	_ = fs.Parse(args)

	if *dbPath == "" || *peerID == "" {
		fmt.Fprintln(os.Stderr, "-db and -peer-id are required")
		os.Exit(2)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fatal(err)
	}
	defer st.Close()
	if err := st.RevokePeer(context.Background(), *peerID); err != nil {
		fatal(err)
	}
}
