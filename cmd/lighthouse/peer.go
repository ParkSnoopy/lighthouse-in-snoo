package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lighthouse-in-snoo/internal/cli"
	"lighthouse-in-snoo/internal/jcs"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/peer"
)

func newPeerCommand() *cli.Command {
	var (
		keyPath    string
		genKey     bool
		algoStr    string
		rsaBits    int
		printID    bool
		memPath    string
		policyPath string
		hubURL     string
		hubOrigin  string
		caPath     string
		stunURI    string
		turnURI    string
		turnUser   string
		turnPass   string
		insecure   bool
		targetID   string
		packetCh   bool
	)

	cmd := &cli.Command{
		Name:       "peer",
		ShortAbout: "Run the DTLS 1.3 WebRTC peer client",
		LongAbout:  "Authenticate to a Lighthouse hub over TLS 1.3 WSS, use DTLS 1.3 / UDP stuns:/turns: by default (or opt in to plaintext stun:/turn: with --insecure), and establish DTLS 1.3 SCTP DataChannel sessions.",
		Examples: []string{
			"lighthouse peer --key peer.key --gen-key --print-id",
			"lighthouse peer --key peer-b.key --membership peer-b.json --policy policy.json --hub wss://hub.example.com/v1/signal --stun stuns:hub.example.com:5349",
			"lighthouse peer --key peer-a.key --membership peer-a.json --policy policy.json --turn turns:hub.example.com:5349 --turn-user u --turn-pass p --connect <PEER_B_ID>",
			"lighthouse peer --insecure --key peer-a.key --policy policy.json --stun stun:hub.example.com:3478 --connect <PEER_B_ID>",
		},
		Run: func(cctx *cli.Context) error {
			logger := slog.New(slog.NewJSONHandler(cctx.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

			var (
				kp  *identity.KeyPair
				err error
			)
			if genKey {
				algo, parseErr := identity.ParseAlgorithm(algoStr)
				if parseErr != nil {
					logger.Error("invalid key algorithm", "err", parseErr)
					return &cli.ExitError{Code: 2, Err: parseErr}
				}
				kp, err = identity.LoadOrGenerateKeyPairWithOptions(keyPath, identity.KeyGenOptions{
					Algorithm: algo,
					RSABits:   rsaBits,
				})
			} else {
				kp, err = identity.LoadKeyPair(keyPath)
			}
			if err != nil {
				logger.Error("identity key error", "err", err)
				return err
			}

			if printID {
				summary := map[string]any{
					"algorithm":  string(kp.Algorithm),
					"peer_id":    kp.PeerID,
					"public_key": identity.EncodePublicKey(kp.PublicKey),
				}
				if bits := kp.PublicKey.BitLen(); bits > 0 {
					summary["bits"] = bits
				}
				out, _ := json.MarshalIndent(summary, "", "  ")
				fmt.Fprintln(cctx.Stdout, string(out))
				return nil
			}

			if policyPath == "" {
				fmt.Fprintln(cctx.Stderr, "error: '--policy <PATH>' is required unless '--print-id' is set\n\nFor more information, try '--help'.")
				return &cli.ExitError{Code: 2, Err: errors.New("missing --policy")}
			}
			policy, err := identity.LoadPolicyFile(policyPath)
			if err != nil {
				logger.Error("load policy failed", "err", err)
				return err
			}

			var memRec *identity.MembershipRecord
			if memPath != "" {
				rawMem, readErr := os.ReadFile(memPath)
				if readErr != nil {
					logger.Error("read membership failed", "err", readErr)
					return readErr
				}
				var rec identity.MembershipRecord
				if uErr := jcs.UnmarshalStrict(rawMem, &rec); uErr != nil {
					logger.Error("parse membership failed", "err", uErr)
					return uErr
				}
				memRec = &rec
			}

			var tlsCfg *tls.Config
			if caPath != "" {
				pemBytes, readErr := os.ReadFile(caPath)
				if readErr != nil {
					logger.Error("read CA bundle failed", "err", readErr)
					return readErr
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pemBytes) {
					logger.Error("invalid CA PEM bundle", "path", caPath)
					return errors.New("invalid CA PEM bundle")
				}
				tlsCfg = &tls.Config{
					MinVersion: tls.VersionTLS13,
					MaxVersion: tls.VersionTLS13,
					RootCAs:    pool,
				}
			}

			sessionReady := make(chan *peer.Session, 1)
			client, err := peer.NewClient(peer.Config{
				KeyPair:             kp,
				Membership:          memRec,
				Policy:              policy,
				SignalingURL:        hubURL,
				HubOrigin:           hubOrigin,
				TLSConfig:           tlsCfg,
				STUNServerURI:       stunURI,
				TURNServerURI:       turnURI,
				TURNUsername:        turnUser,
				TURNCredential:      turnPass,
				AllowInsecureICE:    insecure,
				EnablePacketChannel: packetCh,
				Logger:              logger,
				OnSession: func(s *peer.Session) {
					select {
					case sessionReady <- s:
					default:
					}
				},
			})
			if err != nil {
				if errors.Is(err, peer.ErrInvalidICEConfig) || errors.Is(err, peer.ErrInsecureICEProhibited) {
					fmt.Fprintf(cctx.Stderr, "error: %v\n\nFor more information, try '--help'.\n", err)
					return &cli.ExitError{Code: 2, Err: err}
				}
				logger.Error("create peer client failed", "err", err)
				return err
			}
			defer client.Close()

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			regCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err = client.Register(regCtx)
			cancel()
			if err != nil {
				logger.Error("hub registration failed", "err", err)
				return err
			}
			logger.Info("registered with lighthouse", "peer_id", client.PeerID())

			var sess *peer.Session
			if targetID != "" {
				sess, err = client.Connect(ctx, targetID)
				if err != nil {
					logger.Error("peer connection failed", "target", targetID, "err", err)
					return err
				}
			} else {
				select {
				case <-ctx.Done():
					return nil
				case sess = <-sessionReady:
				}
			}
			defer sess.Close()

			diag := sess.Diagnostics()
			logger.Info("session established",
				"remote_peer_id", diag.RemotePeerID,
				"dtls_version", diag.DTLSVersion,
				"local_type", diag.LocalCandidateType,
				"remote_type", diag.RemoteCandidateType,
				"rtt_sec", diag.RTTSeconds,
			)

			go func() {
				for msg := range sess.Messages() {
					_, _ = cctx.Stdout.Write(append(msg, '\n'))
				}
			}()

			stdinDone := make(chan struct{})
			go func() {
				defer close(stdinDone)
				sc := bufio.NewScanner(os.Stdin)
				sc.Buffer(make([]byte, 1024), peer.MaxApplicationMessageBytes)
				for sc.Scan() {
					line := append([]byte(nil), sc.Bytes()...)
					if len(line) == 0 {
						continue
					}
					if sendErr := sess.Send(ctx, line); sendErr != nil {
						logger.Error("send failed", "err", sendErr)
						return
					}
				}
			}()

			select {
			case <-ctx.Done():
			case <-stdinDone:
			}
			return nil
		},
	}

	cmd.StringOpt(&keyPath, cli.Option{
		Long:      "key",
		Short:     'k',
		ValueName: "PATH",
		ShortHelp: "Identity key file path",
		LongHelp:  "Path to persistent 0600 identity key JSON file",
		Default:   "peer-key.json",
	})
	cmd.BoolOpt(&genKey, cli.Option{
		Long:      "gen-key",
		Short:     'g',
		ShortHelp: "Generate identity key if missing",
		LongHelp:  "Create a new 0600 identity key at --key when the file does not exist",
	})
	cmd.StringOpt(&algoStr, cli.Option{
		Long:      "algo",
		ValueName: "ALGO",
		ShortHelp: "Algorithm for --gen-key (ed25519, ed448, nistp-256, nistp-384, nistp-521, rsa)",
		LongHelp:  "Asymmetric signing algorithm used when --gen-key creates a new identity key",
		Default:   "ed25519",
	})
	cmd.IntOpt(&rsaBits, cli.Option{
		Long:      "bits",
		ValueName: "BITS",
		ShortHelp: "RSA modulus bit length for --gen-key --algo rsa",
		LongHelp:  "Modulus size in bits when generating an RSA identity key (2048..8192, default 3072)",
	})
	cmd.BoolOpt(&printID, cli.Option{
		Long:      "print-id",
		Short:     'i',
		ShortHelp: "Print peer_id and public_key JSON then exit",
		LongHelp:  "Output this identity's base64url peer_id and public_key as JSON without connecting",
	})
	cmd.StringOpt(&memPath, cli.Option{
		Long:      "membership",
		Short:     'm',
		ValueName: "PATH",
		ShortHelp: "Signed MembershipRecord JSON path",
		LongHelp:  "Path to an offline-authority-signed MembershipRecord JSON file",
	})
	cmd.StringOpt(&policyPath, cli.Option{
		Long:      "policy",
		Short:     'p',
		ValueName: "PATH",
		ShortHelp: "Local trust and ACL policy JSON path",
		LongHelp:  "Path to local trust policy (trusted_authorities/trusted_peers, acl_rules, revoked_peers); required unless --print-id is set",
	})
	cmd.StringOpt(&hubURL, cli.Option{
		Long:      "hub",
		ValueName: "URL",
		ShortHelp: "Hub WSS signaling endpoint",
		LongHelp:  "TLS 1.3 WebSocket signaling URL (e.g. wss://hub.example.com/v1/signal)",
		EnvVar:    "LIGHTHOUSE_HUB_URL",
		Default:   resolvedDefaultHubURL(),
	})
	cmd.StringOpt(&hubOrigin, cli.Option{
		Long:      "hub-origin",
		ValueName: "URL",
		ShortHelp: "Canonical hub origin override",
		LongHelp:  "Explicit wss://host[:port] origin signed in registration proofs (defaults to origin of --hub)",
		EnvVar:    "LIGHTHOUSE_HUB_ORIGIN",
	})
	cmd.StringOpt(&caPath, cli.Option{
		Long:      "ca",
		ValueName: "PATH",
		ShortHelp: "PEM Root CA bundle for hub TLS/DTLS",
		LongHelp:  "Optional custom PEM Root CA certificate file for validating hub TLS 1.3 WSS and DTLS 1.3 STUNS/TURNS certificates",
		EnvVar:    "LIGHTHOUSE_CA",
	})
	cmd.StringOpt(&stunURI, cli.Option{
		Long:      "stun",
		Short:     's',
		ValueName: "URI",
		ShortHelp: "STUNS/TURNS server URI (DTLS/UDP prioritized)",
		LongHelp:  "STUNS or TURNS server URI (stuns:host:5349 or turns:host:5349 over DTLS 1.3/UDP); plaintext stun:/turn: require --insecure",
		EnvVar:    "LIGHTHOUSE_STUN_URI",
		Default:   resolvedDefaultSTUNURI(),
	})
	cmd.StringOpt(&turnURI, cli.Option{
		Long:      "turn",
		ValueName: "URI",
		ShortHelp: "Optional TURNS/TURN relay URI (DTLS/UDP prioritized)",
		LongHelp:  "Optional TURNS relay URI (turns:host:5349 over DTLS 1.3/UDP; pass ?transport=tcp for TLS/TCP); plaintext turn: requires --insecure",
		EnvVar:    "LIGHTHOUSE_TURN_URI",
		Default:   resolvedDefaultTURNURI(),
	})
	cmd.StringOpt(&turnUser, cli.Option{
		Long:      "turn-user",
		ValueName: "USER",
		ShortHelp: "Username for TURNS/TURN authentication",
		LongHelp:  "Username sent during RFC 8656 TURNS/TURN long-term credential authentication",
		EnvVar:    "LIGHTHOUSE_TURN_USER",
	})
	cmd.StringOpt(&turnPass, cli.Option{
		Long:      "turn-pass",
		ValueName: "PASS",
		ShortHelp: "Password for TURNS/TURN authentication",
		LongHelp:  "Password or HMAC credential sent during RFC 8656 TURNS/TURN authentication",
		EnvVar:    "LIGHTHOUSE_TURN_PASS",
	})
	cmd.BoolOpt(&insecure, cli.Option{
		Long:      "insecure",
		ShortHelp: "Allow plaintext stun:/turn: URIs",
		LongHelp:  "Opt in to unencrypted stun: and turn: server URIs; WSS TLS 1.3 and peer DTLS 1.3 remain enforced",
		EnvVar:    "LIGHTHOUSE_INSECURE",
	})
	cmd.StringOpt(&targetID, cli.Option{
		Long:      "connect",
		Short:     'c',
		ValueName: "PEER_ID",
		ShortHelp: "Remote peer_id to dial",
		LongHelp:  "Target peer_id to look up and dial immediately; omit to listen for authorized inbound offers",
	})
	cmd.BoolOpt(&packetCh, cli.Option{
		Long:      "packet-channel",
		ShortHelp: "Enable optional unordered packet/v1 channel",
		LongHelp:  "Negotiate the optional unordered packet/v1 DataChannel (maxRetransmits = 0)",
	})

	return cmd
}
