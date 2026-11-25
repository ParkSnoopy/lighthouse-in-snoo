package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lighthouse-in-snoo/internal/jcs"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/peer"
)

func main() {
	var (
		keyPath    = flag.String("key", "peer-key.json", "Ed25519 identity key file path")
		genKey     = flag.Bool("gen-key", false, "Generate identity key if missing")
		printID    = flag.Bool("print-id", false, "Print peer_id and public_key JSON then exit")
		memPath    = flag.String("membership", "", "Optional signed MembershipRecord JSON path")
		policyPath = flag.String("policy", "", "Local trust & ACL policy JSON path")
		hubURL     = flag.String("hub", "wss://localhost:8443/v1/signal", "Hub WSS signaling endpoint")
		hubOrigin  = flag.String("hub-origin", "", "Optional canonical hub origin override")
		caPath     = flag.String("ca", "", "Optional PEM Root CA bundle for Hub TLS 1.3 verification")
		stunURI    = flag.String("stun", "stun:127.0.0.1:3478", "UDP STUN URI (stun:host:port)")
		targetID   = flag.String("connect", "", "Optional remote peer_id to dial immediately")
		packetCh   = flag.Bool("packet-channel", false, "Enable optional unordered packet/v1 DataChannel")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var (
		kp  *identity.KeyPair
		err error
	)
	if *genKey {
		kp, err = identity.LoadOrGenerateKeyPair(*keyPath)
	} else {
		kp, err = identity.LoadKeyPair(*keyPath)
	}
	if err != nil {
		logger.Error("identity key error", "err", err)
		os.Exit(1)
	}

	if *printID {
		out, _ := json.MarshalIndent(map[string]string{
			"peer_id":    kp.PeerID,
			"public_key": identity.EncodePublicKey(kp.PublicKey),
		}, "", "  ")
		fmt.Println(string(out))
		return
	}

	if *policyPath == "" {
		logger.Error("local -policy file is required")
		os.Exit(1)
	}
	policy, err := identity.LoadPolicyFile(*policyPath)
	if err != nil {
		logger.Error("load policy failed", "err", err)
		os.Exit(1)
	}

	var memRec *identity.MembershipRecord
	if *memPath != "" {
		rawMem, readErr := os.ReadFile(*memPath)
		if readErr != nil {
			logger.Error("read membership failed", "err", readErr)
			os.Exit(1)
		}
		var rec identity.MembershipRecord
		if uErr := jcs.UnmarshalStrict(rawMem, &rec); uErr != nil {
			logger.Error("parse membership failed", "err", uErr)
			os.Exit(1)
		}
		memRec = &rec
	}

	var tlsCfg *tls.Config
	if *caPath != "" {
		pemBytes, readErr := os.ReadFile(*caPath)
		if readErr != nil {
			logger.Error("read CA bundle failed", "err", readErr)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			logger.Error("invalid CA PEM bundle", "path", *caPath)
			os.Exit(1)
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
		SignalingURL:        *hubURL,
		HubOrigin:           *hubOrigin,
		TLSConfig:           tlsCfg,
		STUNServerURI:       *stunURI,
		EnablePacketChannel: *packetCh,
		Logger:              logger,
		OnSession: func(s *peer.Session) {
			select {
			case sessionReady <- s:
			default:
			}
		},
	})
	if err != nil {
		logger.Error("create peer client failed", "err", err)
		os.Exit(1)
	}
	defer client.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	regCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = client.Register(regCtx)
	cancel()
	if err != nil {
		logger.Error("hub registration failed", "err", err)
		os.Exit(1)
	}
	logger.Info("registered with lighthouse", "peer_id", client.PeerID())

	var sess *peer.Session
	if *targetID != "" {
		sess, err = client.Connect(ctx, *targetID)
		if err != nil {
			logger.Error("direct peer connection failed", "target", *targetID, "err", err)
			os.Exit(1)
		}
	} else {
		select {
		case <-ctx.Done():
			return
		case sess = <-sessionReady:
		}
	}
	defer sess.Close()

	diag := sess.Diagnostics()
	logger.Info("direct session established",
		"remote_peer_id", diag.RemotePeerID,
		"dtls_version", diag.DTLSVersion,
		"local_type", diag.LocalCandidateType,
		"remote_type", diag.RemoteCandidateType,
		"rtt_sec", diag.RTTSeconds,
	)

	// Pump received messages to stdout and stdin lines to data/v1.
	go func() {
		for msg := range sess.Messages() {
			_, _ = os.Stdout.Write(append(msg, '\n'))
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
}
