package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/identity"
)

func main() {
	var (
		httpsAddr   = flag.String("https-addr", envOr("LIGHTHOUSE_HTTPS_ADDR", ":8443"), "HTTPS/WSS listen address")
		stunAddr    = flag.String("stun-addr", envOr("LIGHTHOUSE_STUN_ADDR", ":3478"), "UDP STUN Binding listen address")
		hubOrigin   = flag.String("hub-origin", envOr("LIGHTHOUSE_HUB_ORIGIN", "wss://localhost:8443"), "Canonical WSS hub origin")
		tlsCert     = flag.String("tls-cert", envOr("LIGHTHOUSE_TLS_CERT", "/etc/lighthouse/tls.crt"), "TLS certificate PEM path")
		tlsKey      = flag.String("tls-key", envOr("LIGHTHOUSE_TLS_KEY", "/etc/lighthouse/tls.key"), "TLS private key PEM path")
		policyPath  = flag.String("policy", envOr("LIGHTHOUSE_POLICY", "/etc/lighthouse/policy.json"), "Authorization policy JSON path")
		sqlitePath  = flag.String("sqlite", envOr("LIGHTHOUSE_SQLITE", ""), "Optional SQLite state DB path")
		hbInterval  = flag.Duration("presence-heartbeat", 20*time.Second, "Presence heartbeat interval")
		presenceTTL = flag.Duration("presence-ttl", 60*time.Second, "Presence lease expiry")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	policy, err := identity.LoadPolicyFile(*policyPath)
	if err != nil {
		logger.Error("load policy failed", "path", *policyPath, "err", err)
		os.Exit(1)
	}

	srv, err := hub.New(hub.Config{
		HTTPSListenAddr:   *httpsAddr,
		EnableSTUN:        true,
		STUNListenAddr:    *stunAddr,
		HubOrigin:         *hubOrigin,
		TLSCertFile:       *tlsCert,
		TLSKeyFile:        *tlsKey,
		Policy:            policy,
		SQLitePath:        *sqlitePath,
		PresenceHeartbeat: *hbInterval,
		PresenceTTL:       *presenceTTL,
		Logger:            logger,
	})
	if err != nil {
		logger.Error("hub startup failed", "err", err)
		os.Exit(1)
	}

	logger.Info("lighthouse hub started",
		"https_addr", srv.HTTPSAddr().String(),
		"stun_addr", fmt.Sprint(srv.STUNAddr()),
		"hub_origin", srv.HubOrigin(),
	)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			newPol, loadErr := identity.LoadPolicyFile(*policyPath)
			if loadErr != nil {
				logger.Error("policy reload failed", "err", loadErr)
				continue
			}
			if reloadErr := srv.ReloadPolicy(newPol); reloadErr != nil {
				logger.Error("policy apply failed", "err", reloadErr)
				continue
			}
			logger.Info("policy reloaded")
			continue
		}
		break
	}

	logger.Info("shutting down lighthouse hub")
	if err := srv.Close(); err != nil {
		logger.Error("shutdown error", "err", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
