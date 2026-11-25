package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lighthouse-in-snoo/internal/cli"
	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/pkg/identity"
)

func newHubCommand() *cli.Command {
	var (
		httpsAddr   string
		stunAddr    string
		hubOrigin   string
		tlsCert     string
		tlsKey      string
		policyPath  string
		sqlitePath  string
		hbInterval  time.Duration
		presenceTTL time.Duration
	)

	cmd := &cli.Command{
		Name:       "hub",
		ShortAbout: "Run the HTTPS/WSS signaling and UDP STUN control-plane server",
		LongAbout:  "Run the Lighthouse control-plane server exposing TLS 1.3 HTTPS/WSS signaling (/healthz, /v1/signal) and UDP-only RFC 8489 STUN Binding. Send SIGHUP to reload policy and revocations.",
		Examples: []string{
			"lighthouse hub --https-addr :8443 --stun-addr :3478 --hub-origin wss://hub.example.com",
			"lighthouse hub --policy /etc/lighthouse/policy.json --sqlite /var/lib/lighthouse/state.db",
		},
		Run: func(ctx *cli.Context) error {
			logger := slog.New(slog.NewJSONHandler(ctx.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

			policy, err := identity.LoadPolicyFile(policyPath)
			if err != nil {
				logger.Error("load policy failed", "path", policyPath, "err", err)
				return err
			}

			srv, err := hub.New(hub.Config{
				HTTPSListenAddr:   httpsAddr,
				EnableSTUN:        true,
				STUNListenAddr:    stunAddr,
				HubOrigin:         hubOrigin,
				TLSCertFile:       tlsCert,
				TLSKeyFile:        tlsKey,
				Policy:            policy,
				SQLitePath:        sqlitePath,
				PresenceHeartbeat: hbInterval,
				PresenceTTL:       presenceTTL,
				Logger:            logger,
			})
			if err != nil {
				logger.Error("hub startup failed", "err", err)
				return err
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
					newPol, loadErr := identity.LoadPolicyFile(policyPath)
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
				return err
			}
			return nil
		},
	}

	cmd.StringOpt(&httpsAddr, cli.Option{
		Long:      "https-addr",
		ValueName: "ADDR",
		ShortHelp: "HTTPS/WSS listen address",
		LongHelp:  "TCP listen address for TLS 1.3 /healthz and /v1/signal endpoints",
		EnvVar:    "LIGHTHOUSE_HTTPS_ADDR",
		Default:   ":8443",
	})
	cmd.StringOpt(&stunAddr, cli.Option{
		Long:      "stun-addr",
		ValueName: "ADDR",
		ShortHelp: "UDP STUN Binding listen address",
		LongHelp:  "UDP listen address for RFC 8489 STUN Binding responses",
		EnvVar:    "LIGHTHOUSE_STUN_ADDR",
		Default:   ":3478",
	})
	cmd.StringOpt(&hubOrigin, cli.Option{
		Long:      "hub-origin",
		ValueName: "URL",
		ShortHelp: "Canonical WSS hub origin",
		LongHelp:  "Canonical wss://host[:port] origin verified in peer registration proofs",
		EnvVar:    "LIGHTHOUSE_HUB_ORIGIN",
		Default:   resolvedDefaultHubOrigin(),
	})
	cmd.StringOpt(&tlsCert, cli.Option{
		Long:      "tls-cert",
		ValueName: "PATH",
		ShortHelp: "TLS certificate PEM path",
		LongHelp:  "Path to the PEM-encoded TLS 1.3 server certificate chain",
		EnvVar:    "LIGHTHOUSE_TLS_CERT",
		Default:   "/etc/lighthouse/tls.crt",
	})
	cmd.StringOpt(&tlsKey, cli.Option{
		Long:      "tls-key",
		ValueName: "PATH",
		ShortHelp: "TLS private key PEM path",
		LongHelp:  "Path to the PEM-encoded TLS 1.3 server private key",
		EnvVar:    "LIGHTHOUSE_TLS_KEY",
		Default:   "/etc/lighthouse/tls.key",
	})
	cmd.StringOpt(&policyPath, cli.Option{
		Long:      "policy",
		Short:     'p',
		ValueName: "PATH",
		ShortHelp: "Authorization policy JSON path",
		LongHelp:  "Path to JSON policy containing trusted authorities, peers, ACLs, and revocations",
		EnvVar:    "LIGHTHOUSE_POLICY",
		Default:   "/etc/lighthouse/policy.json",
	})
	cmd.StringOpt(&sqlitePath, cli.Option{
		Long:      "sqlite",
		ValueName: "PATH",
		ShortHelp: "Optional SQLite state DB path",
		LongHelp:  "Optional persistent SQLite database merged with static policy configuration",
		EnvVar:    "LIGHTHOUSE_SQLITE",
	})
	cmd.DurationOpt(&hbInterval, cli.Option{
		Long:      "presence-heartbeat",
		ValueName: "DURATION",
		ShortHelp: "Presence heartbeat interval",
		LongHelp:  "Heartbeat cadence advertised to registered peers",
		Default:   "20s",
	})
	cmd.DurationOpt(&presenceTTL, cli.Option{
		Long:      "presence-ttl",
		ValueName: "DURATION",
		ShortHelp: "Presence lease expiry",
		LongHelp:  "Ephemeral presence lease lifetime before idle peers expire",
		Default:   "60s",
	})

	return cmd
}
