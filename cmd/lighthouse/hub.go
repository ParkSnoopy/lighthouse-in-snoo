package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lighthouse-in-snoo/internal/cli"
	"lighthouse-in-snoo/internal/hub"
	"lighthouse-in-snoo/internal/stunserver"
	"lighthouse-in-snoo/internal/turnserver"
	"lighthouse-in-snoo/pkg/identity"
)

func newHubCommand() *cli.Command {
	var (
		httpsAddr        string
		stunsAddr        string
		stunAddr         string
		tcpOnly          bool
		insecure         bool
		turnTLSAddr      string
		turnSecret       string
		turnUsersRaw     string
		turnRealm        string
		turnPublicIPStr  string
		turnRelayMinPort int
		turnRelayMaxPort int
		hubOrigin        string
		tlsCert          string
		tlsKey           string
		policyPath       string
		sqlitePath       string
		hbInterval       time.Duration
		presenceTTL      time.Duration
	)

	cmd := &cli.Command{
		Name:       "hub",
		ShortAbout: "Run the HTTPS/WSS signaling and STUNS/TURNS server",
		LongAbout:  "Run the Lighthouse server exposing TLS 1.3 HTTPS/WSS signaling (/healthz, /v1/signal) and DTLS 1.3 over UDP STUNS/TURNS (:5349/udp). Pass --tcp-only to disable UDP and serve STUNS/TURNS over TLS 1.3/TCP only. Plaintext STUN/TURN requires --insecure. Send SIGHUP to reload policy and revocations.",
		Examples: []string{
			"lighthouse hub --https-addr :8443 --stuns-addr :5349 --hub-origin wss://hub.example.com",
			"lighthouse hub --stuns-addr :5349 --turn-secret <SECRET> --turn-public-ip 203.0.113.10",
			"lighthouse hub --tcp-only --stuns-addr :5349 --policy /etc/lighthouse/policy.json",
			"lighthouse hub --insecure --stun-addr :3478 --policy /etc/lighthouse/policy.json",
		},
		Run: func(ctx *cli.Context) error {
			logger := slog.New(slog.NewJSONHandler(ctx.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

			if stunAddr != "" && !insecure {
				fmt.Fprintln(ctx.Stderr, "error: plaintext '--stun-addr' requires '--insecure' (use '--stuns-addr' for encrypted STUNS)\n\nFor more information, try '--help'.")
				return &cli.ExitError{Code: 2, Err: stunserver.ErrInsecureSTUNProhibited}
			}
			if insecure && stunAddr == "" {
				stunAddr = stunserver.DefaultInsecureSTUNAddr
			}

			turnUsers, err := turnserver.ParseStaticUsers(turnUsersRaw)
			if err != nil {
				logger.Error("invalid --turn-users", "err", err)
				return &cli.ExitError{Code: 2, Err: err}
			}

			var turnPublicIP net.IP
			if turnPublicIPStr != "" {
				turnPublicIP = net.ParseIP(turnPublicIPStr)
				if turnPublicIP == nil {
					parseErr := fmt.Errorf("invalid --turn-public-ip %q", turnPublicIPStr)
					fmt.Fprintf(ctx.Stderr, "error: %v\n", parseErr)
					return &cli.ExitError{Code: 2, Err: parseErr}
				}
			}
			if turnRelayMinPort < 0 || turnRelayMinPort > 65535 || turnRelayMaxPort < 0 || turnRelayMaxPort > 65535 ||
				(turnRelayMaxPort > 0 && turnRelayMaxPort < turnRelayMinPort) {
				portErr := errors.New("invalid --turn-relay-min-port / --turn-relay-max-port range")
				fmt.Fprintf(ctx.Stderr, "error: %v\n", portErr)
				return &cli.ExitError{Code: 2, Err: portErr}
			}

			policy, err := identity.LoadPolicyFile(policyPath)
			if err != nil {
				logger.Error("load policy failed", "path", policyPath, "err", err)
				return err
			}

			srv, err := hub.New(hub.Config{
				HTTPSListenAddr:    httpsAddr,
				TCPOnly:            tcpOnly,
				AllowInsecure:      insecure,
				EnableSTUN:         true,
				STUNSListenAddr:    stunsAddr,
				STUNListenAddr:     stunAddr,
				EnableTURN:         turnSecret != "" || len(turnUsers) > 0,
				TURNSTLSListenAddr: turnTLSAddr,
				TURNRealm:          turnRealm,
				TURNSecret:         turnSecret,
				TURNUsers:          turnUsers,
				TURNPublicIP:       turnPublicIP,
				TURNRelayMinPort:   uint16(turnRelayMinPort),
				TURNRelayMaxPort:   uint16(turnRelayMaxPort),
				HubOrigin:          hubOrigin,
				TLSCertFile:        tlsCert,
				TLSKeyFile:         tlsKey,
				Policy:             policy,
				SQLitePath:         sqlitePath,
				PresenceHeartbeat:  hbInterval,
				PresenceTTL:        presenceTTL,
				Logger:             logger,
			})
			if err != nil {
				logger.Error("hub startup failed", "err", err)
				return err
			}

			logger.Info("lighthouse hub started",
				"https_addr", srv.HTTPSAddr().String(),
				"stuns_addr", fmt.Sprint(srv.STUNSAddr()),
				"stun_udp_addr", fmt.Sprint(srv.STUNUDPAddr()),
				"stun_tcp_addr", fmt.Sprint(srv.STUNTCPAddr()),
				"tcp_only", tcpOnly,
				"turn_active", srv.TURNActive(),
				"insecure", insecure,
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
	cmd.StringOpt(&stunsAddr, cli.Option{
		Long:      "stuns-addr",
		ValueName: "ADDR",
		ShortHelp: "DTLS 1.3 / UDP STUNS/TURNS listen address",
		LongHelp:  "UDP listen address for DTLS 1.3 STUNS Binding (and TURNS when credentials are configured)",
		EnvVar:    "LIGHTHOUSE_STUNS_ADDR",
		Default:   ":5349",
	})
	cmd.StringOpt(&stunAddr, cli.Option{
		Long:      "stun-addr",
		ValueName: "ADDR",
		ShortHelp: "Plaintext UDP STUN/TURN address (requires --insecure)",
		LongHelp:  "Plaintext UDP listen address for unencrypted stun:/turn: traffic; rejected unless --insecure is set (defaults to :3478 with --insecure)",
		EnvVar:    "LIGHTHOUSE_STUN_ADDR",
	})
	cmd.BoolOpt(&tcpOnly, cli.Option{
		Long:      "tcp-only",
		ShortHelp: "Disable UDP; serve STUNS/TURNS over TLS 1.3/TCP only",
		LongHelp:  "Opt in to sole-TCP mode: bind zero UDP sockets and serve STUNS/TURNS over TLS 1.3/TCP on --stuns-addr",
		EnvVar:    "LIGHTHOUSE_TCP_ONLY",
	})
	cmd.BoolOpt(&insecure, cli.Option{
		Long:      "insecure",
		ShortHelp: "Enable plaintext stun:/turn: listener",
		LongHelp:  "Opt in to unencrypted STUN/TURN on --stun-addr alongside encrypted STUNS/TURNS",
		EnvVar:    "LIGHTHOUSE_INSECURE",
	})
	cmd.StringOpt(&turnSecret, cli.Option{
		Long:      "turn-secret",
		ValueName: "SECRET",
		ShortHelp: "Shared secret for HMAC TURN REST credentials",
		LongHelp:  "Enable authenticated DTLS 1.3 TURNS on --stuns-addr using time-limited TURN REST credentials",
		EnvVar:    "LIGHTHOUSE_TURN_SECRET",
	})
	cmd.StringOpt(&turnUsersRaw, cli.Option{
		Long:      "turn-users",
		ValueName: "LIST",
		ShortHelp: "Static TURN credentials (user=pass,...)",
		LongHelp:  "Comma-separated static user=pass entries enabling authenticated DTLS 1.3 TURNS on --stuns-addr",
		EnvVar:    "LIGHTHOUSE_TURN_USERS",
	})
	cmd.StringOpt(&turnRealm, cli.Option{
		Long:      "turn-realm",
		ValueName: "REALM",
		ShortHelp: "TURN authentication realm",
		LongHelp:  "RFC 8656 realm advertised by the integrated TURNS/TURN service",
		EnvVar:    "LIGHTHOUSE_TURN_REALM",
		Default:   turnserver.DefaultRealm,
	})
	cmd.StringOpt(&turnPublicIPStr, cli.Option{
		Long:      "turn-public-ip",
		ValueName: "IP",
		ShortHelp: "Public IP advertised in TURN relay allocations",
		LongHelp:  "Optional static public IPv4/IPv6 address returned in XOR-RELAYED-ADDRESS responses",
		EnvVar:    "LIGHTHOUSE_TURN_PUBLIC_IP",
	})
	cmd.StringOpt(&turnTLSAddr, cli.Option{
		Long:      "turn-tls-addr",
		ValueName: "ADDR",
		ShortHelp: "Optional TLS 1.3 / TCP TURNS fallback address",
		LongHelp:  "Optional TCP listen address for TLS 1.3 TURNS (?transport=tcp fallback; DTLS/UDP on --stuns-addr is primary)",
		EnvVar:    "LIGHTHOUSE_TURN_TLS_ADDR",
	})
	cmd.IntOpt(&turnRelayMinPort, cli.Option{
		Long:      "turn-relay-min-port",
		ValueName: "PORT",
		ShortHelp: "Minimum UDP port for TURN relay allocations",
		LongHelp:  "Optional lower bound of the UDP relay port range when --turn-public-ip is set",
	})
	cmd.IntOpt(&turnRelayMaxPort, cli.Option{
		Long:      "turn-relay-max-port",
		ValueName: "PORT",
		ShortHelp: "Maximum UDP port for TURN relay allocations",
		LongHelp:  "Optional upper bound of the UDP relay port range when --turn-public-ip is set",
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
		ShortHelp: "TLS/DTLS certificate PEM path",
		LongHelp:  "Path to the PEM-encoded server certificate chain for TLS 1.3 WSS and DTLS 1.3 STUNS/TURNS",
		EnvVar:    "LIGHTHOUSE_TLS_CERT",
		Default:   "/etc/lighthouse/tls.crt",
	})
	cmd.StringOpt(&tlsKey, cli.Option{
		Long:      "tls-key",
		ValueName: "PATH",
		ShortHelp: "TLS/DTLS private key PEM path",
		LongHelp:  "Path to the PEM-encoded server private key for TLS 1.3 WSS and DTLS 1.3 STUNS/TURNS",
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
