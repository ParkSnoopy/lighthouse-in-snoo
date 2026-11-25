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
)

func newHubCommand() *cli.Command {
	var (
		httpsAddr        string
		stunsAddr        string
		stunAddr         string
		passphrase       string
		tcpOnly          bool
		insecure         bool
		noRelay          bool
		turnTLSAddr      string
		turnSecret       string
		turnRealm        string
		turnPublicIPStr  string
		turnAdvHost      string
		turnRelayMinPort int
		turnRelayMaxPort int
		hubOrigin        string
		tlsCert          string
		tlsKey           string
		hbInterval       time.Duration
		presenceTTL      time.Duration
	)

	cmd := &cli.Command{
		Name:       "hub",
		ShortAbout: "Run the zero-config universal signaling hub and relay",
		LongAbout:  "Run a stateless Lighthouse signaling hub and universal DTLS 1.3/UDP STUNS+TURNS relay with zero ACLs or policy files. Pass --passphrase to gate hub registration with an offline shared passphrase, or --tcp-only to disable UDP.",
		Examples: []string{
			"lighthouse hub",
			"lighthouse hub --https-addr :8443 --stuns-addr :5349 --hub-origin wss://hub.example.com --tls-cert tls.crt --tls-key tls.key",
			"lighthouse hub --passphrase <SECRET> --turn-public-ip 203.0.113.10",
			"lighthouse hub --tcp-only --stuns-addr :5349",
			"lighthouse hub --insecure --stun-addr :3478",
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

			enableRelay := !noRelay && !tcpOnly
			autoTLS := tlsCert == "" && tlsKey == ""

			srv, err := hub.New(&hub.Config{
				HTTPSListenAddr:    httpsAddr,
				Passphrase:         passphrase,
				TCPOnly:            tcpOnly,
				AllowInsecure:      insecure,
				EnableSTUN:         true,
				STUNSListenAddr:    stunsAddr,
				STUNListenAddr:     stunAddr,
				EnableTURN:         enableRelay,
				TURNSTLSListenAddr: turnTLSAddr,
				TURNRealm:          turnRealm,
				TURNSecret:         turnSecret,
				TURNPublicIP:       turnPublicIP,
				TURNAdvertiseHost:  turnAdvHost,
				TURNRelayMinPort:   uint16(turnRelayMinPort),
				TURNRelayMaxPort:   uint16(turnRelayMaxPort),
				HubOrigin:          hubOrigin,
				TLSCertFile:        tlsCert,
				TLSKeyFile:         tlsKey,
				AutoTLS:            autoTLS,
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
				"relay_active", srv.TURNActive(),
				"passphrase_gated", srv.PassphraseRequired(),
				"auto_tls", autoTLS,
				"insecure", insecure,
				"hub_origin", srv.HubOrigin(),
			)

			sigCh := make(chan os.Signal, 2)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			<-sigCh

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
		ShortHelp: "Encrypted STUNS/TURNS listen address",
		LongHelp:  "Listen address for DTLS 1.3/UDP STUNS+TURNS (or TLS 1.3/TCP STUNS with --tcp-only)",
		EnvVar:    "LIGHTHOUSE_STUNS_ADDR",
		Default:   ":5349",
	})
	cmd.StringOpt(&stunAddr, cli.Option{
		Long:      "stun-addr",
		ValueName: "ADDR",
		ShortHelp: "Plaintext STUN/TURN address (requires --insecure)",
		LongHelp:  "Plaintext listen address for unencrypted stun:/turn:; rejected unless --insecure is set (default :3478)",
		EnvVar:    "LIGHTHOUSE_STUN_ADDR",
	})
	cmd.StringOpt(&passphrase, cli.Option{
		Long:      "passphrase",
		Short:     'P',
		ValueName: "SECRET",
		ShortHelp: "Optional offline hub passphrase",
		LongHelp:  "Optional offline shared passphrase required to register on this hub (verified via challenge HMAC, never sent in plaintext)",
		EnvVar:    "LIGHTHOUSE_PASSPHRASE",
	})
	cmd.BoolOpt(&tcpOnly, cli.Option{
		Long:      "tcp-only",
		ShortHelp: "Disable UDP; serve STUNS over TLS 1.3/TCP only",
		LongHelp:  "Opt in to sole-TCP mode: bind zero UDP sockets and serve STUNS over TLS 1.3/TCP",
		EnvVar:    "LIGHTHOUSE_TCP_ONLY",
	})
	cmd.BoolOpt(&insecure, cli.Option{
		Long:      "insecure",
		ShortHelp: "Enable plaintext stun:/turn: listener",
		LongHelp:  "Opt in to unencrypted STUN/TURN on --stun-addr alongside encrypted STUNS/TURNS",
		EnvVar:    "LIGHTHOUSE_INSECURE",
	})
	cmd.BoolOpt(&noRelay, cli.Option{
		Long:      "no-relay",
		ShortHelp: "Disable integrated universal TURNS relay",
		LongHelp:  "Serve STUNS Binding only without integrated TURNS relay allocations",
		EnvVar:    "LIGHTHOUSE_NO_RELAY",
	})
	cmd.StringOpt(&turnSecret, cli.Option{
		Long:      "turn-secret",
		ValueName: "SECRET",
		ShortHelp: "Optional HMAC secret for universal TURNS credentials",
		LongHelp:  "Optional shared secret for HMAC TURN REST credentials (auto-generated ephemerally when unset)",
		EnvVar:    "LIGHTHOUSE_TURN_SECRET",
	})
	cmd.StringOpt(&turnRealm, cli.Option{
		Long:      "turn-realm",
		ValueName: "REALM",
		ShortHelp: "TURN authentication realm",
		EnvVar:    "LIGHTHOUSE_TURN_REALM",
		Default:   turnserver.DefaultRealm,
	})
	cmd.StringOpt(&turnPublicIPStr, cli.Option{
		Long:      "turn-public-ip",
		ValueName: "IP",
		ShortHelp: "Public IP advertised in TURN relay allocations",
		EnvVar:    "LIGHTHOUSE_TURN_PUBLIC_IP",
	})
	cmd.StringOpt(&turnAdvHost, cli.Option{
		Long:      "turn-advertise-host",
		ValueName: "HOST",
		ShortHelp: "Host advertised to peers in universal relay URIs",
		EnvVar:    "LIGHTHOUSE_TURN_ADVERTISE_HOST",
	})
	cmd.StringOpt(&turnTLSAddr, cli.Option{
		Long:      "turn-tls-addr",
		ValueName: "ADDR",
		ShortHelp: "Optional TLS 1.3/TCP TURNS fallback address",
		EnvVar:    "LIGHTHOUSE_TURN_TLS_ADDR",
	})
	cmd.IntOpt(&turnRelayMinPort, cli.Option{
		Long:      "turn-relay-min-port",
		ValueName: "PORT",
		ShortHelp: "Minimum UDP port for TURN relay allocations",
	})
	cmd.IntOpt(&turnRelayMaxPort, cli.Option{
		Long:      "turn-relay-max-port",
		ValueName: "PORT",
		ShortHelp: "Maximum UDP port for TURN relay allocations",
	})
	cmd.StringOpt(&hubOrigin, cli.Option{
		Long:      "hub-origin",
		ValueName: "URL",
		ShortHelp: "Canonical WSS hub origin",
		EnvVar:    "LIGHTHOUSE_HUB_ORIGIN",
		Default:   resolvedDefaultHubOrigin(),
	})
	cmd.StringOpt(&tlsCert, cli.Option{
		Long:      "tls-cert",
		ValueName: "PATH",
		ShortHelp: "TLS/DTLS certificate PEM path (ephemeral self-signed if omitted)",
		EnvVar:    "LIGHTHOUSE_TLS_CERT",
	})
	cmd.StringOpt(&tlsKey, cli.Option{
		Long:      "tls-key",
		ValueName: "PATH",
		ShortHelp: "TLS/DTLS private key PEM path (ephemeral self-signed if omitted)",
		EnvVar:    "LIGHTHOUSE_TLS_KEY",
	})
	cmd.DurationOpt(&hbInterval, cli.Option{
		Long:      "presence-heartbeat",
		ValueName: "DURATION",
		ShortHelp: "Presence heartbeat interval",
		Default:   "20s",
	})
	cmd.DurationOpt(&presenceTTL, cli.Option{
		Long:      "presence-ttl",
		ValueName: "DURATION",
		ShortHelp: "Presence lease expiry",
		Default:   "60s",
	})

	return cmd
}
