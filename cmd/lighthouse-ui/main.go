package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2/app"

	"lighthouse-in-snoo/internal/cli"
	"lighthouse-in-snoo/internal/ui"
	"lighthouse-in-snoo/pkg/identity"
	"lighthouse-in-snoo/pkg/version"
)

func main() {
	var (
		keyPath       string
		algoStr       string
		rsaBits       int
		blacklistPath string
		hubURL        string
		hubPassphrase string
		caPath        string
		stunURI       string
		ifName        string
		cidrStr       string
		tcpOnly       bool
		insecure      bool
	)

	defaultDir := defaultConfigDir()

	cmd := &cli.Command{
		Name:       "lighthouse-ui",
		Version:    version.Version,
		ShortAbout: "Fyne desktop app binding Lighthouse as an OS TUN interface",
		LongAbout:  "Bind a local OS TUN virtual network interface (lh0) to Lighthouse with explicit Allow/Deny/Blacklist incoming consent and passphrase-scoped peer broadcasting.",
		Run: func(ctx *cli.Context) error {
			algo, err := identity.ParseAlgorithm(algoStr)
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return &cli.ExitError{Code: 2, Err: err}
			}
			kp, err := identity.LoadOrGenerateKeyPairWithOptions(keyPath, identity.KeyGenOptions{
				Algorithm: algo,
				RSABits:   rsaBits,
			})
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}

			var tlsCfg *tls.Config
			if caPath != "" {
				pemBytes, readErr := os.ReadFile(caPath)
				if readErr != nil {
					fmt.Fprintln(ctx.Stderr, readErr)
					return readErr
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pemBytes) {
					return errors.New("invalid CA PEM bundle")
				}
				tlsCfg = &tls.Config{
					MinVersion: tls.VersionTLS13,
					MaxVersion: tls.VersionTLS13,
					RootCAs:    pool,
				}
			}

			virtualCIDR, err := identity.ParseVirtualCIDR(cidrStr)
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return &cli.ExitError{Code: 2, Err: err}
			}

			fyneApp := app.NewWithID("io.lighthouse.ui")
			ctrl, err := ui.NewController(fyneApp, ui.Options{
				KeyPair:          kp,
				BlacklistPath:    blacklistPath,
				HubURL:           hubURL,
				HubPassphrase:    hubPassphrase,
				STUNServerURI:    stunURI,
				TLSConfig:        tlsCfg,
				TCPOnly:          tcpOnly,
				AllowInsecureICE: insecure,
				InterfaceName:    ifName,
				VirtualCIDR:      virtualCIDR,
			})
			if err != nil {
				fmt.Fprintln(ctx.Stderr, err)
				return err
			}
			ctrl.Window().SetOnClosed(func() {
				ctrl.Disconnect()
			})
			ctrl.Window().ShowAndRun()
			return nil
		},
	}

	cmd.StringOpt(&keyPath, cli.Option{
		Long:      "key",
		Short:     'k',
		ValueName: "PATH",
		ShortHelp: "Identity key path (created if absent)",
		Default:   filepath.Join(defaultDir, "identity.key"),
	})
	cmd.StringOpt(&algoStr, cli.Option{
		Long:      "algo",
		Short:     'a',
		ValueName: "ALGO",
		ShortHelp: "Key algorithm if generating (ed25519, ed448, nistp-256, nistp-384, nistp-521, rsa)",
		Default:   "ed25519",
	})
	cmd.IntOpt(&rsaBits, cli.Option{
		Long:      "bits",
		ValueName: "BITS",
		ShortHelp: "RSA modulus bit length (2048..8192)",
	})
	cmd.StringOpt(&blacklistPath, cli.Option{
		Long:      "blacklist",
		ValueName: "PATH",
		ShortHelp: "Local peer blacklist JSON path",
		Default:   filepath.Join(defaultDir, "blacklist.json"),
	})
	cmd.StringOpt(&hubURL, cli.Option{
		Long:      "hub",
		ValueName: "URL",
		ShortHelp: "Universal Lighthouse hub WSS URL",
		EnvVar:    "LIGHTHOUSE_HUB_URL",
		Default:   "wss://localhost:8443/v1/signal",
	})
	cmd.StringOpt(&hubPassphrase, cli.Option{
		Long:      "hub-passphrase",
		ValueName: "SECRET",
		ShortHelp: "Optional offline hub passphrase",
		EnvVar:    "LIGHTHOUSE_PASSPHRASE",
	})
	cmd.StringOpt(&caPath, cli.Option{
		Long:      "ca",
		ValueName: "PATH",
		ShortHelp: "Optional PEM Root CA bundle",
		EnvVar:    "LIGHTHOUSE_CA",
	})
	cmd.StringOpt(&stunURI, cli.Option{
		Long:      "stun",
		Short:     's',
		ValueName: "URI",
		ShortHelp: "Optional explicit STUNS/TURNS URI",
		EnvVar:    "LIGHTHOUSE_STUN_URI",
	})
	cmd.StringOpt(&ifName, cli.Option{
		Long:      "ifname",
		ValueName: "NAME",
		ShortHelp: "OS TUN interface name",
		EnvVar:    "LIGHTHOUSE_IFNAME",
		Default:   "lh0",
	})
	cmd.StringOpt(&cidrStr, cli.Option{
		Long:      "cidr",
		ValueName: "CIDR",
		ShortHelp: "Virtual IPv4 subnet CIDR for TUN addressing",
		EnvVar:    "LIGHTHOUSE_CIDR",
		Default:   identity.DefaultVirtualCIDRString,
	})
	cmd.BoolOpt(&tcpOnly, cli.Option{
		Long:      "tcp-only",
		ShortHelp: "Disable UDP; use ICE-TCP and TLS 1.3/TCP only",
		EnvVar:    "LIGHTHOUSE_TCP_ONLY",
	})
	cmd.BoolOpt(&insecure, cli.Option{
		Long:      "insecure",
		ShortHelp: "Allow plaintext stun:/turn: URIs",
		EnvVar:    "LIGHTHOUSE_INSECURE",
	})

	if err := cmd.Execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		os.Exit(1)
	}
}

func defaultConfigDir() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "."
	}
	return filepath.Join(dir, "lighthouse")
}
