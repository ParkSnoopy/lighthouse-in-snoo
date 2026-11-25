package main

import (
	"errors"
	"os"

	"lighthouse-in-snoo/internal/cli"
	"lighthouse-in-snoo/pkg/version"
)

func newRootCommand() *cli.Command {
	root := &cli.Command{
		Name:       "lighthouse",
		Version:    version.Version,
		ShortAbout: "Zero-config Lighthouse universal signaling hub and relay",
		LongAbout:  "Zero-config Lighthouse universal signaling hub and STUNS/TURNS relay. Peers authenticate independently and control connections via the Fyne TUN interface app (lighthouse-ui).",
		Examples: []string{
			"lighthouse hub",
			"lighthouse hub --domain hub.example.com",
			"lighthouse hub --domain hub.example.com --cidr 10.88.0.0/16 --tls-algo ed25519",
			"lighthouse hub --tcp-only --stuns-addr :5349",
		},
	}

	root.AddSubcommand(newHubCommand())
	return root
}

func main() {
	cli.LoadDotEnvIfPresent(".env")
	root := newRootCommand()
	if err := root.Execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		os.Exit(1)
	}
}
