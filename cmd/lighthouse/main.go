package main

import (
	"errors"
	"os"

	"lighthouse-in-snoo/internal/cli"
)

func newRootCommand() *cli.Command {
	root := &cli.Command{
		Name:       "lighthouse",
		Version:    Version,
		ShortAbout: "WebRTC Lighthouse hub, peer client, and admin CLI",
		LongAbout:  "WebRTC Lighthouse hub, peer client, and policy administration tool.",
		Examples: []string{
			"lighthouse hub --policy /etc/lighthouse/policy.json --tls-cert tls.crt --tls-key tls.key",
			"lighthouse peer --key peer.key --policy policy.json --hub wss://hub.example.com/v1/signal --stun stuns:hub.example.com:5349",
			"lighthouse admin keygen --out peer.key",
		},
	}

	root.AddSubcommand(newHubCommand())
	root.AddSubcommand(newPeerCommand())
	root.AddSubcommand(newAdminCommand())
	return root
}

func main() {
	loadDotEnvIfPresent(".env")
	root := newRootCommand()
	if err := root.Execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		os.Exit(1)
	}
}
