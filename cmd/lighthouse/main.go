package main

import (
	"errors"
	"os"

	"lighthouse-in-snoo/internal/cli"
)

func newRootCommand() *cli.Command {
	root := &cli.Command{
		Name:       "lighthouse",
		Version:    appVersion,
		ShortAbout: "Direct P2P WebRTC Lighthouse hub, peer client, and admin CLI",
		LongAbout:  "Direct P2P WebRTC Lighthouse hub, peer client, and policy administration tool.",
		Examples: []string{
			"lighthouse hub --policy /etc/lighthouse/policy.json --tls-cert tls.crt --tls-key tls.key",
			"lighthouse peer --key peer.key --policy policy.json --hub wss://hub.example.com/v1/signal --stun stun:hub.example.com:3478",
			"lighthouse admin keygen --out peer.key",
		},
	}

	root.AddSubcommand(newHubCommand())
	root.AddSubcommand(newPeerCommand())
	root.AddSubcommand(newAdminCommand())
	return root
}

func main() {
	root := newRootCommand()
	if err := root.Execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		os.Exit(1)
	}
}
