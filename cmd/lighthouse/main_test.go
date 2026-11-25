package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnifiedBinaryClapHelpAndFlagForms(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "lighthouse")

	buildOut, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build unified binary failed: %v\n%s", err, string(buildOut))
	}

	// Root verbose --help and -V version output.
	helpOut, err := exec.Command(binPath, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse --help failed: %v\n%s", err, string(helpOut))
	}
	for _, want := range []string{"Usage: lighthouse <COMMAND>", "Commands:", "hub", "peer", "admin", "Options:", "-h, --help", "-V, --version", "Examples:"} {
		if !strings.Contains(string(helpOut), want) {
			t.Fatalf("root --help missing %q:\n%s", want, string(helpOut))
		}
	}

	verOut, err := exec.Command(binPath, "-V").CombinedOutput()
	if err != nil || !strings.Contains(string(verOut), "lighthouse 0.1.0") {
		t.Fatalf("lighthouse -V failed: err=%v out=%q", err, string(verOut))
	}

	// Nested verbose help via both "help hub" and "hub --help" and "admin issue-membership --help".
	hubHelp, err := exec.Command(binPath, "help", "hub").CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse help hub failed: %v\n%s", err, string(hubHelp))
	}
	for _, want := range []string{"Usage: lighthouse hub [OPTIONS]", "--https-addr <ADDR>", "[env: LIGHTHOUSE_HTTPS_ADDR]", "[default: :8443]"} {
		if !strings.Contains(string(hubHelp), want) {
			t.Fatalf("hub help missing %q:\n%s", want, string(hubHelp))
		}
	}

	issueHelp, err := exec.Command(binPath, "admin", "issue-membership", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("admin issue-membership --help failed: %v\n%s", err, string(issueHelp))
	}
	if !strings.Contains(string(issueHelp), "Usage: lighthouse admin issue-membership --authority <PATH> --peer-pub <BASE64URL> [OPTIONS]") {
		t.Fatalf("unexpected issue-membership usage:\n%s", string(issueHelp))
	}

	// Verify BOTH --long, -long, and -short flag forms interoperate across admin and peer subcommands.
	keyPath := filepath.Join(tmpDir, "peer.key")
	genOut, err := exec.Command(binPath, "admin", "keygen", "--out", keyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("admin keygen --out failed: %v\n%s", err, string(genOut))
	}
	var genInfo map[string]string
	if err := json.Unmarshal(genOut, &genInfo); err != nil {
		t.Fatalf("parse keygen output: %v", err)
	}

	for _, args := range [][]string{
		{"peer", "--key", keyPath, "--print-id"},
		{"peer", "-key", keyPath, "-print-id"},
		{"peer", "-k", keyPath, "--print-id=true"},
		{"peer", "--key=" + keyPath, "-print-id"},
	} {
		out, err := exec.Command(binPath, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("lighthouse %v failed: %v\n%s", args, err, string(out))
		}
		var info map[string]string
		if err := json.Unmarshal(out, &info); err != nil {
			t.Fatalf("parse output for %v: %v", args, err)
		}
		if info["peer_id"] != genInfo["peer_id"] {
			t.Fatalf("peer_id mismatch for %v: got %q want %q", args, info["peer_id"], genInfo["peer_id"])
		}
	}

	// Verify clap-like typo suggestion and exit code 2 on invalid option.
	badCmd := exec.Command(binPath, "hub", "--polcy", "x")
	badOut, badErr := badCmd.CombinedOutput()
	if badErr == nil || badCmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for unknown flag, got err=%v code=%d", badErr, badCmd.ProcessState.ExitCode())
	}
	if !strings.Contains(string(badOut), "tip: a similar argument exists: '--policy'") {
		t.Fatalf("expected typo suggestion in stderr:\n%s", string(badOut))
	}
}
