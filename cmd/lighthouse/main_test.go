package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnifiedBinaryClapHelpAndPOSIXFlags(t *testing.T) {
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

	// Nested verbose help via both "help hub" and "admin issue-membership --help".
	hubHelp, err := exec.Command(binPath, "help", "hub").CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse help hub failed: %v\n%s", err, string(hubHelp))
	}
	for _, want := range []string{
		"Usage: lighthouse hub [OPTIONS]",
		"--https-addr <ADDR>",
		"[env: LIGHTHOUSE_HTTPS_ADDR]",
		"[default: :8443]",
		"--stuns-addr <ADDR>",
		"[default: :5349]",
		"--insecure",
		"--turn-secret <SECRET>",
	} {
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

	// Verify double-dash long flags and concatenated single-dash short flags (-gik <path>).
	keyPath := filepath.Join(tmpDir, "peer.key")
	clusterOut, err := exec.Command(binPath, "peer", "-gik", keyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse peer -gik failed: %v\n%s", err, string(clusterOut))
	}
	var genInfo map[string]string
	if err := json.Unmarshal(clusterOut, &genInfo); err != nil {
		t.Fatalf("parse -gik output: %v", err)
	}

	for _, args := range [][]string{
		{"peer", "--key", keyPath, "--print-id"},
		{"peer", "-ik", keyPath},
		{"peer", "--key=" + keyPath, "-i"},
		{"peer", "-k" + keyPath, "--print-id=true"},
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

	// Verify single-dash full-word flags (-help, -https-addr) are rejected with exit code 2.
	for _, badArgs := range [][]string{
		{"-help"},
		{"hub", "-help"},
		{"hub", "-https-addr", ":8443"},
		{"peer", "-gen-key"},
	} {
		cmd := exec.Command(binPath, badArgs...)
		out, err := cmd.CombinedOutput()
		if err == nil || cmd.ProcessState.ExitCode() != 2 {
			t.Fatalf("expected exit code 2 for %v, got err=%v code=%d out=%s", badArgs, err, cmd.ProcessState.ExitCode(), string(out))
		}
		if !strings.Contains(string(out), "use two dashes") {
			t.Fatalf("expected double-dash tip for %v, got:\n%s", badArgs, string(out))
		}
	}

	// Verify hub rejects plaintext --stun-addr without --insecure (exit code 2).
	hubInsecureCmd := exec.Command(binPath, "hub", "--stun-addr", ":3478")
	hubInsecureOut, hubInsecureErr := hubInsecureCmd.CombinedOutput()
	if hubInsecureErr == nil || hubInsecureCmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for hub --stun-addr without --insecure, got err=%v code=%d out=%s", hubInsecureErr, hubInsecureCmd.ProcessState.ExitCode(), string(hubInsecureOut))
	}
	if !strings.Contains(string(hubInsecureOut), "--insecure") {
		t.Fatalf("expected --insecure hint in hub error:\n%s", string(hubInsecureOut))
	}

	// Verify peer rejects plaintext stun: URI without --insecure (exit code 2).
	polPath := filepath.Join(tmpDir, "policy.json")
	if err := os.WriteFile(polPath, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	peerInsecureCmd := exec.Command(binPath, "peer", "--key", keyPath, "--policy", polPath, "--stun", "stun:127.0.0.1:3478")
	peerInsecureOut, peerInsecureErr := peerInsecureCmd.CombinedOutput()
	if peerInsecureErr == nil || peerInsecureCmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for peer --stun stun:... without --insecure, got err=%v code=%d out=%s", peerInsecureErr, peerInsecureCmd.ProcessState.ExitCode(), string(peerInsecureOut))
	}
	if !strings.Contains(string(peerInsecureOut), "--insecure") {
		t.Fatalf("expected --insecure hint in peer error:\n%s", string(peerInsecureOut))
	}

	// Verify clap-like typo suggestion on unknown double-dash option.
	badCmd := exec.Command(binPath, "hub", "--polcy", "x")
	badOut, badErr := badCmd.CombinedOutput()
	if badErr == nil || badCmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for unknown flag, got err=%v code=%d", badErr, badCmd.ProcessState.ExitCode())
	}
	if !strings.Contains(string(badOut), "tip: a similar argument exists: '--policy'") {
		t.Fatalf("expected typo suggestion in stderr:\n%s", string(badOut))
	}

	// Verify multi-algorithm keygen via CLI (ed25519, ed448, nistp-256, nistp-384, nistp-521, rsa).
	algoChecks := []struct {
		algo string
		args []string
	}{
		{"ed25519", []string{"admin", "keygen", "--algo", "ed25519"}},
		{"ed448", []string{"admin", "keygen", "-a", "ed448"}},
		{"nistp-256", []string{"admin", "keygen", "--algo=nistp-256"}},
		{"nistp-384", []string{"admin", "keygen", "--algo", "nistp-384"}},
		{"nistp-521", []string{"admin", "keygen", "--algo", "nistp-521"}},
		{"rsa", []string{"admin", "keygen", "--algo", "rsa", "--bits", "2048"}},
	}

	var authKeyPath, rsaPub string
	for _, ac := range algoChecks {
		outFile := filepath.Join(tmpDir, ac.algo+".key")
		cmdArgs := append(append([]string(nil), ac.args...), "--out", outFile)
		out, err := exec.Command(binPath, cmdArgs...).CombinedOutput()
		if err != nil {
			t.Fatalf("keygen %s failed: %v\n%s", ac.algo, err, string(out))
		}
		var info map[string]any
		if err := json.Unmarshal(out, &info); err != nil {
			t.Fatalf("parse keygen %s output: %v", ac.algo, err)
		}
		if info["algorithm"] != ac.algo {
			t.Fatalf("keygen %s returned algorithm=%v", ac.algo, info["algorithm"])
		}
		if ac.algo == "ed448" {
			authKeyPath = outFile
		}
		if ac.algo == "rsa" {
			rsaPub, _ = info["public_key"].(string)
		}

		// Reload key via lighthouse peer -ik <file> and confirm matching algorithm and peer_id.
		pOut, err := exec.Command(binPath, "peer", "-ik", outFile).CombinedOutput()
		if err != nil {
			t.Fatalf("peer -ik %s failed: %v\n%s", ac.algo, err, string(pOut))
		}
		var pInfo map[string]any
		if err := json.Unmarshal(pOut, &pInfo); err != nil {
			t.Fatalf("parse peer -ik %s output: %v", ac.algo, err)
		}
		if pInfo["peer_id"] != info["peer_id"] || pInfo["algorithm"] != ac.algo {
			t.Fatalf("peer -ik %s mismatch: got %+v want %+v", ac.algo, pInfo, info)
		}
	}

	// Issue membership using Ed448 authority for RSA peer via unified CLI.
	memOut, err := exec.Command(binPath, "admin", "issue-membership", "-a", authKeyPath, "--peer-pub", rsaPub, "--allow", "*").CombinedOutput()
	if err != nil {
		t.Fatalf("issue-membership ed448->rsa failed: %v\n%s", err, string(memOut))
	}
	if !strings.Contains(string(memOut), `"sig"`) {
		t.Fatalf("unexpected membership output:\n%s", string(memOut))
	}
}

func TestVersionAlignmentAndBuildTimeSTUNDomainDefaults(t *testing.T) {
	t.Parallel()

	// Verify VERSION file, default binary --version, and README.md stay strictly synchronized.
	verBytes, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	fileVer := strings.TrimSpace(string(verBytes))
	if fileVer != appVersion {
		t.Fatalf("VERSION file (%q) != appVersion (%q)", fileVer, appVersion)
	}
	readmeBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	if !strings.Contains(string(readmeBytes), "v"+fileVer) {
		t.Fatalf("README.md does not contain current version v%s", fileVer)
	}

	// Build a binary with compile-time VERSION + LIGHTHOUSE_STUN_DOMAIN injected via -ldflags.
	tmpDir := t.TempDir()
	bakedBin := filepath.Join(tmpDir, "lighthouse-baked")
	ldflags := "-X main.appVersion=9.8.7 -X main.defaultSTUNDomain=stun.baked.example -X main.defaultSTUNPort=5350 -X main.defaultHubOrigin=wss://hub.baked.example"
	if out, err := exec.Command("go", "build", "-ldflags", ldflags, "-o", bakedBin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build with ldflags failed: %v\n%s", err, string(out))
	}

	verOut, err := exec.Command(bakedBin, "--version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(verOut)) != "lighthouse 9.8.7" {
		t.Fatalf("baked --version = %q (err=%v); want 'lighthouse 9.8.7'", strings.TrimSpace(string(verOut)), err)
	}

	peerHelp, err := exec.Command(bakedBin, "peer", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("baked peer --help failed: %v\n%s", err, string(peerHelp))
	}
	for _, want := range []string{
		"[default: stuns:stun.baked.example:5350]",
		"[default: wss://hub.baked.example/v1/signal]",
		"--insecure",
		"--turn <URI>",
	} {
		if !strings.Contains(string(peerHelp), want) {
			t.Fatalf("baked peer --help missing %q:\n%s", want, string(peerHelp))
		}
	}

	// Verify runtime ENV LIGHTHOUSE_STUN_DOMAIN overrides compile-time default with stuns:.
	envCmd := exec.Command(bakedBin, "peer", "--help")
	envCmd.Env = append(os.Environ(), "LIGHTHOUSE_STUN_DOMAIN=stun.env.example", "LIGHTHOUSE_STUN_PORT=5351")
	envHelp, err := envCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("env peer --help failed: %v\n%s", err, string(envHelp))
	}
	if !strings.Contains(string(envHelp), "[default: stuns:stun.env.example:5351]") {
		t.Fatalf("runtime env STUNS override not reflected in help:\n%s", string(envHelp))
	}
}
