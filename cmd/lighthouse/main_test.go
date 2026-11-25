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
	if err != nil || !strings.Contains(string(verOut), "lighthouse "+Version) {
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
		"--tcp-only",
		"[env: LIGHTHOUSE_TCP_ONLY]",
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

	// Verify peer --tcp-only rejects ?transport=udp with exit code 2.
	peerTCPUDPCmd := exec.Command(binPath, "peer", "--tcp-only", "--key", keyPath, "--policy", polPath, "--stun", "stuns:127.0.0.1:5349?transport=udp")
	peerTCPUDPOut, peerTCPUDPErr := peerTCPUDPCmd.CombinedOutput()
	if peerTCPUDPErr == nil || peerTCPUDPCmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for peer --tcp-only with ?transport=udp, got err=%v code=%d out=%s", peerTCPUDPErr, peerTCPUDPCmd.ProcessState.ExitCode(), string(peerTCPUDPOut))
	}
	if !strings.Contains(string(peerTCPUDPOut), "TCP-only") {
		t.Fatalf("expected TCP-only error message, got:\n%s", string(peerTCPUDPOut))
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

func TestVersionAlignmentAndRuntimeEnvDefaults(t *testing.T) {
	t.Parallel()

	// Verify cmd/lighthouse/version.go is the single source of truth (no duplicate root VERSION file).
	if _, err := os.Stat(filepath.Join("..", "..", "VERSION")); !os.IsNotExist(err) {
		t.Fatalf("duplicate root VERSION file must not exist (use cmd/lighthouse/version.go only), stat err=%v", err)
	}
	readmeBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	if strings.Contains(string(readmeBytes), Version) {
		t.Fatalf("README.md must not hardcode specific version %q", Version)
	}

	// Verify build definitions never duplicate Version or bake LIGHTHOUSE_* variables at build time.
	for _, rel := range []string{"Dockerfile", "Makefile", "docker-compose.yml", filepath.Join(".github", "workflows", "build.yml")} {
		data, readErr := os.ReadFile(filepath.Join("..", "..", rel))
		if readErr != nil {
			t.Fatalf("read %s: %v", rel, readErr)
		}
		text := string(data)
		if strings.Contains(text, "LIGHTHOUSE_") {
			t.Fatalf("%s must not reference LIGHTHOUSE_* variables at build time", rel)
		}
		if strings.Contains(text, "ARG VERSION") || strings.Contains(text, "appVersion") || strings.Contains(text, Version) {
			t.Fatalf("%s must not hardcode or duplicate version %q (single source is cmd/lighthouse/version.go)", rel, Version)
		}
	}

	// Build a single binary directly from source (Version comes solely from version.go).
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "lighthouse-ver")
	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		t.Fatalf("build binary failed: %v\n%s", err, string(out))
	}

	verOut, err := exec.Command(binPath, "--version").CombinedOutput()
	wantVer := "lighthouse " + Version
	if err != nil || strings.TrimSpace(string(verOut)) != wantVer {
		t.Fatalf("--version = %q (err=%v); want %q", strings.TrimSpace(string(verOut)), err, wantVer)
	}

	// Verify runtime .env file sets LIGHTHOUSE_* defaults when process env is unset.
	dotEnvDir := t.TempDir()
	dotEnvContent := strings.Join([]string{
		"# Runtime defaults",
		"LIGHTHOUSE_STUN_DOMAIN=stun.dotenv.example",
		"LIGHTHOUSE_STUN_PORT=5350",
		"LIGHTHOUSE_HUB_ORIGIN=wss://hub.dotenv.example",
		"NON_LIGHTHOUSE_VAR=ignored",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dotEnvDir, ".env"), []byte(dotEnvContent), 0o600); err != nil {
		t.Fatal(err)
	}

	dotEnvCmd := exec.Command(binPath, "peer", "--help")
	dotEnvCmd.Dir = dotEnvDir
	dotEnvCmd.Env = stripLighthouseEnv(os.Environ())
	dotEnvHelp, err := dotEnvCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dotenv peer --help failed: %v\n%s", err, string(dotEnvHelp))
	}
	for _, want := range []string{
		"[default: stuns:stun.dotenv.example:5350]",
		"[default: wss://hub.dotenv.example/v1/signal]",
		"--tcp-only",
		"[env: LIGHTHOUSE_TCP_ONLY]",
		"--tcp-listen-addr <ADDR>",
		"--insecure",
		"--turn <URI>",
	} {
		if !strings.Contains(string(dotEnvHelp), want) {
			t.Fatalf("dotenv peer --help missing %q:\n%s", want, string(dotEnvHelp))
		}
	}

	// Verify explicit runtime process ENV overrides .env values without rebuilding.
	envCmd := exec.Command(binPath, "peer", "--help")
	envCmd.Dir = dotEnvDir
	envCmd.Env = append(stripLighthouseEnv(os.Environ()),
		"LIGHTHOUSE_STUN_DOMAIN=stun.env.example",
		"LIGHTHOUSE_STUN_PORT=5351",
		"LIGHTHOUSE_HUB_ORIGIN=wss://hub.env.example",
	)
	envHelp, err := envCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("env peer --help failed: %v\n%s", err, string(envHelp))
	}
	for _, want := range []string{
		"[default: stuns:stun.env.example:5351]",
		"[default: wss://hub.env.example/v1/signal]",
	} {
		if !strings.Contains(string(envHelp), want) {
			t.Fatalf("runtime env override missing %q:\n%s", want, string(envHelp))
		}
	}
}

func stripLighthouseEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "LIGHTHOUSE_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
