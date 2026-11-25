package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnifiedBinarySubcommands(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "lighthouse")

	buildOut, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build unified binary failed: %v\n%s", err, string(buildOut))
	}

	// Verify help output lists hub, peer, and admin subcommands.
	helpOut, err := exec.Command(binPath, "help").CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse help failed: %v\n%s", err, string(helpOut))
	}
	if !strings.Contains(string(helpOut), "lighthouse <hub|peer|admin>") {
		t.Fatalf("unexpected help output: %q", string(helpOut))
	}

	// Verify admin keygen + peer -print-id interoperate through the single binary.
	keyPath := filepath.Join(tmpDir, "peer.key")
	genOut, err := exec.Command(binPath, "admin", "keygen", "-out", keyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse admin keygen failed: %v\n%s", err, string(genOut))
	}
	var genInfo map[string]string
	if err := json.Unmarshal(genOut, &genInfo); err != nil {
		t.Fatalf("parse keygen output: %v", err)
	}

	printOut, err := exec.Command(binPath, "peer", "-key", keyPath, "-print-id").CombinedOutput()
	if err != nil {
		t.Fatalf("lighthouse peer -print-id failed: %v\n%s", err, string(printOut))
	}
	var printInfo map[string]string
	if err := json.Unmarshal(printOut, &printInfo); err != nil {
		t.Fatalf("parse print-id output: %v", err)
	}
	if genInfo["peer_id"] == "" || genInfo["peer_id"] != printInfo["peer_id"] {
		t.Fatalf("peer_id mismatch: keygen=%q print-id=%q", genInfo["peer_id"], printInfo["peer_id"])
	}
}
