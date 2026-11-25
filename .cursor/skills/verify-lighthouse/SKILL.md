---
name: verify-lighthouse
description: Verify the Lighthouse CLI and hub (`lighthouse hub`, `lighthouse peer`, `lighthouse admin`) end to end by building the real binary, launching an isolated TLS 1.3 WSS + DTLS 1.3/UDP (or `--tcp-only` TLS 1.3/TCP) hub, driving live peers and admin flows, capturing proof artifacts, and tearing down cleanly. Use when proving behavior after changes to signaling, ICE/STUNS/TURNS, key algorithms, policy/revocation, or CLI flags.
---

# Verify Lighthouse

Drive the real compiled `lighthouse` binary (`cmd/lighthouse`) against an isolated local `lighthouse hub`, real `lighthouse peer` processes, and real `lighthouse admin` commands. Never use test-only hooks or shared production ports.

Primary surface: `lighthouse` CLI (`hub`, `peer`, `admin`). Secondary surfaces: Go SDK (`pkg/peer`, `pkg/identity`, `pkg/protocol`) and `linux/amd64` container image (`Dockerfile`, `docker-compose.yml`).

Feature recipes live in [`features/README.md`](./features/README.md). Read the index and matching feature file before driving.

## Launch

Every run creates two disjoint directories:
- Disposable run dir: `/tmp/lighthouse-verify-<RUN_ID>` (binary, verification TLS CA/cert scaffolding, seeded keys/memberships/policy, SQLite DB, FIFOs, PID files, live logs).
- Durable evidence dir: `/tmp/lighthouse-verify-evidence/<RUN_ID>` (survives cleanup).

Launch builds the static `linux/amd64` binary (`CGO_ENABLED=0 GOARCH=amd64 go build`), generates ephemeral TLS 1.3 CA + server cert scaffolding for `127.0.0.1`/`localhost`, seeds an authority plus `peer-a` and `peer-b` via real `lighthouse admin keygen` and `issue-membership`, allocates unused local ports, and starts `lighthouse hub` with all `LIGHTHOUSE_*` env vars stripped.

```bash
CTRL=".cursor/skills/verify-lighthouse/scripts/control-lighthouse"
STATE="$("$CTRL" launch --run-id demo)"
RUN_DIR="$(jq -r '.run_dir' <<<"$STATE")"
EVIDENCE_DIR="$(jq -r '.evidence_dir' <<<"$STATE")"
```

Mode variants (each isolated in its own `--run-id`, safe to run side by side):
- Default DTLS 1.3 / UDP STUNS: `"$CTRL" launch --run-id udp-run`
- TCP-only (zero UDP, TLS 1.3 / TCP STUNS + ICE-TCP): `"$CTRL" launch --run-id tcp-run --tcp-only`
- Opt-in insecure plaintext STUN/TURN alongside encrypted STUNS: `"$CTRL" launch --run-id insecure-run --insecure`
- Integrated DTLS 1.3 TURNS relay: `"$CTRL" launch --run-id turns-run --turn-secret verify-secret`

Readiness criteria enforced by `launch`:
1. Hub stderr JSON log contains `"msg":"lighthouse hub started"`.
2. `curl --tlsv1.3 --tls-max 1.3 --cacert "$RUN_DIR/tls/ca.crt" -fsS "https://127.0.0.1:$HTTPS_PORT/healthz"` returns exact body `{"status":"ok"}`.

Teardown: always run `"$CTRL" cleanup --run-dir "$RUN_DIR"` when finished or after any failure.

## Doctor

Run this read-only check before driving any feature and whenever anything looks off:

```bash
"$CTRL" doctor --run-dir "$RUN_DIR"
```

`doctor` returns exit code `0` and `"healthy": true` only when all of the following hold:
- Tracked Hub PID is alive and its `/proc/<pid>/cmdline` matches `$RUN_DIR/bin/lighthouse`.
- `lighthouse --version` matches `const Version` in `cmd/lighthouse/version.go`.
- `ss` confirms our Hub PID owns the expected `https_port` (TCP) and `stuns_port` (UDP in default mode; TCP with zero UDP sockets in `--tcp-only` mode).
- TLS 1.3 `GET /healthz` returns `{"status":"ok"}` and TLS 1.2 `GET /healthz` fails the handshake.
- Seeded key files (`authority.key`, `peer-a.key`, `peer-b.key`) have `0600` permissions.

If `doctor` returns non-zero, do not drive that instance; inspect `$RUN_DIR/logs/hub.log`, run `cleanup`, and relaunch.

## Drive

Always drive through `control-lighthouse` so every invocation uses the run's isolated binary, stripped `LIGHTHOUSE_*` env, and tracked PIDs:

- **One-shot CLI commands** (`admin`, `peer -gik`, negative flag checks):
  ```bash
  "$CTRL" cli --run-dir "$RUN_DIR" --capture "identity/keygen.txt" -- admin keygen --algo ed448 --out "$RUN_DIR/keys/test-ed448.key"
  ```
- **Start responder peer** (FIFO keeps stdin open so `lighthouse peer` does not exit on EOF):
  ```bash
  "$CTRL" peer-start --run-dir "$RUN_DIR" --name peer-b
  ```
- **Start initiator peer and connect**:
  ```bash
  PEER_B_ID="$(jq -r '.peer_b.id' "$RUN_DIR/state.json")"
  "$CTRL" peer-start --run-dir "$RUN_DIR" --name peer-a --connect "$PEER_B_ID"
  ```
- **Send and verify live DataChannel messages**:
  ```bash
  "$CTRL" peer-send --run-dir "$RUN_DIR" --name peer-a --message "hello-from-a"
  "$CTRL" peer-wait --run-dir "$RUN_DIR" --name peer-b --stdout-contains "hello-from-a"
  ```
- **Live hub policy/revocation reload (`SIGHUP`)**:
  ```bash
  "$CTRL" hub-reload --run-dir "$RUN_DIR"
  ```
- **Stop one peer**:
  ```bash
  "$CTRL" peer-stop --run-dir "$RUN_DIR" --name peer-a
  ```

Follow the exact recipes in [`features/`](./features/README.md) for preconditions, commands, and gotchas.

## Evidence

Proof artifacts are written to `/tmp/lighthouse-verify-evidence/<RUN_ID>/<feature>/` (outside `$RUN_DIR`) via:

```bash
"$CTRL" capture --run-dir "$RUN_DIR" --feature "<feature-id>" --note "<summary>"
```

Proof standards:
- Exercise the real `lighthouse` CLI binary and live network sockets, never internal Go setters or test-only hooks.
- Capture both the action and the resulting state: CLI transcripts (`command`, `exit_code`, `stdout`, `stderr`), hub JSON logs (`hub.log`), peer stdout/stderr (`peer-*.out`, `peer-*.err`), `state.json`, `policy.json`, and `sockets.txt` (`ss -H -lntup` filtered to our run PIDs).
- Verify observable side effects: `0600` key permissions, SQLite persistence after `SIGHUP`, `"dtls_version":"FEFC"` in peer stderr logs, received payloads in peer stdout files, and zero UDP sockets in `sockets.txt` for `--tcp-only`.
- Check privacy invariants on captured logs: no raw SDP (`v=0`), ICE passwords (`a=ice-pwd:`), private keys, or application payloads appear in `hub.log` or `peer-*.err`.

## Cleanup

Tear down every run (including failed runs) with:

```bash
"$CTRL" cleanup --run-dir "$RUN_DIR"
```

Cleanup rules:
- Kills ONLY the exact PIDs recorded in `$RUN_DIR/pids/` (peers, FIFO holders, hub) with `SIGTERM`, falling back to `SIGKILL` after 3s. Never kills by process name (`pkill`/`killall`).
- Deletes `$RUN_DIR` completely (including verification TLS scaffolding, keys, SQLite DB, and FIFOs).
- Never deletes `$EVIDENCE_DIR`. Confirm evidence still exists under `/tmp/lighthouse-verify-evidence/<RUN_ID>/` after cleanup.

## Helpers

| Script | Invocation | Purpose |
| --- | --- | --- |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse launch [--run-id ID] [--tcp-only] [--insecure] [--turn-secret S]` | Build binary, generate disposable TLS scaffolding, seed identities/policy, start hub, wait for readiness |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse doctor --run-dir DIR` | Read-only check of PID, version match, socket ownership, TLS 1.3 vs 1.2, and `0600` keys |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse cli --run-dir DIR [--capture REL] -- <args...>` | Run isolated `lighthouse` subcommand and capture transcript + exit code |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse peer-start --run-dir DIR --name NAME [--connect ID] [--tcp-only] [--insecure]` | Launch live FIFO-backed `lighthouse peer` and wait for registration or session establishment |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse peer-send --run-dir DIR --name NAME --message TEXT` | Send one `data/v1` line through the peer's open stdin FIFO |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse peer-wait --run-dir DIR --name NAME (--stdout-contains S \| --stderr-contains S \| --exit)` | Wait for observable peer output, log marker, or exit without fixed sleeps |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse peer-stop --run-dir DIR --name NAME` | Stop one tracked peer and its FIFO holder by PID |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse hub-reload --run-dir DIR` | Send `SIGHUP` to tracked hub PID and wait for `"policy reloaded"` |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse capture --run-dir DIR --feature ID [--note TEXT]` | Persist logs, state, policy, and socket snapshot to `$EVIDENCE_DIR/<ID>/` |
| [`scripts/control-lighthouse`](./scripts/control-lighthouse) | `control-lighthouse cleanup --run-dir DIR` | Terminate tracked PIDs and delete `$RUN_DIR` while keeping `$EVIDENCE_DIR` intact |
