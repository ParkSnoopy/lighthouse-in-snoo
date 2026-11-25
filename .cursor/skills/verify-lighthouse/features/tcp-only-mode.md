# Opt-in TCP-only mode

Opt-in TCP-only mode (`--tcp-only` / `LIGHTHOUSE_TCP_ONLY=true`) disables every UDP socket across hub and peers, serving STUNS over TLS 1.3 / TCP and establishing end-to-end DTLS 1.3 (`FEFC`) WebRTC DataChannels over ICE-TCP.

## Sub-features

- `tcp-hub-zero-udp` binds zero UDP sockets on `lighthouse hub --tcp-only`, disables UDP relay (`"relay_active":false`), and serves TLS 1.3 / TCP STUNS on `--stuns-addr`.
- `tcp-peer-end-to-end` validates IPv4 and IPv6 TLS 1.3 / TCP STUNS, rejects UDP configs and candidates, and delivers `data/v1` and `packet/v1` traffic over ICE-TCP + DTLS 1.3 (`FEFC`).

## How to get to it (user POV)

- Start hub: `lighthouse hub --tcp-only --stuns-addr :5349 [--tls-cert tls.crt --tls-key tls.key]`
- Start UI app: `lighthouse-ui --tcp-only --hub wss://...` (or check **TCP Only** in the Fyne UI)
- Or enable via runtime environment variable `LIGHTHOUSE_TCP_ONLY=true`.

## Driving it with control-lighthouse

Preconditions:

- TCP-only run is launched with `"$CTRL" launch --run-id tcp-demo --tcp-only`.
- `"$CTRL" doctor --run-dir "$RUN_DIR"` reports `"healthy": true`, `"tcp_only": true`, and `"hub_udp_sockets": 0`.

- **Confirm zero UDP sockets owned by hub.** Run `mkdir -p "$EVIDENCE_DIR/tcp-only" && "$CTRL" doctor --run-dir "$RUN_DIR" > "$EVIDENCE_DIR/tcp-only/doctor.json"` and check `"hub_udp_sockets": 0` and `"tcp_only": true`. Also confirm `"tcp_only":true` and `"relay_active":false` in `$RUN_DIR/logs/hub.log`.
- **Confirm end-to-end ICE-TCP + DTLS 1.3 acceptance suite.** Run `go test -race -v ./test/acceptance -run TestTCPOnlyModeZeroUDPEndToEnd > "$EVIDENCE_DIR/tcp-only/acceptance.txt"` and verify exit code `0`.
- **Proof.** Run `"$CTRL" capture --run-dir "$RUN_DIR" --feature "tcp-only" --note "Zero UDP hub sockets + ICE-TCP DTLS 1.3 proof"`. Confirm `$EVIDENCE_DIR/tcp-only/sockets.txt` contains only `tcp` lines (zero `udp` lines).

## Gotchas

- Both hub and peers must enable `--tcp-only` (or `LIGHTHOUSE_TCP_ONLY=true`): UDP-default peers reject TCP candidates and TCP-only peers reject UDP candidates.
- Verify live kernel sockets with `ss -H -lnup` via `doctor` and `sockets.txt` rather than trusting log fields alone.
