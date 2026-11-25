# Opt-in TCP-only mode

Opt-in TCP-only mode (`--tcp-only` / `LIGHTHOUSE_TCP_ONLY=true`) disables every UDP socket across both hub and peers, serving STUNS/TURNS over TLS 1.3 / TCP and establishing end-to-end DTLS 1.3 (`FEFC`) WebRTC DataChannels over ICE-TCP.

## Sub-features

- `tcp-hub-zero-udp` binds zero UDP sockets on `lighthouse hub --tcp-only` and serves TLS 1.3 / TCP STUNS on `--stuns-addr`.
- `tcp-peer-udp-reject` rejects explicit `?transport=udp` URIs on `lighthouse peer --tcp-only` with exit code `2`.
- `tcp-peer-zero-udp-connect` connects two `--tcp-only` peers over ICE-TCP with DTLS 1.3 (`FEFC`) and zero UDP sockets owned by hub or peers.
- `tcp-bidirectional-data` transfers bidirectional `data/v1` messages over the ICE-TCP DTLS 1.3 session.

## How to get to it (user POV)

- Start hub: `lighthouse hub --tcp-only --stuns-addr :5349 --policy policy.json --tls-cert tls.crt --tls-key tls.key`
- Start peers: `lighthouse peer --tcp-only [--tcp-listen-addr :0] --key peer.key --membership mem.json --policy policy.json --hub wss://... --stun stuns:...`
- Or enable via runtime environment variable `LIGHTHOUSE_TCP_ONLY=true`.

## Driving it with control-lighthouse

Preconditions:

- TCP-only run is launched with `"$CTRL" launch --run-id tcp-demo --tcp-only`.
- `"$CTRL" doctor --run-dir "$RUN_DIR"` reports `"healthy": true`, `"tcp_only": true`, and `"hub_udp_sockets": 0`.
- Host has at least one non-loopback `UP` IPv4 interface (checked with `ip -4 addr show`).

- **Confirm `?transport=udp` rejected on CLI.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "tcp-only/reject-udp-uri.txt" -- peer --tcp-only --key "$RUN_DIR/keys/peer-a.key" --policy "$RUN_DIR/policy.json" --stun "stuns:127.0.0.1:5349?transport=udp" || true`. Captured `exit_code: 2` and stderr states `TCP-only`.
- **Start TCP-only responder `peer-b`.** Run `"$CTRL" peer-start --run-dir "$RUN_DIR" --name peer-b --tcp-only`. Exits `0` after `"msg":"registered with lighthouse"`.
- **Dial TCP-only initiator `peer-a`.** Extract `PEER_B_ID="$(jq -r '.peer_b.id' "$RUN_DIR/state.json")"` and run `"$CTRL" peer-start --run-dir "$RUN_DIR" --name peer-a --tcp-only --connect "$PEER_B_ID"`. Exits `0` after `"msg":"session established"`.
- **Verify zero UDP sockets across hub and both peers.** Collect `HUB_PID`, `PA_PID`, `PB_PID` from `$RUN_DIR/pids/{hub,peer-a,peer-b}.pid` and run `ss -H -lnup | grep -E "pid=(${HUB_PID}|${PA_PID}|${PB_PID})," || true`. Output MUST be empty.
- **Send bidirectional messages over ICE-TCP.** Run `"$CTRL" peer-send --run-dir "$RUN_DIR" --name peer-a --message "tcp-only-a-to-b"`, `"$CTRL" peer-wait --run-dir "$RUN_DIR" --name peer-b --stdout-contains "tcp-only-a-to-b"`, `"$CTRL" peer-send --run-dir "$RUN_DIR" --name peer-b --message "tcp-only-b-to-a"`, and `"$CTRL" peer-wait --run-dir "$RUN_DIR" --name peer-a --stdout-contains "tcp-only-b-to-a"`. Both peer stderr logs show `"dtls_version":"FEFC"` and `"local_type":"host"`.
- **Proof.** Run `"$CTRL" capture --run-dir "$RUN_DIR" --feature "tcp-only" --note "zero UDP sockets, ICE-TCP DTLS 1.3 FEFC transfer"`. Confirm `$EVIDENCE_DIR/tcp-only/sockets.txt` contains only `tcp` sockets (zero `udp` lines).

## Gotchas

- Both peers must pass `--tcp-only` (or `LIGHTHOUSE_TCP_ONLY=true`): a UDP-default peer rejects TCP candidates and a TCP-only peer rejects UDP candidates.
- Do not rely on `hub.log` alone for zero-UDP proof; verify live kernel sockets with `ss -H -lnup` filtered to all run PIDs while both peers are connected.
- `LIGHTHOUSE_TCP_ONLY=true` works identically to `--tcp-only` at runtime without rebuilding the binary.
