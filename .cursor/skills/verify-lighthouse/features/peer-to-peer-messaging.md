# Peer-to-peer messaging

Peer-to-peer messaging connects two independently authenticated `lighthouse peer` CLI processes through the hub's TLS 1.3 WSS signaling and DTLS 1.3 / UDP STUNS, establishes an end-to-end DTLS 1.3 (`FEFC`) `data/v1` WebRTC DataChannel, and delivers bidirectional binary/text messages directly between peers.

## Sub-features

- `p2p-register` authenticates both peers to the hub via single-use challenge-response proofs.
- `p2p-connect-dtls13` negotiates direct UDP ICE candidates and verifies `dtls_version: "FEFC"` on both peers.
- `p2p-bidirectional-data` delivers messages from initiator to responder and responder to initiator on stdout.
- `p2p-log-privacy` keeps SDP, ICE passwords, keys, and application payloads out of hub and peer stderr logs.

## How to get to it (user POV)

- Start responder: `lighthouse peer --key peer-b.key --membership peer-b.json --policy policy.json --hub wss://... --ca ca.crt --stun stuns:...`
- Start initiator: `lighthouse peer --key peer-a.key --membership peer-a.json --policy policy.json --hub wss://... --ca ca.crt --stun stuns:... --connect <PEER_B_ID>`
- Type lines on stdin and read remote peer lines on stdout.

## Driving it with control-lighthouse

Preconditions:

- Default UDP run is launched (`"$CTRL" launch --run-id p2p-demo`) and `"$CTRL" doctor --run-dir "$RUN_DIR"` reports `"healthy": true`.
- Host has at least one non-loopback `UP` IPv4 interface (checked with `ip -4 addr show`), because `lighthouse peer` does not enable loopback ICE candidates.

- **Start responder `peer-b`.** Run `"$CTRL" peer-start --run-dir "$RUN_DIR" --name peer-b`. Command exits `0` and reports `"ready": true` after `"msg":"registered with lighthouse"`.
- **Dial from initiator `peer-a`.** Extract `PEER_B_ID="$(jq -r '.peer_b.id' "$RUN_DIR/state.json")"` and run `"$CTRL" peer-start --run-dir "$RUN_DIR" --name peer-a --connect "$PEER_B_ID"`. Command exits `0` after `"msg":"session established"`.
- **Confirm responder session established with DTLS 1.3.** Run `"$CTRL" peer-wait --run-dir "$RUN_DIR" --name peer-b --stderr-contains '"msg":"session established"'`. Inspect `"$RUN_DIR/logs/peer-a.err"` and `"$RUN_DIR/logs/peer-b.err"`: both log `"dtls_version":"FEFC"` and `"local_type"`/`"remote_type"` (`host` or `srflx`).
- **Send message A -> B.** Run `"$CTRL" peer-send --run-dir "$RUN_DIR" --name peer-a --message "verify-p2p-a-to-b"` and `"$CTRL" peer-wait --run-dir "$RUN_DIR" --name peer-b --stdout-contains "verify-p2p-a-to-b"`. Exact line appears in `$RUN_DIR/logs/peer-b.out`.
- **Send message B -> A.** Run `"$CTRL" peer-send --run-dir "$RUN_DIR" --name peer-b --message "verify-p2p-b-to-a"` and `"$CTRL" peer-wait --run-dir "$RUN_DIR" --name peer-a --stdout-contains "verify-p2p-b-to-a"`. Exact line appears in `$RUN_DIR/logs/peer-a.out`.
- **Check log privacy.** Verify `grep -E 'v=0|a=ice-pwd:|verify-p2p-a-to-b|verify-p2p-b-to-a' "$RUN_DIR/logs/hub.log" "$RUN_DIR/logs/peer-a.err" "$RUN_DIR/logs/peer-b.err"` returns no matches.
- **Proof.** Run `"$CTRL" capture --run-dir "$RUN_DIR" --feature "peer-to-peer" --note "live DTLS 1.3 FEFC bidirectional data/v1 transfer"`.

## Gotchas

- `lighthouse peer` exits immediately if stdin reaches EOF. Never run it with `< /dev/null` or piped `echo ... | lighthouse peer`; always use `control-lighthouse peer-start` (open FIFO).
- In an isolated container with only `lo` (`127.0.0.1`) and no non-loopback `UP` interface, `lighthouse peer` gathers zero host candidates and fails ICE negotiation. Report that unmet network precondition rather than weakening the test.
- Empty lines on stdin are ignored by `lighthouse peer`; send non-empty payload strings.
