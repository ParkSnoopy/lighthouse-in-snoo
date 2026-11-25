# Hub signaling and transport security

Hub signaling and transport security enforces TLS 1.3 exclusivity on HTTPS/WSS, binds encrypted DTLS 1.3 / UDP STUNS by default, blocks plaintext `--stun-addr` unless `--insecure` is passed, and resolves `LIGHTHOUSE_*` configuration strictly at runtime.

## Sub-features

- `hub-tls13-only` serves `GET /healthz` over TLS 1.3 and rejects TLS 1.2 clients.
- `hub-stuns-default` binds DTLS 1.3 / UDP on `--stuns-addr` without binding plaintext UDP.
- `hub-insecure-gate` rejects `--stun-addr` without `--insecure` (exit code `2`) and binds plaintext UDP only when `--insecure` is set.
- `hub-version-and-env` reports `cmd/lighthouse/version.go` via `--version` and reads `LIGHTHOUSE_*` from `.env` and process env at runtime.

## How to get to it (user POV)

- Run `lighthouse hub --policy <PATH> --tls-cert <CERT> --tls-key <KEY>` (or with `--insecure --stun-addr <ADDR>`).
- Query `GET https://<host>:<port>/healthz`.
- Run `lighthouse --version` and `lighthouse peer --help` with runtime `LIGHTHOUSE_*` env vars or a local `.env` file.

## Driving it with control-lighthouse

Preconditions:

- Default run is launched (`"$CTRL" launch --run-id hub-sec`) and `"$CTRL" doctor --run-dir "$RUN_DIR"` reports `"healthy": true`.

- **Confirm TLS 1.3 healthy and TLS 1.2 rejected.** Run `"$CTRL" doctor --run-dir "$RUN_DIR" > "$EVIDENCE_DIR/hub-security/doctor.json"` (create directory first with `mkdir -p "$EVIDENCE_DIR/hub-security"`). JSON reports `"healthy": true`, `"tls12_rejected": true`, `"tcp_only": false`, and `"hub_udp_sockets": 1`.
- **Confirm plaintext `--stun-addr` rejected without `--insecure`.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "hub-security/reject-plain-hub.txt" -- hub --stun-addr 127.0.0.1:0 --policy "$RUN_DIR/policy.json" --tls-cert "$RUN_DIR/tls/server.crt" --tls-key "$RUN_DIR/tls/server.key" || true`. Captured `exit_code: 2` and stderr names `--insecure`.
- **Confirm plaintext `stun:` URI rejected on peer without `--insecure`.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "hub-security/reject-plain-peer.txt" -- peer --key "$RUN_DIR/keys/peer-a.key" --policy "$RUN_DIR/policy.json" --stun stun:127.0.0.1:3478 || true`. Captured `exit_code: 2` and stderr mentions `--insecure`.
- **Confirm opt-in `--insecure` hub binds both encrypted and plaintext UDP.** Launch a second isolated run: `INSEC_STATE="$("$CTRL" launch --run-id hub-insec --insecure)"`, extract `INSEC_DIR="$(jq -r '.run_dir' <<<"$INSEC_STATE")"`, run `"$CTRL" doctor --run-dir "$INSEC_DIR" > "$EVIDENCE_DIR/hub-security/insecure-doctor.json"`, then `"$CTRL" cleanup --run-dir "$INSEC_DIR"`. Doctor reports `"healthy": true` and `"hub_udp_sockets": 2`.
- **Confirm runtime `.env` and env override.** Write `LIGHTHOUSE_STUN_DOMAIN=stun.verify.local` into a scratch dir under `$RUN_DIR/dotenv-test/.env`, run `(cd "$RUN_DIR/dotenv-test" && env -u LIGHTHOUSE_STUN_DOMAIN -u LIGHTHOUSE_STUN_URI "$RUN_DIR/bin/lighthouse" peer --help)` and verify `[default: stuns:stun.verify.local:5349]`; then pass `LIGHTHOUSE_STUN_DOMAIN=stun.override.local` in env and confirm override without rebuilding.
- **Proof.** Run `"$CTRL" capture --run-dir "$RUN_DIR" --feature "hub-security" --note "TLS 1.3 enforcement, insecure gate, runtime env"`.

## Gotchas

- `lighthouse` automatically loads `./.env` from its current working directory; `control-lighthouse` always runs inside `$RUN_DIR` with `LIGHTHOUSE_*` unset to prevent repo `.env` leakage.
- `curl` must pass `--cacert "$RUN_DIR/tls/ca.crt"`; using `-k` hides certificate verification regressions.
- Always clean up secondary runs (`INSEC_DIR`) immediately so ports and processes are not stranded.
