# Identity and membership management

Identity and membership management lets operators generate persistent multi-algorithm keys with `0600` permissions, inspect peer IDs, sign offline authority memberships across algorithms, and receive strict exit-code-2 feedback on malformed flags.

## Sub-features

- `id-keygen-algos` generates `ed25519`, `ed448`, `nistp-256`, `nistp-384`, `nistp-521`, and `rsa` keys with `0600` mode.
- `id-peer-print` creates/reloads a key via `peer -gik` clustered short flags and prints matching JSON identity fields.
- `id-cross-algo-membership` issues a signed `MembershipRecord` using one key algorithm for a peer of another algorithm.
- `id-flag-errors` rejects single-dash full-word flags (`-help`, `-algo`) with exit code `2` and double-dash guidance.

## How to get to it (user POV)

- Run `lighthouse admin keygen --algo <ALGO> [--bits <BITS>] --out <PATH>`.
- Run `lighthouse peer -gik <PATH>` or `lighthouse peer --key <PATH> --print-id`.
- Run `lighthouse admin issue-membership --authority <PATH> --peer-pub <PUB> --allow <IDS> --out <PATH>`.

## Driving it with control-lighthouse

Preconditions:

- An isolated run is launched and `"$CTRL" doctor --run-dir "$RUN_DIR"` reports `"healthy": true`.

- **Generate Ed448 authority key.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "identity/keygen-ed448.txt" -- admin keygen --algo ed448 --out "$RUN_DIR/keys/auth-ed448.key"`. Exit code `0`, stdout JSON contains `"algorithm": "ed448"`, `"peer_id"`, and `"public_key"` prefixed with `ed448:`, and `stat -c '%a' "$RUN_DIR/keys/auth-ed448.key"` is `600`.
- **Generate RSA peer key.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "identity/keygen-rsa.txt" -- admin keygen --algo rsa --bits 2048 --out "$RUN_DIR/keys/peer-rsa.key"`. Exit code `0`, stdout JSON contains `"algorithm": "rsa"` and `"bits": 2048`, and file mode is `600`.
- **Inspect key via clustered short flags.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "identity/peer-ik.txt" -- peer -ik "$RUN_DIR/keys/peer-rsa.key"`. Exit code `0` and stdout `"peer_id"` matches the keygen output.
- **Create key via `peer -gik`.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "identity/peer-gik.txt" -- peer -gik "$RUN_DIR/keys/peer-short.key"`. Exit code `0`, JSON contains `"algorithm": "ed25519"`, and `"$RUN_DIR/keys/peer-short.key"` exists with mode `600`.
- **Issue cross-algorithm membership.** Extract `RSA_PUB="$(jq -r '.public_key' <(sed -n '/--- stdout ---/,/--- stderr ---/p' "$EVIDENCE_DIR/identity/keygen-rsa.txt" | sed '1d;$d'))"` and run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "identity/membership-ed448-rsa.txt" -- admin issue-membership -a "$RUN_DIR/keys/auth-ed448.key" --peer-pub "$RSA_PUB" --allow '*' --out "$RUN_DIR/memberships/peer-rsa.json"`. Exit code `0`, stdout and file contain valid JSON with non-empty `"sig"`.
- **Verify single-dash long-flag rejection.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "identity/bad-flag.txt" -- admin keygen -algo ed25519 --out "$RUN_DIR/keys/nope.key" || true`. Captured `exit_code: 2`, stderr advises using two dashes (`--`), and `nope.key` is not created.
- **Proof.** Run `"$CTRL" capture --run-dir "$RUN_DIR" --feature "identity" --note "multi-algo keygen, -gik, cross-algo membership, flag error"`.

## Gotchas

- `lighthouse` rejects loading any key file with permissions looser than `0600`.
- `--bits` is valid only with `--algo rsa` (range `2048..8192`, default `3072`).
- Single-dash flags only accept single-character short options (`-a`, `-o`, `-gik`); `-help` and `-algo` intentionally fail with exit code `2`.
