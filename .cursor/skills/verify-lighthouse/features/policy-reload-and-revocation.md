# Policy reload and revocation

Policy reload and revocation lets operators update ACL rules and revoke compromised peers in the hub's SQLite state database and apply changes immediately via `SIGHUP` without restarting `lighthouse hub`.

## Sub-features

- `policy-sqlite-acl` persists a pairwise ACL rule in `--sqlite` via `lighthouse admin sqlite-acl`.
- `policy-sqlite-revoke` records a revoked `peer_id` in `--sqlite` via `lighthouse admin sqlite-revoke`.
- `policy-sighup-evict` reloads policy on `SIGHUP`, disconnects an active revoked peer session, and keeps `/healthz` serving.
- `policy-revoked-reregister-denied` rejects subsequent registration attempts by the revoked peer.

## How to get to it (user POV)

- Run `lighthouse admin sqlite-acl --db <DB> --peer-a <ID_A> --peer-b <ID_B>`.
- Run `lighthouse admin sqlite-revoke --db <DB> --peer-id <PEER_ID>`.
- Send `SIGHUP` to the running `lighthouse hub` process.

## Driving it with control-lighthouse

Preconditions:

- An isolated run is launched (`"$CTRL" launch --run-id revoke-demo`) with `--sqlite` enabled (default in `control-lighthouse launch`).
- `"$CTRL" doctor --run-dir "$RUN_DIR"` reports `"healthy": true`.

- **Register `peer-b` before revocation.** Run `"$CTRL" peer-start --run-dir "$RUN_DIR" --name peer-b`. Exits `0` after `"msg":"registered with lighthouse"`.
- **Record a new SQLite ACL rule.** Extract `PEER_A_ID` and `PEER_B_ID` from `$RUN_DIR/state.json` and run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "policy-reload/sqlite-acl.txt" -- admin sqlite-acl --db "$RUN_DIR/state.db" --peer-a "$PEER_A_ID" --peer-b "$PEER_B_ID"`. Exit code `0`.
- **Revoke `peer-b` in SQLite.** Run `"$CTRL" cli --run-dir "$RUN_DIR" --capture "policy-reload/sqlite-revoke.txt" -- admin sqlite-revoke --db "$RUN_DIR/state.db" --peer-id "$PEER_B_ID"`. Exit code `0`.
- **Reload live hub via `SIGHUP`.** Run `"$CTRL" hub-reload --run-dir "$RUN_DIR"`. Returns `{"reloaded":true}` and `hub.log` appends `"msg":"policy reloaded"` while `"$CTRL" doctor --run-dir "$RUN_DIR"` remains `"healthy": true` (same `hub_pid`).
- **Verify re-registration of revoked `peer-b` fails.** Stop `peer-b` (`"$CTRL" peer-stop --run-dir "$RUN_DIR" --name peer-b`) and attempt `"$CTRL" cli --run-dir "$RUN_DIR" --capture "policy-reload/revoked-register.txt" -- peer --key "$RUN_DIR/keys/peer-b.key" --membership "$RUN_DIR/memberships/peer-b.json" --policy "$RUN_DIR/policy.json" --hub "$(jq -r '.hub_url' "$RUN_DIR/state.json")" --ca "$RUN_DIR/tls/ca.crt" --stun "$(jq -r '.stuns_uri' "$RUN_DIR/state.json")" || true`. Captured exit code is non-zero, stderr reports `hub rejected registration: auth_failed`, and `hub.log` records `"msg":"peer registration rejected"`.
- **Proof.** Run `"$CTRL" capture --run-dir "$RUN_DIR" --feature "policy-reload" --note "SQLite revoke + SIGHUP reload + rejected re-registration"`.

## Gotchas

- `lighthouse hub` only reads SQLite mutations after receiving `SIGHUP` (or on startup); mutating `state.db` alone does not evict active sessions until `SIGHUP` runs.
- `sqlite-revoke` persists in `$RUN_DIR/state.db` for the rest of that run; use a dedicated `--run-id` so later feature checks are not affected by a revoked `peer-b`.
- Peers verify policy locally as well as on the hub; testing re-registration against the hub proves server-side SQLite + `SIGHUP` enforcement.
