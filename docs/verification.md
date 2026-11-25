# Verification Procedures and Invariants

## 1. Build and Static Analysis Commands

Verify static compilation (`CGO_ENABLED=0`), hub dependency isolation, and `go vet` from a fresh clone:

```bash
CGO_ENABLED=0 go build ./...
go vet ./...
go list -deps ./cmd/lighthouse | grep -E 'github\.com/pion/(webrtc|turn)' && exit 1 || true
```

### Verifiable Build Invariants

- `cmd/lighthouse`, `cmd/lighthouse-peer`, and `cmd/lighthouse-admin` compile into static Go binaries with `CGO_ENABLED=0`.
- `go list -deps ./cmd/lighthouse` contains neither `github.com/pion/webrtc` nor `github.com/pion/turn`, proving structurally that the hub executable cannot instantiate a `PeerConnection` or TURN relay.

## 2. Full Automated Verification Suite

Run all unit and acceptance tests with the Go race detector enabled:

```bash
go test -race -v ./...
```

## 3. Acceptance Criteria Mapping (`T01`–`T13`)

Each acceptance requirement in `test/acceptance` exercises two independently authenticated `pkg/peer.Client` instances coordinated by a single `internal/hub.Server` instance.

| ID | Test Function | Reproducible Command | Verifiable Invariants |
| --- | --- | --- | --- |
| `ARCH` | `TestArchitectureAndControlPlaneInvariants` | `go test -race -v ./test/acceptance -run TestArchitectureAndControlPlaneInvariants` | Hub binary excludes `pion/webrtc` and `pion/turn`; `GET /healthz` exposes only `{"status":"ok"}`; TLS 1.2 WSS clients fail handshake. |
| `T01` | `TestT01_SameLANDirectHostConnectivity` | `go test -race -v ./test/acceptance -run TestT01_SameLANDirectHostConnectivity` | Direct `host`–`host` UDP pair selected; `DTLSVersion == "FEFC"` (DTLS 1.3); `data/v1` and `packet/v1` deliver payloads; `> 16 KiB` messages return `ErrMessageTooLarge`; logs omit SDP, ICE passwords, keys, candidates, and payloads. |
| `T02` | `TestT02_PublicIPv4AndIPv6Connectivity` | `go test -race -v ./test/acceptance -run TestT02_PublicIPv4AndIPv6Connectivity` | Separate `IPv4` (`udp4`) and `IPv6` (`udp6`) runs establish direct connectivity and negotiate DTLS 1.3 (`FEFC`). |
| `T03` | `TestT03_CompatibleNATsSeparateNetworks` | `go test -race -v ./test/acceptance -run TestT03_CompatibleNATsSeparateNetworks` | Peers behind separate `192.168.10.0/24` and `192.168.20.0/24` cone NATs discover `srflx` mappings via Hub STUN (`203.0.113.10:3478`) and establish a non-relayed `srflx`/`prflx` pair over DTLS 1.3. |
| `T04` | `TestT04_RestrictiveNATsFailClosed` | `go test -race -v ./test/acceptance -run TestT04_RestrictiveNATsFailClosed` | Peers behind symmetric NATs with blocked direct UDP fail closed (`ErrConnectTimeout`, `StateFailed`) within the configured deadline without attempting relay fallback. |
| `T05` | `TestT05_PeerSupportsOnlyDTLS12Fails` | `go test -race -v ./test/acceptance -run TestT05_PeerSupportsOnlyDTLS12Fails` | Connection between a conformant DTLS 1.3 peer and a DTLS 1.2-only peer fails handshake; zero application bytes are delivered. |
| `T06` | `TestT06_CompromisedHubTamperingFails` | `go test -race -v ./test/acceptance -run TestT06_CompromisedHubTamperingFails` | Hub mutations to SDP `sha-256` fingerprint, `ice-pwd`, or `from` sender identity fail Ed25519 signature verification at the recipient prior to WebRTC installation. |
| `T07` | `TestT07_UnknownForbiddenAndReplayedSignalingRejected` | `go test -race -v ./test/acceptance -run TestT07_UnknownForbiddenAndReplayedSignalingRejected` | Unrecognized peers fail registration; unauthorized peer pairs fail lookup/signaling (`unauthorized_pair`); replayed signed envelopes are rejected at both hub (`replayed_signaling`) and peer (`ErrReplayedSignaling`). |
| `T08` | `TestT08_RelayAndHubEndpointCandidatesRejected` | `go test -race -v ./test/acceptance -run TestT08_RelayAndHubEndpointCandidatesRejected` | `turn:` URIs fail client construction; `typ relay` candidates in SDP or Trickle ICE and candidates targeting hub service endpoints fail validation before `SetRemoteDescription` / `AddICECandidate`. |
| `T09` | `TestT09_LargeBinaryTransferPacketCapture` | `go test -race -v ./test/acceptance -run TestT09_LargeBinaryTransferPacketCapture` | A `512 KiB` (`32 x 16 KiB`) SHA-256-verified transfer records `>= 512 KiB` of direct peer-to-peer UDP bytes, `0` signaling messages forwarded during transfer, and hub UDP datagrams bounded to `<= 128 B` STUN packets. |
| `T10` | `TestT10_StopHubDuringHealthyDirectSession` | `go test -race -v ./test/acceptance -run TestT10_StopHubDuringHealthyDirectSession` | Stopping the hub leaves an established `Connected` direct session transferring `64 KiB` of data uninterrupted while new `Connect` attempts fail closed. |
| `T11` | `TestT11_NetworkChangeAndNATExpiryICERestart` | `go test -race -v ./test/acceptance -run TestT11_NetworkChangeAndNATExpiryICERestart` | Switching a peer's network interface suspends unverified traffic, performs a signed ICE restart (`generation >= 1`), and resumes direct transfer on the new IP; unrecoverable path loss exhausts `MaxICERestarts` and transitions to `StateFailed`. |
| `T12` | `TestT12_FloodOversizedSignalingAndMalformedSTUN` | `go test -race -v ./test/acceptance -run TestT12_FloodOversizedSignalingAndMalformedSTUN` | `80 KiB` WSS frames close with `StatusMessageTooBig`; connection bursts trigger HTTP `429` rate limits; malformed, oversized, and TURN `Allocate` UDP floods increment rejection counters while subsequent legitimate peers connect. |
| `T13` | `TestT13_TamperDTLSProtectedRecordNotDelivered` | `go test -race -v ./test/acceptance -run TestT13_TamperDTLSProtectedRecordNotDelivered` | In-flight bit flips on DTLS 1.3 ciphertext records (`IsDTLS13Ciphertext`) are dropped by AEAD verification and never delivered to `Session.Packets()`, while subsequent untampered records arrive intact. |

## 4. Unit Test Suites

| Package | Command | Covered Invariants |
| --- | --- | --- |
| `internal/jcs` | `go test -race ./internal/jcs` | RFC 8785 UTF-16 key sorting, ES6 number canonicalization, duplicate-key rejection, strict field decoding |
| `pkg/identity` | `go test -race ./pkg/identity` | Ed25519 keygen, `0600` file mode enforcement, `peer_id` derivation, registration proofs, authority memberships, ACLs, revocations |
| `pkg/protocol` | `go test -race ./pkg/protocol` | 12 message schemas, `64 KiB` limit, JCS envelope signatures, clock skew and TTL bounds |
| `internal/stunserver` | `go test -race ./internal/stunserver` | Dual-stack `XOR-MAPPED-ADDRESS`, TURN `Allocate` error rejection, datagram size and per-IP rate limits |
| `internal/store` | `go test -race ./internal/store` | Pure-Go SQLite persistence of authorities, peers, memberships, ACL rules, and revocations |
| `internal/hub` | `go test -race ./internal/hub` | Unauthenticated gating, single-use challenges, concurrent-session caps, live revocation eviction |
| `pkg/peer` | `go test -race ./pkg/peer` | STUN URI validation, audio/video and `ice-lite` SDP rejection, TCP/relay/hub-IP candidate filtering |
