# Installation and configuration

## Build the desktop app

Install Make, a C compiler, and [Fyne's Linux build dependencies](https://docs.fyne.io/started/quick/).
Use the Go version in [go.mod](../go.mod).

```bash
git clone https://github.com/ParkSnoopy/lighthouse-in-snoo
cd lighthouse-in-snoo
make build-ui
```

The executable is `bin/lighthouse-ui`.
The app needs access to `/dev/net/tun` and `CAP_NET_ADMIN` to configure the interface and its routes.

## Deploy the hub

### Docker Compose

From the repository root, start the published image with [Docker Compose](../docker-compose.yml):

```bash
IMAGE=ghcr.io/parksnoopy/lighthouse-in-snoo:latest docker compose up -d --no-build --pull always
```

To build the image from the checkout instead, run `docker compose up -d --build`.
Compose maps host TCP port `443` to hub port `8443` and exposes UDP port `5349` for address discovery and relay access.
Keep the `lighthouse_data` volume to reuse the generated certificate across restarts.

If clients need the relay across a firewall or NAT, they must also reach its allocated UDP ports.
Set `--turn-public-ip`, select a range with `--turn-relay-min-port` and `--turn-relay-max-port`, and publish and forward that range.
The `5349/udp` mapping alone does not forward those allocations.

### Run the hub binary

From the repository root on Linux, build the `linux/amd64` hub with `make build`.
Start it with `./bin/lighthouse hub`.
It listens on TCP port `8443` by default.

For a standalone hub with a fixed public domain and relay IP:

```bash
./bin/lighthouse hub \
  --domain hub.example.com:8443 \
  --tls-algo ed25519 \
  --turn-public-ip 203.0.113.10
```

Replace the example domain and IP with your own.
Include the public port in `--domain` if it is not `443`.
The domain determines the expected connection address, the advertised relay hostname and realm, and the names in a newly generated certificate.

### Trust the hub certificate

The hub generates a self-signed certificate by default.
It reuses the certificate and key in `/etc/lighthouse` when it can write to that directory.
If it cannot write to the directory, the certificate lasts only for the current run.
Changing the domain or key algorithm does not replace an existing certificate.

For remote clients, set `LIGHTHOUSE_DOMAIN` to the hostname they will use before the first start.
For `docker run`, add `-e LIGHTHOUSE_DOMAIN=hub.example.com` before the image name.
For Compose, set `LIGHTHOUSE_DOMAIN=hub.example.com` in `.env`.
Replace `hub.example.com` with your public hostname.

For the [README's Docker setup](../README.md#run-a-hub), copy only the public certificate:

```bash
docker cp lighthouse:/etc/lighthouse/tls.crt ./lighthouse-hub.crt
```

Transfer the certificate to each client over a trusted channel.
Use `localhost` for a client on the same host as the default Docker setup.
For a remote client, use the hostname or IP that the certificate covers.
Start the desktop app from the repository root with the path to the copied certificate:

```bash
./bin/lighthouse-ui --ca ./lighthouse-hub.crt
```

A client that trusts the public HTTPS certificate can connect without a separate CA file.

### Cloudtype and other HTTPS proxies

1. Deploy `ghcr.io/parksnoopy/lighthouse-in-snoo:latest` as an HTTP service on container port `8443`, or use the port the host supplies through `PORT`.
2. Let the proxy terminate public HTTPS and forward WebSocket connections to the hub.
3. Leave `LIGHTHOUSE_DOMAIN` and `LIGHTHOUSE_HUB_ORIGIN` unset if the public hostname or port can change.
4. Set `LIGHTHOUSE_NO_RELAY=true` if the host cannot publish UDP ports for the relay.
5. Enter the public hostname in the desktop app without `https://` or a path.

Check `https://hub.example.com/healthz` using the public hostname.
A healthy hub returns `{"status":"ok"}`.
This check does not test peer connectivity.
If peers cannot connect directly, they need a relay that both can reach.

## Configuration reference

Set variables in the process environment or use a `.env` file in the working directory.
Both binaries read only `LIGHTHOUSE_*` entries from `.env` and do not overwrite variables already in the process environment.
Compose passes the optional `.env` file into the container and uses `IMAGE` to select the image.
For options with both a flag and a variable, the flag takes precedence over the variable.
See [the sample environment file](../.env.example) for a starting point.

### Hub options

Run `lighthouse hub --help` to see the options supported by your build.

| Flag | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `--domain` | `LIGHTHOUSE_DOMAIN` | Unset | Set the public host or `host:port`. Derive the hub origin, relay hostname and realm, and generated certificate names. |
| `--hub-origin` | `LIGHTHOUSE_HUB_ORIGIN` | From the domain, otherwise unpinned | Require a specific public `wss://` origin. |
| `--https-addr` | `LIGHTHOUSE_HTTPS_ADDR` | From `PORT`, otherwise `:8443` | Set the listen address for HTTPS and signaling. |
| `--stuns-addr` | `LIGHTHOUSE_STUNS_ADDR` | `:5349` | Set the encrypted STUNS/TURNS listen address. Use TCP for STUNS in TCP-only mode. |
| `--cidr` | `LIGHTHOUSE_CIDR` | `10.88.0.0/16` | Set the virtual IPv4 subnet used to assign peer addresses. |
| `--tls-algo` | `LIGHTHOUSE_TLS_ALGO` | `ed25519` | Select the key type for a new certificate: `ed25519`, `nistp-256`, `nistp-384`, `nistp-521`, or `rsa`. |
| `--tls-rsa-bits` | `LIGHTHOUSE_TLS_RSA_BITS` | `3072` for RSA | Set the RSA key size in multiples of 8, from `2048` to `8192`. |
| `--tls-cert` | — | Automatic if you omit both flags | Use an existing certificate in PEM format. Supply `--tls-key` too. |
| `--tls-key` | — | Automatic if you omit both flags | Use the private key for `--tls-cert`. |
| `--no-relay` | `LIGHTHOUSE_NO_RELAY` | `false` | Disable the integrated relay but keep address discovery. |
| `--turn-public-ip` | `LIGHTHOUSE_TURN_PUBLIC_IP` | No public IP override | Set the IP advertised in relay allocations. |
| `--turn-advertise-host` | `LIGHTHOUSE_TURN_ADVERTISE_HOST` | From the domain, otherwise inferred | Set the host or `host:port` advertised to clients for the relay. |
| `--turn-secret` | `LIGHTHOUSE_TURN_SECRET` | Generated at startup | Set the shared secret used to issue relay credentials. |
| `--turn-realm` | `LIGHTHOUSE_TURN_REALM` | From the domain, otherwise `lighthouse` | Set the TURN authentication realm. |
| `--turn-tls-addr` | `LIGHTHOUSE_TURN_TLS_ADDR` | Disabled | Add a TLS/TCP TURNS listener if you enable the integrated relay. |
| `--turn-relay-min-port` | — | Unset | Set the first UDP allocation port. Requires a public IP and a matching upper bound. |
| `--turn-relay-max-port` | — | Unset | Set the last UDP allocation port. Requires a public IP and a matching lower bound. |
| `--tcp-only` | `LIGHTHOUSE_TCP_ONLY` | `false` | Disable UDP and the integrated relay. Serve STUNS over TLS/TCP. |
| `--insecure` | `LIGHTHOUSE_INSECURE` | `false` | Enable a plaintext STUN/TURN listener. |
| `--stun-addr` | `LIGHTHOUSE_STUN_ADDR` | `:3478` with `--insecure`, otherwise disabled | Set the plaintext STUN/TURN listen address. Requires `--insecure`. |
| `--presence-heartbeat` | — | `20s` | Set the interval for client presence updates. |
| `--presence-ttl` | — | `60s` | Set how long the hub keeps a peer without a presence update. |

`PORT` is the optional hosting platform listen port.
`LIGHTHOUSE_HTTPS_ADDR` overrides it.
If `LIGHTHOUSE_DOMAIN` is unset, the hub and the desktop app also recognize `LIGHTHOUSE_STUN_DOMAIN` as a legacy fallback for domain-derived defaults.

### Desktop app options

Run `lighthouse-ui --help` to see the options supported by your build.

| Flag | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `--domain` | `LIGHTHOUSE_DOMAIN` | Unset | Set the default hub domain. |
| `--hub` | `LIGHTHOUSE_HUB_URL` | From the domain, otherwise `localhost:8443` | Set the hub host, `host:port`, or WebSocket URL. |
| `--ifname` | `LIGHTHOUSE_IFNAME` | `lh0` | Set the virtual network interface name. |
| `--ca` | `LIGHTHOUSE_CA` | System trust store | Use a specific PEM certificate bundle instead of the system trust store. |
| `-s`, `--stun` | `LIGHTHOUSE_STUN_URI` | Automatic | Use an explicit STUNS or TURNS URI. |
| `-k`, `--key` | — | `~/.config/lighthouse/identity.key` on Linux | Set the local identity key path. The app creates a key if none exists. |
| `-a`, `--algo` | — | `ed25519` | Select a new identity key type: `ed25519`, `ed448`, `nistp-256`, `nistp-384`, `nistp-521`, or `rsa`. |
| `--bits` | — | `3072` for RSA | Set the RSA identity key size in multiples of 8, from `2048` to `8192`. |
| `--blacklist` | — | `~/.config/lighthouse/blacklist.json` on Linux | Set the local blacklist file path. |
| `--tcp-only` | `LIGHTHOUSE_TCP_ONLY` | `false` | Disable UDP. Use ICE-TCP and TLS/TCP for address discovery. |
| `--insecure` | `LIGHTHOUSE_INSECURE` | `false` | Permit plaintext `stun:` and `turn:` URIs. |

The two default file paths follow the user's configuration directory if it differs from `~/.config`.
See [Protocol and architecture](protocol-and-architecture.md) for the meaning of the transport and consent settings.
