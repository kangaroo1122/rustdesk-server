
# RustDesk Server (kangaroo1122 fork)

[![build](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/build.yaml/badge.svg?branch=forapi)](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/build.yaml)
[![test](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/test.yml/badge.svg?branch=forapi)](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/test.yml)

This fork tracks stable upstream releases on the production branch `forapi`.

The server provides device registration, rendezvous, and relay services, with IPv6, encrypted TCP, WebSocket, and WebRTC signaling support. API integration adds login checks, device identity synchronization, admission approval, and centralized permissions, as well as online status queries for the Web Client.

Related repositories:

- API: [kangaroo1122/rustdesk-api](https://github.com/kangaroo1122/rustdesk-api), production branch `master`
- Web Admin: [kangaroo1122/rustdesk-api-web](https://github.com/kangaroo1122/rustdesk-api-web), production branch `master`
- Official upstream: [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server)

[Changelog](CHANGELOG.md)

## Images and deployment

- S6 all-in-one: `ghcr.io/kangaroo1122/rustdesk-server-s6:<server-version>-api-<api-version>`
- Classic: `ghcr.io/kangaroo1122/rustdesk-server:<server-version>`
- Both also publish `latest`; pin exact versions for production.
- Docker Hub publishing is optional, while GHCR is always the primary target.

### Image builds

- `docker-source.yml` builds S6 and Classic images from the API and Web `master` branches under the same GitHub owner. Private repositories require `SOURCE_REPOSITORIES_TOKEN`.
- `docker.yml` assembles S6 using a specified API image version and also builds Classic. Its S6 tag is `<server-version>-api-<api-version>`.

Source builds use `image_tag` as entered. To follow the `<server-version>-api-<api-version>` naming convention, enter the complete tag; the workflow does not append the API version.

### Deployment example

```yaml
 networks:
   rustdesk-net:
     external: false
 services:
   rustdesk:
     ports:
       - 21114:21114
       - 21115:21115
       - 21116:21116
       - 21116:21116/udp
       - 21117:21117
       - 21118:21118
       - 21119:21119
     image: ghcr.io/kangaroo1122/rustdesk-server-s6:latest
     environment:
       - RELAY=<relay_server[:port]>
       - ENCRYPTED_ONLY=1
       - MUST_LOGIN=Y
       - TZ=Asia/Shanghai
       - RUSTDESK_API_RUSTDESK_ID_SERVER=<id_server[:21116]>
       - RUSTDESK_API_RUSTDESK_RELAY_SERVER=<relay_server[:21117]>
       - RUSTDESK_API_RUSTDESK_API_SERVER=http://<api_server[:21114]>
       - RUSTDESK_API_RUSTDESK_KEY_FILE=/data/id_ed25519.pub
       - RUSTDESK_API_JWT_KEY=<shared-jwt-key> # must match API and Server
     volumes:
       - /data/rustdesk/server:/data
       - /data/rustdesk/api:/app/data #
     networks:
       - rustdesk-net
     restart: unless-stopped

```

- Releases: [kangaroo1122/rustdesk-server/releases](https://github.com/kangaroo1122/rustdesk-server/releases)


# API Screenshot

![Api.png](./readme/api.png)

![commnd.png](./readme/command_simple.png)

See [RustDesk API](https://github.com/kangaroo1122/rustdesk-api) for API and Web Admin details.





<p align="center">
  <a href="#how-to-build-manually">Manually</a> •
  <a href="#docker-images">Docker</a> •
  <a href="#s6-overlay-based-images">S6-overlay</a> •
  <a href="#how-to-create-a-keypair">Keypair</a> •
  <a href="#deb-packages">Debian</a> •
  <a href="#env-variables">Variables</a><br>
  [<a href="README-DE.md">Deutsch</a>] | [<a href="README-NL.md">Nederlands</a>] | [<a href="README-TW.md">繁體中文</a>] | [<a href="README.md">简体中文</a>]<br>
</p>

# RustDesk Server Program

[![build](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/build.yaml/badge.svg)](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/build.yaml)

[**Download**](https://github.com/kangaroo1122/rustdesk-server/releases)

[**Manual**](https://rustdesk.com/docs/en/self-host/)

[**FAQ**](https://github.com/rustdesk/rustdesk/wiki/FAQ)

Self-host your own RustDesk server, it is free and open source.

## How to build manually

```bash
cargo build --release
```

Three executables will be generated in target/release.

- hbbs - RustDesk ID/Rendezvous server
- hbbr - RustDesk relay server
- rustdesk-utils - RustDesk CLI utilities

You can find binaries built by this fork on its [Releases](https://github.com/kangaroo1122/rustdesk-server/releases) page.

If you want extra features, [RustDesk Server Pro](https://rustdesk.com/pricing.html) might suit you better.

If you want to develop your own server, the upstream [rustdesk-server-demo](https://github.com/rustdesk/rustdesk-server-demo) is a simpler starting point.

## Docker images

Images are published to this fork's GitHub Container Registry. Docker Hub is an optional mirror
when repository credentials are configured. Two image variants are available.

### Classic image

The Classic image is built from scratch with `hbbs` and `hbbr`. It is available from
[GHCR](https://github.com/kangaroo1122/rustdesk-server/pkgs/container/rustdesk-server) for these architectures:

* amd64
* arm64v8
* armv7
* i386

Use an exact server version in production or `latest` for manual validation:

| Version | image:tag |
| --- | --- |
| latest | `ghcr.io/kangaroo1122/rustdesk-server:latest` |
| Exact | `ghcr.io/kangaroo1122/rustdesk-server:<server-version>` |


You can start these images directly with `docker run` with these commands:

```bash
docker run --name hbbs --net=host -v "$PWD/data:/root" -d ghcr.io/kangaroo1122/rustdesk-server:latest hbbs -r <relay-server-ip[:port]>
docker run --name hbbr --net=host -v "$PWD/data:/root" -d ghcr.io/kangaroo1122/rustdesk-server:latest hbbr
```

Port mapping is also supported. P2P connectivity depends on NAT, firewall rules, and port configuration.

For systems using SELinux, replacing `/root` by `/root:z` is required for the containers to run correctly. Alternatively, SELinux container separation can be disabled completely adding the option `--security-opt label=disable`.

```bash
docker run --name hbbs -p 21115:21115 -p 21116:21116 -p 21116:21116/udp -p 21118:21118 -v "$PWD/data:/root" -d ghcr.io/kangaroo1122/rustdesk-server:latest hbbs -r <relay-server-ip[:port]>
docker run --name hbbr -p 21117:21117 -p 21119:21119 -v "$PWD/data:/root" -d ghcr.io/kangaroo1122/rustdesk-server:latest hbbr
```

The `relay-server-ip` parameter is the IP address (or dns name) of the server running these containers. The **optional** `port` parameter has to be used if you use a port different than **21117** for `hbbr`.

You can also use docker-compose, using this configuration as a template:

```yaml
version: '3'

networks:
  rustdesk-net:
    external: false

services:
  hbbs:
    container_name: hbbs
    ports:
      - 21115:21115
      - 21116:21116
      - 21116:21116/udp
      - 21118:21118
    image: ghcr.io/kangaroo1122/rustdesk-server:latest
    command: hbbs -r rustdesk.example.com:21117
    volumes:
      - ./data:/root
    networks:
      - rustdesk-net
    depends_on:
      - hbbr
    restart: unless-stopped

  hbbr:
    container_name: hbbr
    ports:
      - 21117:21117
      - 21119:21119
    image: ghcr.io/kangaroo1122/rustdesk-server:latest
    command: hbbr
    volumes:
      - ./data:/root
    networks:
      - rustdesk-net
    restart: unless-stopped
```

Edit line 16 to point to your relay server (the one listening on port 21117). You can also edit the volume lines (line 18 and line 33) if you need.

(docker-compose credit goes to @lukebarone and @QuiGonLeong)

## S6-overlay based images

The S6 image includes the API, `hbbs`, `hbbr`,
`rustdesk-utils`, and [S6-overlay](https://github.com/just-containers/s6-overlay). It is published to
[GHCR](https://github.com/kangaroo1122/rustdesk-server/pkgs/container/rustdesk-server-s6).

* amd64
* arm64v8
* armv7

Use the exact image tag specified during the build for production:

| Version | image:tag |
| --- | --- |
| latest | `ghcr.io/kangaroo1122/rustdesk-server-s6:latest` |
| Exact | `ghcr.io/kangaroo1122/rustdesk-server-s6:<server-version>-api-<api-version>` |

S6 supervises key initialization, `hbbr`, `hbbs`, and API, so separate API and server containers are not required.

Persist `/data` for the hbbs database and server key pair, and `/app/data` for the API database.
Back up both directories before upgrades; they are separate data stores and must not be merged.

You can start these images directly with `docker run` with this command:

```bash
docker run --name rustdesk-server \
  --net=host \
  -e "RELAY=rustdeskrelay.example.com" \
  -e "ENCRYPTED_ONLY=1" \
  -v "$PWD/data:/data" \
  -v "$PWD/api-data:/app/data" \
  -d ghcr.io/kangaroo1122/rustdesk-server-s6:latest
```

Port mapping is also supported. P2P connectivity depends on NAT, firewall rules, and port configuration.

```bash
docker run --name rustdesk-server \
  -p 21114:21114 -p 21115:21115 -p 21116:21116 -p 21116:21116/udp \
  -p 21117:21117 -p 21118:21118 -p 21119:21119 \
  -e "RELAY=rustdeskrelay.example.com" \
  -e "ENCRYPTED_ONLY=1" \
  -v "$PWD/data:/data" \
  -v "$PWD/api-data:/app/data" \
  -d ghcr.io/kangaroo1122/rustdesk-server-s6:latest
```

Or you can use a docker-compose file:

```yaml
version: '3'

services:
  rustdesk-server:
    container_name: rustdesk-server
    ports:
      - 21115:21115
      - 21116:21116
      - 21116:21116/udp
      - 21117:21117
      - 21118:21118
      - 21119:21119
    image: ghcr.io/kangaroo1122/rustdesk-server-s6:latest
    environment:
      - "RELAY=rustdesk.example.com:21117"
      - "ENCRYPTED_ONLY=1"
    volumes:
      - ./data:/data
      - ./api-data:/app/data
    restart: unless-stopped
```

For this container image, you can use these environment variables, **in addition** to the ones specified in the following **ENV variables** section:

| variable | optional | description |
| --- | --- | --- |
| RELAY | no | the IP address/DNS name of the machine running this container |
| ENCRYPTED_ONLY | yes | if set to **"1"** unencrypted connection will not be accepted |
| KEY_PUB | yes | public part of the key pair |
| KEY_PRIV | yes | private part of the key pair |

### HBBS/API integration

Set these variables on the S6 container to enable API login validation, device admission and central permissions:

```yaml
environment:
  RUSTDESK_API_INTERNAL_URL: "http://127.0.0.1:21114"
  RUSTDESK_API_CLIENT_COMPATIBILITY_INTERNAL_SECRET: "${RUSTDESK_INTERNAL_SECRET}"
```

Set `RUSTDESK_INTERNAL_SECRET` to a random secret of at least 32 bytes in the deployment environment. HBBS and API must use the same secret and share the local network namespace. The API URL must not include a path or query. `RUSTDESK_API_INTERNAL_URL` defaults to `http://127.0.0.1:21114` when unset or empty. Integration is enabled by a nonempty `RUSTDESK_API_CLIENT_COMPATIBILITY_INTERNAL_SECRET`; a secret shorter than 32 bytes rejects integration requests; when enabled, API failure rejects new connections. `MUST_LOGIN=Y` requires user login. See the [API README](https://github.com/kangaroo1122/rustdesk-api/blob/master/README_EN.md) for device policies and recordings.

WebRTC signaling requires HBBS key exchange (`-k`) and the matching server public key on clients. WebSocket deployments require WSS with long-lived connections; TURN must be deployed separately. Version 1.4.9 clients continue using the original connection protocol.

### Secret management in S6-overlay based images

You can obviously keep the key pair in a docker volume, but the best practices tells you to not write the keys on the filesystem; so we provide a couple of options.

On container startup, the presence of the keypair is checked (`/data/id_ed25519.pub` and `/data/id_ed25519`) and if one of these keys doesn't exist, it's recreated from ENV variables or docker secrets.
Then the validity of the keypair is checked: if public and private keys doesn't match, the container will stop.
If you provide no keys, `hbbs` will generate one for you, and it'll place it in the default location.

#### Use ENV to store the key pair

You can use docker environment variables to store the keys. Just follow this examples:

```bash
docker run --name rustdesk-server \
  --net=host \
  -e "RELAY=rustdeskrelay.example.com" \
  -e "ENCRYPTED_ONLY=1" \
  -e "DB_URL=/db/db_v2.sqlite3" \
  -e "KEY_PRIV=FR2j78IxfwJNR+HjLluQ2Nh7eEryEeIZCwiQDPVe+PaITKyShphHAsPLn7So0OqRs92nGvSRdFJnE2MSyrKTIQ==" \
  -e "KEY_PUB=iEyskoaYRwLDy5+0qNDqkbPdpxr0kXRSZxNjEsqykyE=" \
  -v "$PWD/db:/db" -d ghcr.io/kangaroo1122/rustdesk-server-s6:latest
```

```yaml
version: '3'

services:
  rustdesk-server:
    container_name: rustdesk-server
    ports:
      - 21115:21115
      - 21116:21116
      - 21116:21116/udp
      - 21117:21117
      - 21118:21118
      - 21119:21119
    image: ghcr.io/kangaroo1122/rustdesk-server-s6:latest
    environment:
      - "RELAY=rustdesk.example.com:21117"
      - "ENCRYPTED_ONLY=1"
      - "DB_URL=/db/db_v2.sqlite3"
      - "KEY_PRIV=FR2j78IxfwJNR+HjLluQ2Nh7eEryEeIZCwiQDPVe+PaITKyShphHAsPLn7So0OqRs92nGvSRdFJnE2MSyrKTIQ=="
      - "KEY_PUB=iEyskoaYRwLDy5+0qNDqkbPdpxr0kXRSZxNjEsqykyE="
    volumes:
      - ./db:/db
    restart: unless-stopped
```

#### Use Docker secrets to store the key pair

You can alternatively use docker secrets to store the keys.
This is useful if you're using **docker-compose** or **Docker Swarm**.
Just follow this examples:

```bash
cat secrets/id_ed25519.pub | docker secret create key_pub -
cat secrets/id_ed25519 | docker secret create key_priv -
docker service create --name rustdesk-server \
  --secret key_priv --secret key_pub \
  --net=host \
  -e "RELAY=rustdeskrelay.example.com" \
  -e "ENCRYPTED_ONLY=1" \
  -e "DB_URL=/db/db_v2.sqlite3" \
  --mount "type=bind,source=$PWD/db,destination=/db" \
  ghcr.io/kangaroo1122/rustdesk-server-s6:latest
```

```yaml
version: '3'

services:
  rustdesk-server:
    container_name: rustdesk-server
    ports:
      - 21115:21115
      - 21116:21116
      - 21116:21116/udp
      - 21117:21117
      - 21118:21118
      - 21119:21119
    image: ghcr.io/kangaroo1122/rustdesk-server-s6:latest
    environment:
      - "RELAY=rustdesk.example.com:21117"
      - "ENCRYPTED_ONLY=1"
      - "DB_URL=/db/db_v2.sqlite3"
    volumes:
      - ./db:/db
    restart: unless-stopped
    secrets:
      - key_pub
      - key_priv

secrets:
  key_pub:
    file: secrets/id_ed25519.pub
  key_priv:
    file: secrets/id_ed25519
```

## How to create a keypair

A keypair is needed for encryption; you can provide it, as explained before, but you need a way to create one.

You can use this command to generate a keypair:

```bash
/usr/bin/rustdesk-utils genkeypair
```

If you don't have (or don't want) the `rustdesk-utils` package installed on your system, you can invoke the same command with docker:

```bash
docker run --rm --entrypoint /usr/bin/rustdesk-utils  ghcr.io/kangaroo1122/rustdesk-server-s6:latest genkeypair
```

The output will be something like this:

```text
Public Key:  8BLLhtzUBU/XKAH4mep3p+IX4DSApe7qbAwNH9nv4yA=
Secret Key:  egAVd44u33ZEUIDTtksGcHeVeAwywarEdHmf99KM5ajwEsuG3NQFT9coAfiZ6nen4hfgNICl7upsDA0f2e/jIA==
```

## .deb packages

Separate .deb packages are available for each binary, you can find them in the [Releases](https://github.com/kangaroo1122/rustdesk-server/releases).
These packages are meant for the following distributions:

- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Ubuntu 20.04 LTS
- Ubuntu 18.04 LTS
- Debian 12 bookworm
- Debian 11 bullseye
- Debian 10 buster

## ENV variables

`hbbs` and `hbbr` can be configured using these ENV variables.
You can specify the variables as usual or use an `.env` file.

| variable | binary | description |
| --- | --- | --- |
| ALWAYS_USE_RELAY | hbbs | if set to **"Y"** disallows direct peer connection |
| DB_URL | hbbs | path for database file |
| DOWNGRADE_START_CHECK | hbbr | delay (in seconds) before downgrade check |
| DOWNGRADE_THRESHOLD | hbbr | threshold of downgrade check (bit/ms) |
| KEY | hbbs/hbbr | if set force the use of a specific key, if set to **"_"** force the use of any key |
| LIMIT_SPEED | hbbr | speed limit (in Mb/s) |
| PORT | hbbs/hbbr | listening port (21116 for hbbs - 21117 for hbbr) |
| RELAY | hbbs | IP address/DNS name of the machines running hbbr (separated by comma) |
| RUST_LOG | all | set debug level (error\|warn\|info\|debug\|trace) |
| SINGLE_BANDWIDTH | hbbr | max bandwidth for a single connection (in Mb/s) |
| TOTAL_BANDWIDTH | hbbr | max total bandwidth (in Mb/s) |
