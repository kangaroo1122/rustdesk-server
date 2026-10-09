
# RustDesk Server（kangaroo1122 fork）

[![build](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/build.yaml/badge.svg?branch=forapi)](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/build.yaml)
[![test](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/test.yml/badge.svg?branch=forapi)](https://github.com/kangaroo1122/rustdesk-server/actions/workflows/test.yml)

本仓库是面向自建 RustDesk 服务的增强 fork。`forapi` 为线上分支，在保留原有
`hbbs`/`hbbr` 能力的基础上同步官方稳定版本，并与以下自有仓库配套：

- API：[kangaroo1122/rustdesk-api](https://github.com/kangaroo1122/rustdesk-api)（线上分支 `master`）
- Web Admin：[kangaroo1122/rustdesk-api-web](https://github.com/kangaroo1122/rustdesk-api-web)（线上分支 `master`）
- 官方上游：[rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server)

主要增强包括 API 登录兼容、`MUST_LOGIN`/JWT 校验、客户端 WebSocket、加密 TCP
连接和 Web Client 在线状态查询。

## 发布镜像

- S6 一体镜像：`ghcr.io/kangaroo1122/rustdesk-server-s6:<server-version>-api-<api-version>`
- Classic 镜像：`ghcr.io/kangaroo1122/rustdesk-server:<server-version>`
- 两类镜像同时维护 `latest`；生产部署建议固定精确版本。
- Docker Hub 仅在仓库配置了相应凭据时同步发布，GHCR 是默认发布目标。

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
       - RUSTDESK_API_JWT_KEY=<shared-jwt-key> # API 与 Server 必须一致
     volumes:
       - /data/rustdesk/server:/data
       - /data/rustdesk/api:/app/data #将数据库挂载
     networks:
       - rustdesk-net
     restart: unless-stopped

```

- Releases：[kangaroo1122/rustdesk-server/releases](https://github.com/kangaroo1122/rustdesk-server/releases)


# API功能截图

![Api.png](./readme/api.png)

![commnd.png](./readme/command_simple.png)

更多说明请查看 [RustDesk API](https://github.com/kangaroo1122/rustdesk-api)。


---

<p align="center">
  <a href="#如何自行构建">自行构建</a> •
  <a href="#Docker-镜像">Docker</a> •
  <a href="#基于-S6-overlay-的镜像">S6-overlay</a> •
  <a href="#如何创建密钥">密钥</a> •
  <a href="#deb-套件">Debian</a> •
  <a href="#ENV-环境参数">环境参数</a><br>
  [<a href="README-EN.md">English</a>] | [<a href="README-DE.md">Deutsch</a>] | [<a href="README-NL.md">Nederlands</a>] | [<a href="README-TW.md">繁体中文</a>]<br>
</p>

# RustDesk Server Program



[**下载**](https://github.com/kangaroo1122/rustdesk-server/releases)

[**说明文件**](https://rustdesk.com/docs/zh-cn/self-host/)

自行搭建属于你的RustDesk服务器,所有的一切都是免费且开源的

## 如何自行构建

```bash
cargo build --release
```

执行后会在target/release目录下生成三个对应平台的可执行程序

- hbbs - RustDesk ID/会和服务器
- hbbr - RustDesk 中继服务器
- rustdesk-utils - RustDesk 命令行工具

您可以在 [Releases](https://github.com/kangaroo1122/rustdesk-server/releases) 页面中找到当前 fork 构建的服务端软件。

如果您需要额外的功能支持，[RustDesk 专业版服务器](https://rustdesk.com/pricing.html) 获取更适合您。

如果您想开发自己的服务器，[rustdesk-server-demo](https://github.com/rustdesk/rustdesk-server-demo) 应该会比直接使用这个仓库更简单快捷。

## Docker 镜像

Docker镜像会在每次 GitHub 发布新的release版本时自动构建。我们提供两种类型的镜像。

### Classic 传统镜像

Classic 镜像基于 `scratch`，仅包含 `hbbr` 和 `hbbs`。默认发布到
[GitHub Container Registry](https://github.com/kangaroo1122/rustdesk-server/pkgs/container/rustdesk-server)：

| 架构      | image:tag                                 |
|---------| ----------------------------------------- |
| multiarch | `ghcr.io/kangaroo1122/rustdesk-server:latest` |
| 精确版本 | `ghcr.io/kangaroo1122/rustdesk-server:<server-version>` |

您可以使用以下命令，直接通过 ``docker run`` 來启动这些镜像：

```bash
docker run --name hbbs --net=host -v "$PWD/data:/root" -d ghcr.io/kangaroo1122/rustdesk-server:latest hbbs -r <relay-server-ip[:port]>
docker run --name hbbr --net=host -v "$PWD/data:/root" -d ghcr.io/kangaroo1122/rustdesk-server:latest hbbr
```

或不使用 `--net=host` 参数启动， 但这样 P2P 直连功能将无法工作。

对于使用了 SELinux 的系统，您需要将 ``/root`` 替换为 ``/root:z``，以保证容器的正常运行。或者，也可以通过添加参数 ``--security-opt label=disable`` 来完全禁用 SELinux 容器隔离。

```bash
docker run --name hbbs -p 21115:21115 -p 21116:21116 -p 21116:21116/udp -p 21118:21118 -v "$PWD/data:/root" -d ghcr.io/kangaroo1122/rustdesk-server:latest hbbs -r <relay-server-ip[:port]>
docker run --name hbbr -p 21117:21117 -p 21119:21119 -v "$PWD/data:/root" -d ghcr.io/kangaroo1122/rustdesk-server:latest hbbr
```

`relay-server-ip` 参数是运行这些容器的服务器的 IP 地址（或 DNS 名称）。如果你不想使用 **21117** 作为 `hbbr` 的服务端口,可使用可选参数 `port` 进行指定。

您也可以使用 docker-compose 进行构建,以下为配置示例：

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

编辑第16行来指定你的中继服务器 （默认端口监听在 21117 的那一个）。 如果需要的话，您也可以编辑 volume 信息  (第 18 和 33 行)。

（感谢 @lukebarone 和 @QuiGonLeong 协助提供的 docker-compose 配置示例）

## 基于 S6-overlay 的镜像

S6 镜像以当前 fork 的精确版本 API 镜像为基础，加入 `hbbs`、`hbbr`、
`rustdesk-utils` 和 [S6-overlay](https://github.com/just-containers/s6-overlay)。容器内同时运行
密钥初始化、`hbbr`、`hbbs` 和 API。默认发布到
[GitHub Container Registry](https://github.com/kangaroo1122/rustdesk-server/pkgs/container/rustdesk-server-s6)。


| 架構      | version | image:tag                                    |
| --------- | ------- | -------------------------------------------- |
| multiarch | latest | `ghcr.io/kangaroo1122/rustdesk-server-s6:latest` |
| multiarch | 精确版本 | `ghcr.io/kangaroo1122/rustdesk-server-s6:<server-version>-api-<api-version>` |
| 平台 | - | `linux/amd64`、`linux/arm64`、`linux/arm/v7` |

生产环境建议使用包含 Server 和 API 精确版本的 multiarch 标签；`latest` 适合手动验证。

S6-overlay 负责一体镜像内各服务的启动顺序和进程监管，因此无需另外启动 API、hbbs 和 hbbr 容器。

部署时必须分别持久化 `/data`（hbbs 数据库及服务端密钥）和 `/app/data`（API 数据库）。
升级前应同时备份这两个目录；不要把两套 SQLite 数据库混为同一个文件。

您可以使用 `docker run` 命令直接启动镜像，如下：

```bash
docker run --name rustdesk-server \
  --net=host \
  -e "RELAY=rustdeskrelay.example.com" \
  -e "ENCRYPTED_ONLY=1" \
  -v "$PWD/data:/data" \
  -v "$PWD/api-data:/app/data" \
  -d ghcr.io/kangaroo1122/rustdesk-server-s6:latest
```

或刪去 `--net=host` 参数， 但 P2P 直连功能将无法工作。

```bash
docker run --name rustdesk-server \
  -p 21115:21115 -p 21116:21116 -p 21116:21116/udp \
  -p 21117:21117 -p 21118:21118 -p 21119:21119 \
  -e "RELAY=rustdeskrelay.example.com" \
  -e "ENCRYPTED_ONLY=1" \
  -v "$PWD/data:/data" \
  -v "$PWD/api-data:/app/data" \
  -d ghcr.io/kangaroo1122/rustdesk-server-s6:latest
```

或着您也可以使用 docker-compose 文件:

```yaml
version: '3'

services:
  rustdesk-server:
    container_name: rustdesk-server
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
      - "RELAY=rustdesk.example.com:21117"
      - "ENCRYPTED_ONLY=1"
    volumes:
      - ./data:/data
      - ./api-data:/app/data
    restart: unless-stopped
```

对于此容器镜像，除了在下面的环境变量部分指定的变量之外，您还可以使用以下`环境变量`

| 环境变量           | 是否可选 | 描述                       |
|----------------|------|--------------------------|
| RELAY          | 否    | 运行此容器的宿主机的 IP 地址/ DNS 名称 |
| ENCRYPTED_ONLY | 是    | 如果设置为 **"1"**，将不接受未加密的连接。 |
| KEY_PUB        | 是    | 密钥对中的公钥（Public Key）      |
| KEY_PRIV       | 是    | 密钥对中的私钥（Private Key）     |

### HBBS 与 API 联动

在 S6 容器中设置以下变量，可启用 API 登录校验、设备准入和集中权限：

```yaml
environment:
  RUSTDESK_API_INTERNAL_URL: "http://127.0.0.1:21114"
  RUSTDESK_API_CLIENT_COMPATIBILITY_INTERNAL_SECRET: "${RUSTDESK_INTERNAL_SECRET}"
```

在部署环境中为 `RUSTDESK_INTERNAL_SECRET` 设置至少 32 字节的随机密钥，HBBS 与 API 使用相同值。API 地址不带路径或查询参数；API 与 HBBS 需共用本机网络。`RUSTDESK_API_INTERNAL_URL` 未设置或为空时默认使用 `http://127.0.0.1:21114`。未配置 `RUSTDESK_API_CLIENT_COMPATIBILITY_INTERNAL_SECRET` 时不启用联动；密钥非空即启用，但不足 32 字节会拒绝联动请求；启用后 API 不可用会拒绝新连接。`MUST_LOGIN=Y` 要求用户登录。设备策略和录像配置见 [API README](https://github.com/kangaroo1122/rustdesk-api/blob/master/README.md)。

WebRTC 信令要求 HBBS 开启密钥交换（`-k`），客户端配置匹配的服务器公钥。WebSocket 部署需提供 WSS 并保留长连接；TURN 需另行部署。客户端 1.4.9 继续使用原连接协议。

###  基于 S6-overlay 镜像的密钥管理

您可以将密钥对保存在 Docker volume 中，但我们建议不要将密钥写入文件系統中；因此，我们提供了一些方案。

在容器启动时，会检查密钥对是否存在（`/data/id_ed25519.pub` 和 `/data/id_ed25519`），如果其中一個密钥不存在，则会从环境变量或 Docker Secret 中重新生成它。
然后检查密钥对的可用性：如果公钥和私钥不匹配，容器将停止运行。
如果您未提供密钥，`hbbs` 将会在默认位置生成一个。

#### 使用 ENV 存储密钥对

您可以使用 Docker 环境变量來存储密钥。如下：

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
      - 21114:21114
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

#### 使用 Docker Secret 來保存密钥对

您还可以使用 Docker Secret 來保存密钥。
如果您使用 **docker-compose** 或 **docker swarm**，推荐您使用。
只需按照以下示例操作：

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
      - 21114:21114
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

## 如何生成密钥对

加密需要一对密钥；您可以按照前面所述提供它，但需要一个工具去生成密钥对。

您可以使用以下命令生成一对密钥：

```bash
/usr/bin/rustdesk-utils genkeypair
```

如果您沒有（或不想）在系统上安装 `rustdesk-utils` 套件，您可以使用 Docker 执行相同的命令：

```bash
docker run --rm --entrypoint /usr/bin/rustdesk-utils  ghcr.io/kangaroo1122/rustdesk-server-s6:latest genkeypair
```

运行后的输出内容如下：

```text
Public Key:  8BLLhtzUBU/XKAH4mep3p+IX4DSApe7qbAwNH9nv4yA=
Secret Key:  egAVd44u33ZEUIDTtksGcHeVeAwywarEdHmf99KM5ajwEsuG3NQFT9coAfiZ6nen4hfgNICl7upsDA0f2e/jIA==
```

## .deb 套件

每个可执行文件都有单独的 .deb 套件可供使用，您可以在 [releases](https://github.com/kangaroo1122/rustdesk-server/releases) 页面中找到它們。
這些套件适用于以下发行版：

- Ubuntu 22.04 LTS
- Ubuntu 20.04 LTS
- Ubuntu 18.04 LTS
- Debian 11 bullseye
- Debian 10 buster

## ENV 环境变量

可以使用这些`环境变量`参数來配置 hbbs 和 hbbr。
您可以像往常一样指定参数，或者使用 .env 文件。

| 参数                    | 可执行文件         | 描述                                               |
|-----------------------|---------------|--------------------------------------------------|
| ALWAYS_USE_RELAY      | hbbs          | 如果设定为 **"Y"**，将关闭直接点对点连接功能                       |
| DB_URL                | hbbs          | 数据库配置                                            |
| DOWNGRADE_START_CHECK | hbbr          | 降级检查之前的延迟是啊尽（以秒为单位）                              |
| DOWNGRADE_THRESHOLD   | hbbr          | 降级检查的阈值（bit/ms）                                  |
| KEY                   | hbbs/hbbr     | 如果设置了此参数，将强制使用指定密钥对，如果设为 **"_"**，则强制使用任意密钥       |
| LIMIT_SPEED           | hbbr          | 速度限制（以Mb/s为单位）                                   |
| PORT                  | hbbs/hbbr     | 监听端口（hbbs为21116，hbbr为21117）                      |
| RELAY_SERVERS         | hbbs          | 运行hbbr的机器的IP地址/DNS名称（用逗号分隔）                      |
| RUST_LOG              | all           | 设置 debug level (error\|warn\|info\|debug\|trace) |
| SINGLE_BANDWIDTH      | hbbr          | 单个连接的最大带宽（以Mb/s为单位）                              |
| TOTAL_BANDWIDTH       | hbbr          | 最大总带宽（以Mb/s为单位）                                  |
