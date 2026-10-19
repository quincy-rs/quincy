FROM rust:alpine3.22 AS builder

# Keep this stage identical to the repository Dockerfile so the Docker layer
# cache can be shared between the production image and the perf image.
RUN apk add build-base gcompat jemalloc-dev
WORKDIR /tmp/quincy-build
COPY . .
RUN cargo build --release --workspace --no-default-features --features "jemalloc,offload" --exclude quincy-gui

FROM alpine:3.22 AS runner

# The harness runs as root inside the container and is granted NET_ADMIN plus
# /dev/net/tun, so no setcap is needed. Do not setcap /bin/busybox here: the
# base image's setcap makes child `docker build` RUN steps fail with EPERM.
RUN apk add --no-cache gcompat jemalloc iperf3 iproute2 wireguard-tools openvpn openssl
COPY --from=builder \
    /tmp/quincy-build/target/release/quincy-client \
    /tmp/quincy-build/target/release/quincy-server \
    /tmp/quincy-build/target/release/quincy-identity \
    /usr/local/bin/
WORKDIR /usr/srv/quincy
