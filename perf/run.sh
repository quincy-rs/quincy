#!/usr/bin/env bash
#
# Tunnel throughput harness. Server and client run in separate Docker network
# namespaces; same-namespace TUN routes bypass the TUN device.
#
# Environment: QUINCY_PERF_IMAGE, QUINCY_PERF_TUNNEL.
#
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

IMAGE="${QUINCY_PERF_IMAGE:-quincy-perf}"
NETWORK="${QUINCY_PERF_NETWORK:-quincy-perf-net}"
SERVER="quincy-perf-server"
CLIENT="quincy-perf-client"

SERVER_IP="10.66.0.1"
CLIENT_IP="10.66.0.2"
TUNNEL_NETWORK="10.66.0.1/24"
TUNNEL_SUBNET="10.66.0.0/24"
IPERF_PORT=5201
DIRECT_PORT=5202

TUNNEL="${QUINCY_PERF_TUNNEL:-quincy}"
DURATION=10
REPEATS=3
RUN_UDP=1
RUN_DIRECT=1
CONGESTION="${QUINCY_PERF_CONGESTION:-Cubic}"
BANDWIDTH="${QUINCY_PERF_BANDWIDTH:-}"
BUILD=0
KEEP=0
OUTPUT=""

usage() {
    cat <<'EOF'
Tunnel throughput harness.

Runs a server and client for the selected tunnel in separate Docker network
namespaces, then drives iperf3 through the tunnel. A direct iperf3 control
over the Docker bridge measures the environment ceiling.

Usage:
  perf/run.sh [--tunnel NAME] [--build] [--duration SECONDS] [--repeats N]
              [--no-udp] [--no-direct] [--keep] [--output FILE]

Options:
  --tunnel NAME       quincy, wireguard, or openvpn (default: quincy)
  --build             rebuild the quincy-perf image
  --duration N        iperf3 test duration in seconds (default: 10)
  --repeats N         repetitions per test, median reported (default: 3)
  --no-udp            skip UDP tests
  --no-direct         skip the direct Docker-bridge control
  --congestion NAME   Quincy only: Cubic, Bbr, or NewReno (default: Cubic)
  --bandwidth LIMIT   Quincy only: server default_bandwidth_limit, e.g. "1 gbps"
  --keep              keep containers and the generated config
  --output FILE       write TSV results to FILE
EOF
}

while (( $# > 0 )); do
    case "$1" in
        --tunnel)    TUNNEL="$2"; shift 2 ;;
        --build)     BUILD=1; shift ;;
        --duration)  DURATION="$2"; shift 2 ;;
        --repeats)   REPEATS="$2"; shift 2 ;;
        --no-udp)    RUN_UDP=0; shift ;;
        --no-direct) RUN_DIRECT=0; shift ;;
        --congestion) CONGESTION="$2"; shift 2 ;;
        --bandwidth)  BANDWIDTH="$2"; shift 2 ;;
        --keep)      KEEP=1; shift ;;
        --output)    OUTPUT="$2"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$TUNNEL" in
    quincy)    UNDERLAY_PORT=55555 ;;
    wireguard) UNDERLAY_PORT=51820 ;;
    openvpn)   UNDERLAY_PORT=1194 ;;
    *)
        echo "invalid --tunnel '$TUNNEL' (expected quincy, wireguard, or openvpn)" >&2
        exit 2
        ;;
esac

case "$CONGESTION" in
    Cubic|Bbr|NewReno) ;;
    *)
        echo "invalid --congestion '$CONGESTION' (expected Cubic, Bbr, or NewReno)" >&2
        exit 2
        ;;
esac

if [[ "$TUNNEL" != quincy && -n "$BANDWIDTH" ]]; then
    echo "warning: --bandwidth only applies to --tunnel quincy; ignoring" >&2
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/quincy-perf.XXXXXX")
CONFIG="$WORK/config"
mkdir -p "$CONFIG"

STAMP=$(date +%Y%m%d-%H%M%S)
RESULTS="${OUTPUT:-$REPO_ROOT/perf/results/$TUNNEL-$STAMP.tsv}"
mkdir -p "$(dirname "$RESULTS")"

cleanup() {
    local status=$?
    if (( KEEP )); then
        echo
        echo "Keeping containers '$SERVER' and '$CLIENT'."
        echo "Config: $WORK"
        echo "Results: $RESULTS"
    else
        docker rm -f "$SERVER" "$CLIENT" >/dev/null 2>&1 || true
        docker network rm "$NETWORK" >/dev/null 2>&1 || true
        rm -rf "$WORK"
    fi
    exit "$status"
}
trap cleanup EXIT

dump_logs() {
    echo "--- client logs ---" >&2
    docker logs --tail 80 "$CLIENT" >&2 2>&1 || true
    echo "--- server logs ---" >&2
    docker logs --tail 80 "$SERVER" >&2 2>&1 || true
}

build_images() {
    echo "Building $IMAGE..."
    docker build -t "$IMAGE" -f perf/Dockerfile .
}

if (( BUILD )) || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    build_images
fi

case "$TUNNEL" in
    quincy)
        echo "Generating Noise keys..."
        SERVER_PRIV=$(docker run --rm "$IMAGE" quincy-identity noise genkey)
        SERVER_PUB=$(printf '%s\n' "$SERVER_PRIV" | docker run --rm -i "$IMAGE" quincy-identity noise pubkey)
        CLIENT_PRIV=$(docker run --rm "$IMAGE" quincy-identity noise genkey)
        CLIENT_PUB=$(printf '%s\n' "$CLIENT_PRIV" | docker run --rm -i "$IMAGE" quincy-identity noise pubkey)

        BANDWIDTH_LINE=""
        if [[ -n "$BANDWIDTH" ]]; then
            BANDWIDTH_LINE="default_bandwidth_limit = \"$BANDWIDTH\""
        fi

        cat > "$CONFIG/server.toml" <<EOF
name = "perf-server"
bind_address = "0.0.0.0"
bind_port = $UNDERLAY_PORT
tunnel_network = "$TUNNEL_NETWORK"
users_file = "/etc/quincy/users.toml"
isolate_clients = true
$BANDWIDTH_LINE

[protocol]
mode = "noise"
key_exchange = "standard"
private_key = "$SERVER_PRIV"

[connection]
mtu = 1400
congestion_controller = "$CONGESTION"
connection_timeout_s = 30
keep_alive_interval_s = 25
send_buffer_size = 2097152
recv_buffer_size = 2097152

[log]
level = "info"
EOF

        cat > "$CONFIG/client.toml" <<EOF
connection_string = "$SERVER:$UNDERLAY_PORT"

[protocol]
mode = "noise"
key_exchange = "standard"
server_public_key = "$SERVER_PUB"
private_key = "$CLIENT_PRIV"

[connection]
mtu = 1400
congestion_controller = "$CONGESTION"
connection_timeout_s = 30
keep_alive_interval_s = 25
send_buffer_size = 2097152
recv_buffer_size = 2097152

[network]
routes = []
dns_servers = []

[log]
level = "info"
EOF

        cat > "$CONFIG/users.toml" <<EOF
[users.perf]
authorized_keys = ["$CLIENT_PUB"]
EOF
        ;;
    wireguard)
        echo "Generating WireGuard keys..."
        SERVER_WG_PRIV=$(docker run --rm "$IMAGE" wg genkey)
        SERVER_WG_PUB=$(printf '%s\n' "$SERVER_WG_PRIV" | docker run --rm -i "$IMAGE" wg pubkey)
        CLIENT_WG_PRIV=$(docker run --rm "$IMAGE" wg genkey)
        CLIENT_WG_PUB=$(printf '%s\n' "$CLIENT_WG_PRIV" | docker run --rm -i "$IMAGE" wg pubkey)

        cat > "$CONFIG/wg-server.conf" <<EOF
[Interface]
PrivateKey = $SERVER_WG_PRIV
ListenPort = $UNDERLAY_PORT

[Peer]
PublicKey = $CLIENT_WG_PUB
AllowedIPs = $CLIENT_IP/32
EOF

        cat > "$CONFIG/wg-client.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_WG_PRIV

[Peer]
PublicKey = $SERVER_WG_PUB
Endpoint = $SERVER:$UNDERLAY_PORT
AllowedIPs = $SERVER_IP/32
PersistentKeepalive = 25
EOF
        ;;
    openvpn)
        echo "Generating OpenVPN certificates..."
        docker run --rm -v "$CONFIG:/certs" "$IMAGE" sh -ec '
            cd /certs
            openssl ecparam -genkey -name prime256v1 -out ca.key
            openssl req -x509 -new -key ca.key -out ca.crt -days 1 -subj "/CN=quincy-perf-ca"
            for name in server client; do
                openssl ecparam -genkey -name prime256v1 -out "$name.key"
                openssl req -new -key "$name.key" -out "$name.csr" -subj "/CN=quincy-perf-$name"
                openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
                    -out "$name.crt" -days 1 -sha256
            done
            chmod 600 ca.key server.key client.key
        '

        cat > "$CONFIG/ovpn-server.conf" <<EOF
dev tun
proto udp
local 0.0.0.0
port $UNDERLAY_PORT
tls-server
ca /etc/quincy/ca.crt
cert /etc/quincy/server.crt
key /etc/quincy/server.key
dh none
ifconfig $SERVER_IP $CLIENT_IP
tun-mtu 1400
sndbuf 2097152
rcvbuf 2097152
data-ciphers CHACHA20-POLY1305:AES-256-GCM
verb 3
EOF

        cat > "$CONFIG/ovpn-client.conf" <<EOF
dev tun
proto udp
remote $SERVER $UNDERLAY_PORT
nobind
tls-client
ca /etc/quincy/ca.crt
cert /etc/quincy/client.crt
key /etc/quincy/client.key
ifconfig $CLIENT_IP $SERVER_IP
tun-mtu 1400
sndbuf 2097152
rcvbuf 2097152
data-ciphers CHACHA20-POLY1305:AES-256-GCM
verb 3
EOF
        ;;
esac

echo "Tunnel: $TUNNEL ($TUNNEL_NETWORK, client $CLIENT_IP, server $SERVER_IP), MTU 1400"
echo "Underlay port: $UNDERLAY_PORT"
if [[ "$TUNNEL" == quincy ]]; then
    echo "Congestion: $CONGESTION"
    echo "Bandwidth limit: ${BANDWIDTH:-unlimited}"
fi
echo "Duration: ${DURATION}s, repeats: $REPEATS"
echo

docker rm -f "$SERVER" "$CLIENT" >/dev/null 2>&1 || true
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create "$NETWORK" >/dev/null

DOCKER_RUN=(docker run -d --network "$NETWORK" --cap-add=NET_ADMIN
    --device=/dev/net/tun -v "$CONFIG:/etc/quincy:ro")

case "$TUNNEL" in
    quincy)
        "${DOCKER_RUN[@]}" --name "$SERVER" "$IMAGE" \
            quincy-server --config-path /etc/quincy/server.toml >/dev/null
        "${DOCKER_RUN[@]}" --name "$CLIENT" "$IMAGE" \
            quincy-client --config-path /etc/quincy/client.toml >/dev/null
        ;;
    wireguard)
        "${DOCKER_RUN[@]}" --name "$SERVER" "$IMAGE" sh -ec "
            ip link add wg0 type wireguard
            wg setconf wg0 /etc/quincy/wg-server.conf
            ip addr add $SERVER_IP/24 dev wg0
            ip link set mtu 1400 dev wg0
            ip link set up dev wg0
            exec sleep infinity
        " >/dev/null
        "${DOCKER_RUN[@]}" --name "$CLIENT" "$IMAGE" sh -ec "
            ip link add wg0 type wireguard
            wg setconf wg0 /etc/quincy/wg-client.conf
            ip addr add $CLIENT_IP/24 dev wg0
            ip link set mtu 1400 dev wg0
            ip link set up dev wg0
            exec sleep infinity
        " >/dev/null
        ;;
    openvpn)
        "${DOCKER_RUN[@]}" --name "$SERVER" "$IMAGE" \
            openvpn --config /etc/quincy/ovpn-server.conf >/dev/null
        "${DOCKER_RUN[@]}" --name "$CLIENT" "$IMAGE" \
            openvpn --config /etc/quincy/ovpn-client.conf >/dev/null
        ;;
esac

is_running() {
    [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]
}

iface_for_ip() {
    docker exec "$1" ip -o -4 addr show 2>/dev/null |
        awk -v ip="$2" '{
            for (i = 1; i <= NF; i++) {
                if ($i == ip || $i ~ ("^" ip "/")) {
                    print $2
                    exit
                }
            }
        }'
}

route_uses_iface() {
    local container="$1" ip="$2" iface="$3"
    for _ in $(seq 1 20); do
        if docker exec "$container" ip route get "$ip" 2>/dev/null |
            grep -q "dev $iface"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

echo "Waiting for the tunnel..."
CLIENT_IF=""
SERVER_IF=""
for _ in $(seq 1 120); do
    CLIENT_IF=$(iface_for_ip "$CLIENT" "$CLIENT_IP")
    SERVER_IF=$(iface_for_ip "$SERVER" "$SERVER_IP")
    if [[ -n "$CLIENT_IF" && -n "$SERVER_IF" ]]; then
        break
    fi
    sleep 0.25
done

if [[ -z "$CLIENT_IF" || -z "$SERVER_IF" ]]; then
    echo "Tunnel interface or address missing." >&2
    for container in "$SERVER" "$CLIENT"; do
        if ! is_running "$container"; then
            echo "Container '$container' is not running." >&2
        fi
    done
    docker exec "$CLIENT" ip -4 addr show >&2 || true
    docker exec "$SERVER" ip -4 addr show >&2 || true
    if [[ "$TUNNEL" == wireguard ]]; then
        docker exec "$CLIENT" wg show >&2 || true
        docker exec "$SERVER" wg show >&2 || true
    fi
    dump_logs
    exit 1
fi

echo "Client interface: $CLIENT_IF ($CLIENT_IP)"
echo "Server interface: $SERVER_IF ($SERVER_IP)"
echo "Client route before fallback: $(docker exec "$CLIENT" ip route get "$SERVER_IP" 2>&1 | head -1)"
echo "Server route before fallback: $(docker exec "$SERVER" ip route get "$CLIENT_IP" 2>&1 | head -1)"
echo "Server routes before fallback:"
docker exec "$SERVER" ip route
echo

# The tunnel addresses must be reached through the TUN, not the Docker bridge.
if ! route_uses_iface "$CLIENT" "$SERVER_IP" "$CLIENT_IF"; then
    echo "WARNING: client route to $SERVER_IP does not use $CLIENT_IF; adding a host route." >&2
    docker exec "$CLIENT" ip route replace "$SERVER_IP/32" dev "$CLIENT_IF"
fi

if ! route_uses_iface "$SERVER" "$CLIENT_IP" "$SERVER_IF"; then
    echo "WARNING: server route to $CLIENT_IP does not use $SERVER_IF; adding a subnet route." >&2
    docker exec "$SERVER" ip route replace "$TUNNEL_SUBNET" dev "$SERVER_IF"
fi

echo "Client route after fallback: $(docker exec "$CLIENT" ip route get "$SERVER_IP" 2>&1 | head -1)"
echo "Server route after fallback: $(docker exec "$SERVER" ip route get "$CLIENT_IP" 2>&1 | head -1)"
echo "Server UDP socket buffers:"
docker exec "$SERVER" ss -mlun 2>/dev/null | grep -A1 ":$UNDERLAY_PORT" || true
echo

echo "Starting iperf3 server..."
docker exec -d "$SERVER" iperf3 -s -B "$SERVER_IP" -p "$IPERF_PORT"
for _ in $(seq 1 50); do
    if docker exec "$SERVER" ss -ltn 2>/dev/null | grep -q ":$IPERF_PORT "; then
        break
    fi
    sleep 0.1
done

cpu_usec() {
    docker exec "$1" sh -c 'cat /sys/fs/cgroup/cpu.stat 2>/dev/null' 2>/dev/null |
        awk '/^usage_usec/{ print $2; exit }'
}

cpu_pct() {
    local before="$1" after="$2"
    if [[ -n "$before" && -n "$after" ]]; then
        awk -v b="$before" -v a="$after" -v d="$DURATION" \
            'BEGIN { printf "%.1f", (a - b) / 1000000 / d * 100 }'
    else
        printf "n/a"
    fi
}

printf '%s\n' "tunnel	test	direction	streams	proto	mbps	retrans	loss_pct	client_cpu_pct	server_cpu_pct" > "$RESULTS"

run_one() {
    local label="$1" direction="$2" streams="$3" proto="$4" target="$5" port="$6" bind="$7"
    shift 7

    local c0 s0 c1 s1 json mbps retr loss cpu_c cpu_s
    local bind_args=()
    if [[ -n "$bind" ]]; then
        bind_args=(-B "$bind")
    fi

    c0=$(cpu_usec "$CLIENT")
    s0=$(cpu_usec "$SERVER")

    if ! json=$(docker exec "$CLIENT" iperf3 \
        -c "$target" "${bind_args[@]}" -p "$port" \
        -t "$DURATION" --connect-timeout 5000 -J "$@" 2>"$WORK/iperf.err"); then
        echo "iperf3 failed for $label:" >&2
        cat "$WORK/iperf.err" >&2 || true
        dump_logs
        return 1
    fi

    c1=$(cpu_usec "$CLIENT")
    s1=$(cpu_usec "$SERVER")

    if ! mbps=$(jq -er '((.end.sum_received.bits_per_second // .end.sum.bits_per_second) / 1000000)' <<<"$json" 2>/dev/null); then
        echo "Could not parse iperf3 JSON for $label:" >&2
        echo "$json" >&2
        return 1
    fi
    retr=$(jq -r '.end.sum_sent.retransmits // 0' <<<"$json")
    loss=$(jq -r '.end.sum.lost_percent // 0' <<<"$json")
    cpu_c=$(cpu_pct "$c0" "$c1")
    cpu_s=$(cpu_pct "$s0" "$s1")

    printf '%-14s %-9s %7s %-5s %10.1f %8s %8s %14s %14s\n' \
        "$label" "$direction" "$streams" "$proto" "$mbps" "$retr" "$loss" "$cpu_c" "$cpu_s"
    printf '%s\t%s\t%s\t%s\t%s\t%.1f\t%s\t%s\t%s\t%s\n' \
        "$TUNNEL" "$label" "$direction" "$streams" "$proto" "$mbps" "$retr" "$loss" "$cpu_c" "$cpu_s" >> "$RESULTS"
    printf '%s\n' "$mbps" >> "$MBPS_FILE"
}

printf '%-14s %-9s %7s %-5s %10s %8s %8s %14s %14s\n' \
    "test" "direction" "streams" "proto" "Mbps" "retrans" "loss%" "client_cpu%" "server_cpu%"

MBPS_FILE="$WORK/mbps"
run_case() {
    local label="$1" direction="$2" streams="$3" proto="$4" target="$5" port="$6" bind="$7"
    shift 7
    : > "$MBPS_FILE"
    for r in $(seq 1 "$REPEATS"); do
        run_one "$label/$r" "$direction" "$streams" "$proto" "$target" "$port" "$bind" "$@"
    done
    local median
    median=$(sort -n "$MBPS_FILE" | awk '
        { a[NR] = $1 }
        END {
            if (NR == 0) { print "n/a" }
            else if (NR % 2) { printf "%.1f", a[(NR + 1) / 2] }
            else { printf "%.1f", (a[NR / 2] + a[NR / 2 + 1]) / 2 }
        }')
    printf '%-14s median %s Mbps\n' "$label" "$median"
}

run_case "tcp-up-1"   "up"   1 tcp "$SERVER_IP" "$IPERF_PORT" "$CLIENT_IP"
run_case "tcp-up-4"   "up"   4 tcp "$SERVER_IP" "$IPERF_PORT" "$CLIENT_IP" -P 4
run_case "tcp-down-1" "down" 1 tcp "$SERVER_IP" "$IPERF_PORT" "$CLIENT_IP" -R
run_case "tcp-down-4" "down" 4 tcp "$SERVER_IP" "$IPERF_PORT" "$CLIENT_IP" -R -P 4
if (( RUN_UDP )); then
    run_case "udp-up-1g"   "up"   1 udp "$SERVER_IP" "$IPERF_PORT" "$CLIENT_IP" -u -b 1G
    run_case "udp-down-1g" "down" 1 udp "$SERVER_IP" "$IPERF_PORT" "$CLIENT_IP" -R -u -b 1G
fi

if (( RUN_DIRECT )); then
    SERVER_ETH_IP=$(docker inspect -f \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SERVER")
    echo
    echo "Direct control via Docker bridge ($SERVER_ETH_IP:$DIRECT_PORT)"
    docker exec -d "$SERVER" iperf3 -s -B "$SERVER_ETH_IP" -p "$DIRECT_PORT"
    for _ in $(seq 1 50); do
        if docker exec "$SERVER" ss -ltn 2>/dev/null | grep -q ":$DIRECT_PORT "; then
            break
        fi
        sleep 0.1
    done
    run_case "direct-tcp-1" "up" 1 tcp "$SERVER_ETH_IP" "$DIRECT_PORT" ""
    run_case "direct-tcp-4" "up" 4 tcp "$SERVER_ETH_IP" "$DIRECT_PORT" "" -P 4
fi

echo
echo "TUN counters (tx/rx packets):"
for pair in "$CLIENT:$CLIENT_IF" "$SERVER:$SERVER_IF"; do
    container=${pair%%:*}
    iface=${pair##*:}
    tx=$(docker exec "$container" cat "/sys/class/net/$iface/statistics/tx_packets")
    rx=$(docker exec "$container" cat "/sys/class/net/$iface/statistics/rx_packets")
    echo "  $container $iface: $tx / $rx"
done

echo
echo "Results: $RESULTS"
