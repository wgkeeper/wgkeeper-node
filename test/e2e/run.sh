#!/usr/bin/env bash
# End-to-end test with a real WireGuard interface.
#
# Runs the node image and a WireGuard client in Docker, then checks that a peer
# can be created and used, that the peer only reaches the internet (not the
# node, private networks or cloud metadata), and that peers and the server key
# survive a restart.
#
# Needs Docker on a Linux kernel with WireGuard (GitHub-hosted Ubuntu runners,
# Docker Desktop) and internet access for the egress check.
#
#   E2E_IMAGE=wgkeeper-node:e2e test/e2e/run.sh     # use an image you built
#   E2E_BUILD=1 test/e2e/run.sh                     # build it first
#   E2E_KEEP=1 test/e2e/run.sh                      # keep containers for debugging
set -euo pipefail

IMAGE="${E2E_IMAGE:-wgkeeper-node:e2e}"
NAME=wgk-e2e
NET_SUBNET=172.30.0.0/24
NODE_IP=172.30.0.10
LAN_IP=172.30.0.20 # stands in for the host's LAN / VPC: private, reachable from the node
WG_SUBNET=10.66.0.0/24
SERVER_IP=10.66.0.1
API=http://127.0.0.1:51821
ALPINE=alpine:3.24

WORK="$(mktemp -d)"
API_KEY="$(openssl rand -hex 32)"
failed=0

cleanup() {
	status=$?
	if [[ "${E2E_KEEP:-0}" == "1" ]]; then
		echo "E2E_KEEP=1: leaving $NAME-* containers and network in place"
		return
	fi
	if [[ "$status" -ne 0 ]] || [[ "$failed" -ne 0 ]]; then
		echo "--- node logs"
		docker logs "$NAME-node" 2>&1 | tail -n 80 || true
	fi
	docker rm -f "$NAME-node" "$NAME-client" "$NAME-lan" >/dev/null 2>&1 || true
	docker network rm "$NAME" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS  $1"; }
fail() {
	echo "FAIL  $1"
	failed=1
}
# expect_ok NAME CMD... / expect_fail NAME CMD...
expect_ok() {
	local name=$1
	shift
	if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}
expect_fail() {
	local name=$1
	shift
	if "$@" >/dev/null 2>&1; then fail "$name"; else pass "$name"; fi
}

api() { curl -fsS -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" "$@"; }

wait_ready() {
	for _ in $(seq 1 60); do
		if curl -fsS "$API/readyz" >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	echo "node did not become ready"
	return 1
}

client() { docker exec "$NAME-client" "$@"; }

if [[ "${E2E_BUILD:-0}" == "1" ]]; then
	docker build -t "$IMAGE" .
fi

# --- node -------------------------------------------------------------------
mkdir -p "$WORK/data" "$WORK/wireguard"
cat >"$WORK/config.yaml" <<EOF
auth:
  api_key: "$API_KEY"
wireguard:
  subnet: "$WG_SUBNET"
  server_ip: "$SERVER_IP"
EOF

docker network create --subnet "$NET_SUBNET" "$NAME" >/dev/null
docker run -d --name "$NAME-lan" --network "$NAME" --ip "$LAN_IP" "$ALPINE" sleep infinity >/dev/null

start_node() {
	docker run -d --name "$NAME-node" \
		--network "$NAME" --ip "$NODE_IP" \
		--cap-add NET_ADMIN --security-opt no-new-privileges:true \
		--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.all.src_valid_mark=1 \
		-v "$WORK/config.yaml:/app/config.yaml:ro" \
		-v "$WORK/wireguard:/etc/wireguard" \
		-v "$WORK/data:/var/lib/wgkeeper" \
		-p 127.0.0.1:51821:51821 \
		"$IMAGE" >/dev/null
}
start_node
wait_ready
pass "node starts and /readyz answers"

# --- peer -------------------------------------------------------------------
PEER_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr '[:upper:]' '[:lower:]')"
created="$(api -X POST "$API/peers" -d "{\"peerId\":\"$PEER_ID\"}")"
server_key="$(echo "$created" | jq -r .server.publicKey)"
server_port="$(echo "$created" | jq -r .server.listenPort)"
peer_key="$(echo "$created" | jq -r .peer.privateKey)"
peer_psk="$(echo "$created" | jq -r .peer.presharedKey)"
peer_ip="$(echo "$created" | jq -r '.peer.allowedIPs[0]')"
if [[ -n "$server_key" ]] && [[ "$server_key" != null ]]; then
	pass "POST /peers returns keys and an address ($peer_ip)"
else
	fail "POST /peers returns keys"
fi

expect_fail "unknown JSON fields are rejected" \
	api -X POST "$API/peers" -d "{\"peerId\":\"$PEER_ID\",\"expires_at\":\"2030-01-01T00:00:00Z\"}"

# --- client -----------------------------------------------------------------
docker run -d --name "$NAME-client" --network "$NAME" \
	--cap-add NET_ADMIN --sysctl net.ipv4.conf.all.src_valid_mark=1 \
	"$ALPINE" sleep infinity >/dev/null
client apk add --no-cache --quiet wireguard-tools iproute2 curl

# Route only what the checks need through the tunnel: the server, an internet
# address, the "LAN" host and the cloud metadata address.
docker exec -i "$NAME-client" sh -c "mkdir -p /etc/wireguard && cat >/etc/wireguard/wg0.conf" <<EOF
[Interface]
PrivateKey = $peer_key
Address = $peer_ip

[Peer]
PublicKey = $server_key
PresharedKey = $peer_psk
Endpoint = $NODE_IP:$server_port
AllowedIPs = $WG_SUBNET, 1.1.1.1/32, $LAN_IP/32, 169.254.169.254/32
PersistentKeepalive = 5
EOF
if ! client wg-quick up wg0 >"$WORK/wg-quick.log" 2>&1; then
	cat "$WORK/wg-quick.log"
	fail "client tunnel comes up"
	exit 1
fi

# Every check below must go through the tunnel, or a PASS means nothing.
via_tunnel() {
	local dst=$1
	[[ "$(client ip route get "$dst")" == *" dev wg0 "* ]]
}
for dst in "$SERVER_IP" 1.1.1.1 "$LAN_IP" 169.254.169.254; do
	if ! via_tunnel "$dst"; then
		fail "client routes $dst through the tunnel"
		exit 1
	fi
done
pass "client routes the test addresses through the tunnel"

# forwarded counts packets the node forwarded from peers to the WAN.
forwarded() {
	docker exec "$NAME-node" iptables -L FORWARD -v -n -x |
		awk '$3 == "ACCEPT" && $6 == "wg0" { print $1; exit }'
}

expect_ok "client reaches the server address over the tunnel (ICMP)" client ping -c 2 -W 3 "$SERVER_IP"
expect_ok "handshake completed" sh -c "docker exec $NAME-client wg show wg0 latest-handshakes | awk 'BEGIN{ok=0} \$2 > 0 {ok=1} END{exit !ok}'"
before="$(forwarded)"
if client curl -sS -o /dev/null --max-time 10 http://1.1.1.1/ >/dev/null 2>&1 && [[ "$(forwarded)" -gt "$before" ]]; then
	pass "client reaches the internet through the node"
else
	fail "client reaches the internet through the node"
fi

# --- isolation --------------------------------------------------------------
expect_fail "client can't reach the node API through the tunnel" \
	client curl -sS -o /dev/null --max-time 3 "http://$SERVER_IP:51821/healthz"

if docker exec "$NAME-node" ping -c 1 -W 2 "$LAN_IP" >/dev/null 2>&1; then
	expect_fail "client can't reach private networks (LAN host $LAN_IP)" client ping -c 2 -W 2 "$LAN_IP"
else
	fail "precondition: the node itself should reach $LAN_IP"
fi

if docker exec "$NAME-node" wget -q -T 3 -O /dev/null http://169.254.169.254/ 2>/dev/null ||
	docker exec "$NAME-node" wget -q -T 3 -O /dev/null --header "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null; then
	expect_fail "client can't reach cloud metadata" client curl -sS -o /dev/null --max-time 3 http://169.254.169.254/
else
	echo "SKIP  cloud metadata check (no metadata service reachable from the node here)"
fi

# --- restart ----------------------------------------------------------------
docker rm -f "$NAME-node" >/dev/null
start_node
wait_ready
pass "node restarts with the existing data"

expect_ok "peer survives the restart" api "$API/peers/$PEER_ID"
rotated="$(api -X POST "$API/peers" -d "{\"peerId\":\"$PEER_ID\"}")"
if [[ "$(echo "$rotated" | jq -r .server.publicKey)" == "$server_key" ]]; then
	pass "server public key is unchanged after the restart"
else
	fail "server public key is unchanged after the restart"
fi
if [[ "$(echo "$rotated" | jq -r '.peer.allowedIPs[0]')" == "$peer_ip" ]]; then
	pass "rotation keeps the peer address"
else
	fail "rotation keeps the peer address"
fi

if [[ "$failed" -ne 0 ]]; then
	echo "E2E: FAILED"
	exit 1
fi
echo "E2E: all checks passed"
