#!/usr/bin/env bash
# Installs or upgrades wgkeeper node with Docker Compose on a Linux host.
#
#   curl -fsSL https://raw.githubusercontent.com/wgkeeper/wgkeeper-node/main/scripts/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/wgkeeper/wgkeeper-node/main/scripts/install.sh | sudo bash -s -- --domain node1.example.com
#
# Options:
#   --version X.Y.Z   release to install (default: the latest stable release)
#   --domain NAME     put Caddy with an automatic HTTPS certificate in front of the API
#   --subnet CIDR     IPv4 subnet for peers on a new install (default: 10.0.0.0/24)
#   --dir PATH        install directory (default: /opt/wgkeeper)
#
# Running it again upgrades the node to the given version. An existing
# config.yaml (API key) and ./wireguard (server key) are never overwritten.
#
# For tests: WGKEEPER_IMAGE replaces the image, WGKEEPER_FILES copies the
# Compose files from a local checkout instead of downloading them.
set -euo pipefail

REPO=wgkeeper/wgkeeper-node
IMAGE=ghcr.io/wgkeeper/node
VERSION=""
DOMAIN=""
SUBNET="10.0.0.0/24"
DIR=/opt/wgkeeper

log() { echo "==> $*"; }
die() {
	echo "error: $*" >&2
	exit 1
}

usage() {
	cat <<'EOF'
Usage: install.sh [--version X.Y.Z] [--domain NAME] [--subnet CIDR] [--dir PATH]

  --version X.Y.Z   release to install (default: the latest stable release)
  --domain NAME     put Caddy with an automatic HTTPS certificate in front of the API
  --subnet CIDR     IPv4 subnet for peers on a new install (default: 10.0.0.0/24)
  --dir PATH        install directory (default: /opt/wgkeeper)
EOF
	exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--version) VERSION="${2#v}" && shift 2 ;;
	--domain) DOMAIN="$2" && shift 2 ;;
	--subnet) SUBNET="$2" && shift 2 ;;
	--dir) DIR="$2" && shift 2 ;;
	-h | --help) usage 0 ;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
done

[[ "$(uname -s)" == "Linux" ]] || die "wgkeeper node runs on Linux only"
[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo bash ...)"
command -v curl >/dev/null || die "curl is required"
if [[ -n "$DOMAIN" && ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
	die "invalid domain: $DOMAIN"
fi

# --- WireGuard --------------------------------------------------------------
# The container has NET_ADMIN only, so the module must be available on the host.
if ! modprobe wireguard 2>/dev/null && [[ ! -d /sys/module/wireguard ]]; then
	die "the kernel has no WireGuard support (Linux 5.6+ has it built in)"
fi

# --- Docker -----------------------------------------------------------------
if ! command -v docker >/dev/null; then
	log "Installing Docker"
	curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (docker compose)"

# --- Version ----------------------------------------------------------------
if [[ -z "$VERSION" ]]; then
	VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n 1)"
	[[ -n "$VERSION" ]] || die "could not find the latest release; pass --version"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "invalid version: $VERSION"
log "Installing wgkeeper node $VERSION into $DIR"

# --- Files ------------------------------------------------------------------
# fetch PATH copies PATH from the release (or WGKEEPER_FILES) into $DIR.
fetch() {
	local path=$1
	mkdir -p "$(dirname "$DIR/$path")"
	if [[ -n "${WGKEEPER_FILES:-}" ]]; then
		cp "$WGKEEPER_FILES/$path" "$DIR/$path"
	else
		curl -fsSL "https://raw.githubusercontent.com/$REPO/v$VERSION/$path" -o "$DIR/$path" ||
			die "could not download $path for $VERSION (the installer supports 2.0.0 and newer)"
	fi
}

mkdir -p "$DIR"
cd "$DIR"

fetch docker-compose.yml
image="${WGKEEPER_IMAGE:-$IMAGE:$VERSION}"
sed -i "s|^\(\s*image:\) $IMAGE\(:.*\)\{0,1\}$|\1 $image|" docker-compose.yml
grep -q "image: $image$" docker-compose.yml || die "could not set the image in docker-compose.yml"

if [[ -f config.yaml ]]; then
	log "Keeping the existing config.yaml"
else
	log "Writing config.yaml with a new API key"
	umask 077
	cat >config.yaml <<EOF
# wgkeeper node config. All keys: https://github.com/$REPO/blob/v$VERSION/docs/configuration.md
auth:
  api_key: "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
wireguard:
  subnet: "$SUBNET"
EOF
	umask 022
fi

compose_files=docker-compose.yml
if [[ -n "$DOMAIN" || -f examples/caddy/compose.yml ]]; then
	fetch examples/caddy/compose.yml
	if [[ ! -f examples/caddy/Caddyfile ]]; then
		[[ -n "$DOMAIN" ]] || die "examples/caddy/Caddyfile is missing; pass --domain"
		fetch examples/caddy/Caddyfile
		sed -i "s/api\.example\.com/$DOMAIN/" examples/caddy/Caddyfile
	fi
	compose_files="$compose_files:examples/caddy/compose.yml"
fi
# Your own changes go in docker-compose.override.yml; this script never touches it.
if [[ -f docker-compose.override.yml ]]; then
	compose_files="$compose_files:docker-compose.override.yml"
fi
echo "COMPOSE_FILE=$compose_files" >.env

# --- Firewall ---------------------------------------------------------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
	log "Opening 51820/udp in ufw"
	ufw allow 51820/udp >/dev/null
	if [[ "$compose_files" == *caddy* ]]; then
		log "Opening 80/tcp and 443/tcp in ufw"
		ufw allow 80/tcp >/dev/null
		ufw allow 443/tcp >/dev/null
	fi
fi

# --- Start ------------------------------------------------------------------
log "Starting the node"
docker compose up -d --remove-orphans

for _ in $(seq 1 60); do
	if curl -fsS http://127.0.0.1:51821/readyz >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
curl -fsS http://127.0.0.1:51821/readyz >/dev/null 2>&1 ||
	die "the node did not become ready; see: cd $DIR && docker compose logs wireguard"

api_key="$(sed -n 's/^ *api_key: *"\{0,1\}\([^"]*\)"\{0,1\} *$/\1/p' config.yaml)"
if [[ "$compose_files" == *caddy* ]]; then
	address="https://$(sed -n 's/^\([A-Za-z0-9.-]*\) {$/\1/p' examples/caddy/Caddyfile | head -n 1)"
else
	address="http://127.0.0.1:51821 (this host only; use --domain for remote access)"
fi

cat <<EOF

wgkeeper node $VERSION is running in $DIR.

  API address:  $address
  API key:      $api_key
  WireGuard:    51820/udp

Add the node to your orchestrator or wgkeeper console with this address and key.
Manage it with: cd $DIR && docker compose ps | logs | down
EOF
