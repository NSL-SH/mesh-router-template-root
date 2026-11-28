#!/bin/bash
# ensure-guard-stack.sh - IP bans on the direct path: crowdsec + mesh-router-guard
# (stacks/guard/), while MESH_GUARD=on.
#
# Deployed to ${DATA_ROOT}/AppData/guard through tools/deploy-stack.sh. What this script
# adds around the deploy:
#   - crowdsec/nsl/: the stack's CrowdSec config (acquisition, ban profiles and the
#     config.yaml.local overlay pointing at them), copied from the template. CrowdSec
#     reads it at start only, so its hash goes into the stack's .env (GUARD_CONFIG_HASH)
#     and a change recreates the container.
#   - GUARD_BOUNCER_KEY: the key mesh-router-guard presents to CrowdSec's local API,
#     minted once into the stack's .stack.env. Deleting it re-mints it; CrowdSec
#     registers the new one at its next start.
#   - GUARD_BACKEND_URL: the backend part of PROVIDER_STR, where mesh-router-guard reads
#     the gateway list it must never drop.
#   - GUARD_PROVIDER_STR: the whole box credential, for guard-sync alone (fleet reports
#     and list); the two containers that parse traffic or touch the firewall never get it.
#   - GUARD_SYNC_PASSWORD: guard-sync's machine password on CrowdSec's local API, minted
#     once like the bouncer key; crowdsec's start.sh registers it.
#
# MESH_GUARD=off (the default) brings the stack down if it is running: stopping
# mesh-router-guard removes its nft table, so no ban outlives it. The folder and
# CrowdSec's database are kept. MESH_ACCESS_LOG follows MESH_GUARD unless set (the mesh
# compose file), so the access log CrowdSec reads exists whenever the guard runs.
#
# ORDERING: after ensure-stack-up.sh (mesh-router-caddy writes the access log the
# stack mounts, and the `pcs` network exists). Nothing else depends on it.
set -euo pipefail

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/library/common.sh"

GUARD_DIR="${DATA_ROOT:-/DATA}/AppData/guard"
GUARD_STACK_ENV="$GUARD_DIR/.stack.env"

GUARD="$(get_env_value MESH_GUARD)"
if [ "$GUARD" != "on" ]; then
    if [ -f "$GUARD_DIR/docker-compose.yml" ] && [ -n "$(stack_compose "$GUARD_DIR" ps -q 2>/dev/null)" ]; then
        stack_compose "$GUARD_DIR" down
        echo "Guard stack stopped (MESH_GUARD=${GUARD:-off}); its bans are lifted"
    fi
    exit 0
fi

# --- config ------------------------------------------------------------------
# Own tree first, then the synced template/ (same rule as deploy-stack.sh).
SELF_TREE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC_CONFIG="$SELF_TREE/stacks/guard/crowdsec"
[ -d "$SRC_CONFIG" ] || SRC_CONFIG="$TEMPLATE_DIR/stacks/guard/crowdsec"
DEST_CONFIG="$GUARD_DIR/crowdsec/nsl"
mkdir -p "$DEST_CONFIG" "$GUARD_DIR/crowdsec/etc" "$GUARD_DIR/crowdsec/data" "$GUARD_DIR/state"

# Copy in place (cat >, not mv): config.yaml.local is a single-file bind mount, pinned
# to its inode. Files the template no longer ships are removed.
(cd "$SRC_CONFIG" && find . -type f) | while read -r f; do
    if ! cmp -s "$SRC_CONFIG/$f" "$DEST_CONFIG/$f"; then
        mkdir -p "$(dirname "$DEST_CONFIG/$f")"
        cat "$SRC_CONFIG/$f" >"$DEST_CONFIG/$f"
        echo "Updated crowdsec/nsl/${f#./}"
    fi
done
(cd "$DEST_CONFIG" && find . -type f) | while read -r f; do
    [ -f "$SRC_CONFIG/$f" ] || { rm -f "$DEST_CONFIG/$f"; echo "Removed crowdsec/nsl/${f#./}"; }
done
CONFIG_HASH="$(cd "$DEST_CONFIG" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)"

# --- secrets / inputs --------------------------------------------------------
for key in GUARD_BOUNCER_KEY GUARD_SYNC_PASSWORD; do
    if [ -z "$(get_stack_env_value "$key" "$GUARD_STACK_ENV")" ]; then
        stack_env_set "$key" "$(openssl rand -hex 32)" "$GUARD_STACK_ENV"
        echo "Generated $key"
    fi
done

PROVIDER_VALUE="$(get_env_value PROVIDER_STR)"
[ -n "$PROVIDER_VALUE" ] || PROVIDER_VALUE="$(get_env_value PROVIDER)"
BACKEND_URL="${PROVIDER_VALUE%%,*}"
if [ -z "$BACKEND_URL" ]; then
    # Not fatal: the guard then enforces nothing until it has a gateway list, which is
    # the safe side (see mesh-router-guard's README).
    log_warn "No PROVIDER_STR: mesh-router-guard cannot read the gateway list and will not enforce bans"
fi
mkdir -p "$GUARD_DIR/state/sync"

# Maison's dashboard hosts, for sso-allowlist.sh: maison-<suffix> on every routing
# domain and maison.<domain> (stacks/maison/routes), plus the Caddyfile's root sites
# while they still serve Maison (DEFAULT_SERVICE_HOST). Exact names, never a pattern:
# a store app called maison-x must not count.
MAISON_HOSTS=""
DOMAIN_VALUE="$(get_env_value DOMAIN)"
IFS=',' read -ra suffixes <<<"$(routing_host_suffixes)"
for suffix in "${suffixes[@]}"; do
    [ -n "$suffix" ] && MAISON_HOSTS+="${MAISON_HOSTS:+,}maison-$suffix"
done
if [ -n "$DOMAIN_VALUE" ]; then
    MAISON_HOSTS+="${MAISON_HOSTS:+,}maison.$DOMAIN_VALUE"
    if [ "$(get_env_value DEFAULT_SERVICE_HOST)" = maison ]; then
        MAISON_HOSTS+=",$DOMAIN_VALUE"
        IP_DASH="$(get_env_value PUBLIC_IP_DASH)"
        [ -n "$IP_DASH" ] && MAISON_HOSTS+=",$IP_DASH.sslip.io"
    fi
fi

# --- deploy ------------------------------------------------------------------
"$SCRIPTS_DIR/tools/deploy-stack.sh" guard "$GUARD_DIR" \
    "GUARD_CONFIG_HASH=$CONFIG_HASH" "GUARD_BACKEND_URL=$BACKEND_URL" "GUARD_PROVIDER_STR=$PROVIDER_VALUE" \
    "GUARD_MAISON_HOSTS=$MAISON_HOSTS"

cd "$GUARD_DIR"
if wait_stack_settled 90 15; then
    echo "Guard stack is up"
else
    exit 1
fi
