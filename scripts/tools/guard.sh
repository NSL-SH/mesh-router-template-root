#!/bin/bash
# guard.sh - the owner's view of the guard stack's IP bans (stacks/guard/), and the
# owner's actions on them.
#
#   status                   JSON: whether the guard runs, this box's own bans (local
#                            detection and manual), the imported fleet list per source,
#                            the allowlists, and guard-sync's last runs
#   lookup <ip>              JSON: every ban that applies to <ip>, imported ones included
#   unban <ip|cidr>          delete the bans on exactly that value. A ban imported from
#                            the fleet list comes back at guard-sync's next run unless the
#                            value is allowed
#   allow <ip|cidr> [days]   never ban it on this box (CrowdSec allowlist nsl-owner), for
#                            <days> or for good (0 / omitted); lifts its current bans, and
#                            guard-sync stops importing it
#   disallow <ip|cidr> [nsl-owner|nsl-sso]
#                            remove it from that allowlist (default nsl-owner); nsl-sso is
#                            the list sso-allowlist.sh fills from SSO logins
#
# THE CONTRACT with mesh-console (same shape as the other tools/): the console only
# knows this path, the verbs, their JSON and the exit codes. Where CrowdSec runs and how
# it is driven (cscli in the crowdsec container, the local API on loopback) is ours.
# Reads and writes nothing in the mesh .env, so it takes no self-check lock.
#
# Exit: 0 done, 2 bad arguments, 3 the guard is not running (MESH_GUARD=off), 1 failed.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$SELF_DIR/library/common.sh"

GUARD_DIR="${DATA_ROOT:-/DATA}/AppData/guard"
OWNER_LIST="nsl-owner"
SSO_LIST="nsl-sso"
CONTAINER="crowdsec"

usage() {
    echo "usage: $0 status | lookup <ip> | unban <ip|cidr> | allow <ip|cidr> [days] | disallow <ip|cidr> [$OWNER_LIST|$SSO_LIST]" >&2
    exit 2
}

# An address or a range, IPv4 or IPv6, nothing else; cscli validates it further.
valid_value() {
    [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] ||
        [[ $1 =~ ^[0-9a-fA-F:]{2,39}(/[0-9]{1,3})?$ && $1 == *:* ]]
}

running() {
    [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ]
}

cs() {
    docker exec "$CONTAINER" cscli "$@"
}

require_running() {
    if ! running; then
        echo "The guard is not running on this box (MESH_GUARD=${MESH_GUARD_VALUE:-off})." >&2
        exit 3
    fi
}

# allowlist_json <name>: its items, [] when the list does not exist.
allowlist_json() {
    cs allowlists inspect "$1" -o json 2>/dev/null |
        jq -c '[.items[]? | {value, description, created_at,
            expiration: (if (.expiration // "") | startswith("0001-") then null else .expiration end)}]' 2>/dev/null ||
        echo '[]'
}

MESH_GUARD_VALUE="$(get_env_value MESH_GUARD)"
CMD="${1:-}"
[ -n "$CMD" ] || usage
shift

case "$CMD" in
status)
    [ $# -eq 0 ] || usage
    enabled=false
    [ "$MESH_GUARD_VALUE" = "on" ] && enabled=true
    sync='null'
    [ -s "$GUARD_DIR/state/sync/sync.json" ] && sync="$(jq -c . "$GUARD_DIR/state/sync/sync.json" 2>/dev/null || echo null)"
    report="$(get_env_value MESH_GUARD_REPORT)"
    import="$(get_env_value MESH_GUARD_IMPORT)"
    if ! running; then
        jq -cn --argjson enabled "$enabled" --argjson sync "$sync" \
            --arg report "${report:-on}" --arg fleet_import "${import:-on}" \
            '{enabled: $enabled, running: false, report: ($report != "off"), "import": ($fleet_import != "off"),
              local: [], allowlists: {}, sync: $sync}'
        exit 0
    fi
    # Only this box's own bans: the imported fleet list (tens of thousands) is counted
    # from guard-sync's last run instead.
    local_bans="$(
        for origin in crowdsec cscli; do
            cs decisions list --origin "$origin" -l 0 -o json 2>/dev/null || echo '[]'
        done | jq -cs '[.[] | (. // [])[] | .decisions[]? |
            {id, value, scope, origin, scenario, type, duration}] | sort_by(.value)'
    )"
    jq -cn --argjson enabled "$enabled" --argjson sync "$sync" \
        --arg report "${report:-on}" --arg fleet_import "${import:-on}" \
        --argjson local "$local_bans" \
        --argjson owner "$(allowlist_json "$OWNER_LIST")" \
        --argjson sso "$(allowlist_json "$SSO_LIST")" \
        '{enabled: $enabled, running: true, report: ($report != "off"), "import": ($fleet_import != "off"),
          local: $local, allowlists: {"nsl-owner": $owner, "nsl-sso": $sso}, sync: $sync}'
    ;;

lookup)
    [ $# -eq 1 ] && valid_value "$1" && [[ $1 != */* ]] || usage
    require_running
    # The bouncer's view: decisions that apply to the address, ranges included.
    key="$(get_stack_env_value GUARD_BOUNCER_KEY "$GUARD_DIR/.stack.env")"
    port="$(get_env_value MESH_GUARD_LAPI_PORT)"
    body="$(curl -sf --max-time 10 -H "X-Api-Key: $key" \
        "http://127.0.0.1:${port:-8089}/v1/decisions?ip=$1")" || { echo "Local API unreachable" >&2; exit 1; }
    printf '%s' "${body:-null}" | jq -c --arg ip "$1" \
        '{ip: $ip, bans: [(. // [])[] | {id, value, scope, origin, scenario, type, duration}]}'
    ;;

unban)
    [ $# -eq 1 ] && valid_value "$1" || usage
    require_running
    if [[ $1 == */* ]]; then flag=--range; else flag=--ip; fi
    out="$(cs decisions delete "$flag" "$1" 2>&1)" || { echo "$out" >&2; exit 1; }
    echo "$out" | tail -n 1
    ;;

allow)
    { [ $# -eq 1 ] || [ $# -eq 2 ]; } && valid_value "$1" || usage
    days="${2:-0}"
    [[ $days =~ ^[0-9]{1,4}$ ]] || usage
    require_running
    cs allowlists inspect "$OWNER_LIST" >/dev/null 2>&1 ||
        cs allowlists create "$OWNER_LIST" -d "Allowed by the box owner (mesh-console)" >/dev/null
    # cscli keeps the old expiry when a value is added again: remove + add.
    cs allowlists remove "$OWNER_LIST" "$1" >/dev/null 2>&1 || true
    args=(allowlists add "$OWNER_LIST" "$1" -d "owner $(date -u +%FT%TZ)")
    [ "$days" -gt 0 ] && args+=(-e "$((days * 24))h")
    out="$(cs "${args[@]}" 2>&1)" || { echo "$out" >&2; exit 1; }
    echo "$out" | tail -n 1
    ;;

disallow)
    { [ $# -eq 1 ] || [ $# -eq 2 ]; } && valid_value "$1" || usage
    list="${2:-$OWNER_LIST}"
    case "$list" in "$OWNER_LIST" | "$SSO_LIST") ;; *) usage ;; esac
    require_running
    out="$(cs allowlists remove "$list" "$1" 2>&1)" || { echo "$out" >&2; exit 1; }
    echo "$out" | tail -n 1
    ;;

*)
    usage
    ;;
esac
