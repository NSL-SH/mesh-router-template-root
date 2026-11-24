#!/bin/bash
# sso-allowlist.sh: a source that completes an SSO login on this box is never banned
# here, for SSO_ALLOW_DAYS after its last login. Started beside CrowdSec by start.sh.
#
# THE SIGNAL: Dex's connector callback, `GET /callback` on its issuer host (auth-<domain>,
# the only redirect URI its connectors use), answered 303. Dex answers 303 there only
# once the upstream (Authelia, Yundera Login) has vouched for the user and the login is
# finalized; a missing, replayed or forged state is a 400, a refused group a 403. Every
# SSO login on the box goes through it, whatever app it was for. Read from Caddy's
# access log, where client_ip is the real client on the direct and the gateway path.
#
# THE EFFECT: the source goes into the CrowdSec allowlist SSO_ALLOWLIST (an IPv6 one
# as its /64), expiring SSO_ALLOW_DAYS after the login. The local API then drops
# every alert this box raises against it, and adding it deletes any ban it has: an
# owner banned on the direct path signs in through the gateway name and is let back in.
# Per box only, never reported anywhere.
#
# Allowlist writes have no API: cscli, in this container, is the only writer.
set -uf

LOG="${SSO_ACCESS_LOG:-/var/log/caddy/access.log}"
HOST="${SSO_HOST:-}"
LIST="${SSO_ALLOWLIST:-nsl-sso}"
DAYS="${SSO_ALLOW_DAYS:-90}"

log() { echo "[sso-allowlist] $*" >&2; }

if [ -z "$HOST" ]; then
    log "no SSO_HOST: SSO logins are not allowlisted"
    exit 0
fi

# v6_net <addr>: the /64 holding an IPv6 address.
v6_net() {
    local head tail i n
    local -a h t all
    if [[ $1 == *::* ]]; then head=${1%%::*}; tail=${1#*::}; else head=$1; tail=; fi
    IFS=: read -ra h <<<"$head"
    IFS=: read -ra t <<<"$tail"
    n=$((8 - ${#h[@]} - ${#t[@]}))
    all=("${h[@]}")
    for ((i = 0; i < n; i++)); do all+=(0); done
    all+=("${t[@]}")
    printf '%x:%x:%x:%x::/64' "$((16#${all[0]:-0}))" "$((16#${all[1]:-0}))" "$((16#${all[2]:-0}))" "$((16#${all[3]:-0}))"
}

# Wait for the local API: CrowdSec's own start registers the hub, the bouncer and the
# database before it serves.
until cscli lapi status >/dev/null 2>&1; do sleep 5; done
cscli allowlists inspect "$LIST" >/dev/null 2>&1 ||
    cscli allowlists create "$LIST" -d "Sources of a successful SSO login on this box (sso-allowlist.sh)" >/dev/null ||
    { log "WARN: could not create allowlist $LIST"; exit 1; }

# The expiry each value already has, so only a later login rewrites it (cscli keeps the
# old expiry when a value is added again: remove + add).
declare -A EXPIRES=()
while IFS=, read -r _ _ value _ expiration _; do
    [ -n "$value" ] && EXPIRES[$value]=$(date -d "$expiration" +%s 2>/dev/null || echo 0)
done < <(cscli allowlists inspect "$LIST" -o raw 2>/dev/null | tail -n +2)

log "allowlisting SSO logins on $HOST for ${DAYS} days ($LIST, ${#EXPIRES[@]} entries)"

# From the start of the current file: a login while this container was down still counts,
# with its own time. Fixed-string prefilter first, then the exact shape. Escaped quotes in
# a client-controlled field (uri) never form these patterns.
PATTERN="\"method\":\"GET\",\"host\":\"$HOST\",\"uri\":\"/callback[?/\"]"
tail -n +1 -F "$LOG" 2>/dev/null |
    grep --line-buffered -F "\"uri\":\"/callback" |
    grep --line-buffered -E "$PATTERN" |
    grep --line-buffered -E '"status":303}$' |
    while read -r line; do
        ip=$(printf '%s' "$line" | sed -n 's/.*"request":{"remote_ip":"[^"]*","remote_port":"[^"]*","client_ip":"\([^"]*\)".*/\1/p')
        ts=$(printf '%s' "$line" | sed -n 's/^{"level":"[a-z]*","ts":\([0-9]*\).*/\1/p')
        [ -n "$ip" ] && [ -n "$ts" ] || continue
        if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            value=$ip
        elif [[ $ip =~ ^[0-9A-Fa-f:]+$ && $ip == *:* ]]; then
            value=$(v6_net "$ip")
        else
            continue
        fi
        until_ts=$((ts + DAYS * 86400))
        hours=$(((until_ts - $(date +%s)) / 3600))
        [ "$hours" -gt 0 ] || continue
        # Within a day of what it has: nothing to write (most logins are repeats).
        [ $((until_ts - ${EXPIRES[$value]:-0})) -gt 86400 ] || continue
        [ -n "${EXPIRES[$value]:-}" ] && cscli allowlists remove "$LIST" "$value" >/dev/null 2>&1
        if cscli allowlists add "$LIST" "$value" -e "${hours}h" -d "SSO login $(date -u -d "@$ts" +%FT%TZ)" >/dev/null 2>&1; then
            EXPIRES[$value]=$until_ts
            log "$value allowlisted for ${hours}h (SSO login at $(date -u -d "@$ts" +%FT%TZ))"
        else
            log "WARN: could not allowlist $value"
        fi
    done
log "access log reader exited"
