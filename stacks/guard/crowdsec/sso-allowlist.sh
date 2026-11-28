#!/bin/bash
# sso-allowlist.sh: a source that signs in on this box is never banned here, for
# SSO_ALLOW_DAYS after it was last seen signed in. Started beside CrowdSec by start.sh.
#
# TWO SIGNALS, both read from Caddy's access log, where client_ip is the real client on
# the direct and the gateway path:
#
#   An SSO login: Dex's connector callback, `GET /callback` on its issuer host
#   (auth-<domain>, the only redirect URI its connectors use), answered 303. Dex answers
#   303 there only once the upstream (Authelia, Yundera Login) has vouched for the user
#   and the login is finalized; a missing, replayed or forged state is a 400, a refused
#   group a 403. Every SSO login on the box goes through it, whatever app it was for.
#
#   A signed-in Maison request: Maison answers `X-Maison-Auth: 1` when its gate passed it
#   the user's identity, and Maison's routes (and the Caddyfile's root sites) copy that
#   header into the log line as "maison_auth" (log_append). An app's gate keeps a
#   session for 30 days without going back to Dex, so the login alone records a source
#   about once a month; the dashboard records it on every day it is used. ONLY ON
#   MAISON'S OWN HOSTS (MAISON_HOSTS): a store app can carry Caddy labels of its own,
#   log_append included, and must not be able to vouch for its visitors.
#
# THE EFFECT: the source goes into the CrowdSec allowlist SSO_ALLOWLIST (an IPv6 one
# as its /64), expiring SSO_ALLOW_DAYS after the signal. The local API then drops
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

# Maison's dashboard hosts, space- or comma-separated (ensure-guard-stack.sh). Empty:
# the Maison signal is ignored and only SSO logins count.
MAISON_HOSTS="${MAISON_HOSTS:-}"
declare -A MAISON=()
for h in ${MAISON_HOSTS//,/ }; do MAISON[${h,,}]=1; done

log() { echo "[sso-allowlist] $*" >&2; }

if [ -z "$HOST" ] && [ ${#MAISON[@]} -eq 0 ]; then
    log "no SSO_HOST and no MAISON_HOSTS: nothing is allowlisted"
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

log "allowlisting SSO logins on $HOST and signed-in requests on ${#MAISON[@]} Maison hosts for ${DAYS} days ($LIST, ${#EXPIRES[@]} entries)"

# One access log line, in mesh-router-caddy's shape: the request object (headers
# deleted) in a fixed field order, then the response fields, then what log_append adds.
# The uri is the only client-controlled string, and JSON escapes any quote in it, so the
# escape-aware uri group is where a forged `"maison_auth":"1"` would have to sit, and it
# cannot leave it: everything after it is Caddy's.
LINE_RE='^\{"level":"[a-z]+","ts":([0-9]+)[^{]*"request":\{"remote_ip":"[^"]*","remote_port":"[^"]*","client_ip":"([^"]*)","proto":"[^"]*","method":"([A-Z]+)","host":"([^"]*)","uri":"((\\.|[^"\\])*)"\}(.*)$'
STATUS_RE='"status":([0-9]{3})[,}]'

# From the start of the current file: a signal while this container was down still
# counts, with its own time. A fixed-string prefilter keeps the bash loop to candidate
# lines; each is then parsed once, with no subprocess (the dashboard is chatty).
tail -n +1 -F "$LOG" 2>/dev/null |
    grep --line-buffered -E -e '"uri":"/callback' -e '"maison_auth":"1"' |
    while IFS= read -r line; do
        [[ $line =~ $LINE_RE ]] || continue
        ts=${BASH_REMATCH[1]} ip=${BASH_REMATCH[2]} method=${BASH_REMATCH[3]}
        host=${BASH_REMATCH[4],,} uri=${BASH_REMATCH[5]} rest=${BASH_REMATCH[7]}
        [[ $rest =~ $STATUS_RE ]] || continue
        status=${BASH_REMATCH[1]}
        if [ -n "$HOST" ] && [ "$host" = "${HOST,,}" ] && [ "$method" = GET ] && [ "$status" = 303 ] &&
            [[ $uri == /callback || $uri == /callback\?* || $uri == /callback/* ]]; then
            why="SSO login"
        elif [ -n "${MAISON[$host]:-}" ] && [ "$status" -lt 400 ] && [[ $rest == *'"maison_auth":"1"'* ]]; then
            why="signed in on Maison"
        else
            continue
        fi
        if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            value=$ip
        elif [[ $ip =~ ^[0-9A-Fa-f:]+$ && $ip == *:* ]]; then
            value=$(v6_net "$ip")
        else
            continue
        fi
        until_ts=$((ts + DAYS * 86400))
        # Within a day of what it has: nothing to write (most signals are repeats). Checked
        # before anything forks, since nearly every Maison line ends here.
        [ $((until_ts - ${EXPIRES[$value]:-0})) -gt 86400 ] || continue
        hours=$(((until_ts - ${EPOCHSECONDS:-$(date +%s)}) / 3600))
        [ "$hours" -gt 0 ] || continue
        [ -n "${EXPIRES[$value]:-}" ] && cscli allowlists remove "$LIST" "$value" >/dev/null 2>&1
        if cscli allowlists add "$LIST" "$value" -e "${hours}h" -d "$why $(date -u -d "@$ts" +%FT%TZ)" >/dev/null 2>&1; then
            EXPIRES[$value]=$until_ts
            log "$value allowlisted for ${hours}h ($why at $(date -u -d "@$ts" +%FT%TZ))"
        else
            log "WARN: could not allowlist $value"
        fi
    done
log "access log reader exited"
