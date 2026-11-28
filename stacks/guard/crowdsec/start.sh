#!/bin/bash
# start.sh: the crowdsec container's entrypoint. CrowdSec's own (docker_start.sh), with
# sso-allowlist.sh beside it. The reader is restarted if it exits; CrowdSec stays PID 1.

# Our local scenarios (crowdsec/scenarios) into CrowdSec's scenarios directory, which
# lives in the state volume: copied at every start, and a file we no longer ship is
# removed (ours are the nsl-*.yaml ones; the hub's are links into its own tree).
mkdir -p /etc/crowdsec/scenarios
for f in /etc/crowdsec/scenarios/nsl-*.yaml; do
    [ -e "$f" ] && [ ! -e "/etc/crowdsec-nsl/scenarios/${f##*/}" ] && rm -f "$f"
done
for f in /etc/crowdsec-nsl/scenarios/nsl-*.yaml; do
    [ -e "$f" ] && cp "$f" /etc/crowdsec/scenarios/
done

(
    while true; do
        bash /etc/crowdsec-nsl/sso-allowlist.sh
        sleep 30
    done
) &
# guard-sync's machine (watcher) credential, from SYNC_PASSWORD, once the local API is
# up. Re-applied at every start, so a re-minted password takes effect with the recreate.
if [ -n "${SYNC_PASSWORD:-}" ]; then
    (
        until cscli lapi status >/dev/null 2>&1; do sleep 5; done
        cscli machines add guard-sync --password "$SYNC_PASSWORD" --force -f /dev/null >/dev/null 2>&1 &&
            echo "[start] guard-sync machine registered" >&2 ||
            echo "[start] WARN: could not register the guard-sync machine" >&2
    ) &
fi
cd / && exec /bin/bash docker_start.sh "$@"
