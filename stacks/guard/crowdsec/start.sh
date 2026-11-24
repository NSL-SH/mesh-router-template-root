#!/bin/bash
# start.sh: the crowdsec container's entrypoint. CrowdSec's own (docker_start.sh), with
# sso-allowlist.sh beside it. The reader is restarted if it exits; CrowdSec stays PID 1.
(
    while true; do
        bash /etc/crowdsec-nsl/sso-allowlist.sh
        sleep 30
    done
) &
cd / && exec /bin/bash docker_start.sh "$@"
