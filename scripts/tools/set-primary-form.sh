#!/bin/bash
# set-primary-form.sh <dash|dot> - the form of the box's primary app names.
#
#   dot   <app>.<domain>: the default (MESH_PRIMARY_FORM unset).
#   dash  <app>-<domain>: the deprecated form, the owner's opt-out until it is phased out.
#
# Writes MESH_PRIMARY_FORM and applies it at once: routing_domains puts the chosen form
# first, so Maison's tiles and every store app's APP_URL move to it (Maison republishes
# each app once: about a minute of 502 per app, and one gate login per app on the new
# host). Both forms stay routed either way. The platform stacks keep their dash names.
#
# THE CONTRACT with mesh-console (same shape as set-routing-mode.sh): the console only
# knows this path, the two values, the exit codes and the derived .env keys
# PRIMARY_FORM_ACTIVE (ensure-routing-domains.sh).
#
# Takes the self-check lock and REFUSES while a self-check runs.
#
# Exit: 0 applied, 2 bad arguments, 75 a self-check is running (try later), 1 written
#       but applying failed.
set -euo pipefail

FORM="${1:-}"
case "$FORM" in
    dash|dot) ;;
    *) echo "usage: $0 <dash|dot>" >&2; exit 2 ;;
esac

exec 200>"/var/run/mesh-self-check.lock"
if ! flock -n 200; then
    echo "A self-check is running on this box - try again once it has finished." >&2
    exit 75
fi

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$SELF_DIR/library/common.sh"

if [ "$(get_env_value MESH_PRIMARY_FORM)" != "$FORM" ]; then
    set_env_value MESH_PRIMARY_FORM "$FORM"
fi
echo "MESH_PRIMARY_FORM=$FORM"

# The two steps of the self-check that carry it: the derived keys, then Maison's
# routing setting (Maison republishes only when the value changed).
bash "$SELF_DIR/self-check/ensure-routing-domains.sh" || exit 1
bash "$SELF_DIR/self-check/ensure-maison-stack.sh" || exit 1
echo "Primary form: $(get_env_value PRIMARY_FORM_ACTIVE)"
