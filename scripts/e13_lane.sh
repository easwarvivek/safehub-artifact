#!/usr/bin/env bash
# Run one lane of the sweep: a namespace, a lane's server ports, and a list of
# experiments. Launched on a client host, one process per lane.
#
#   e13_lane.sh <lane-number> <server-ip> "<experiment list>"
#
# Experiment names are the labels run_e13_sweep.sh uses. Point overrides come
# from the environment (P_A1 … P_E), so a lane can take a subset of a single
# experiment's points -- which is how B's expensive point is split off.
set -uo pipefail
LANE="${1:?lane number}"; SRV="${2:?server ip}"; ONLY="${3:?experiment list}"
export SAFEHUB_E13_SERVER="$SRV"
export SAFEHUB_E13_GIT_PORT=18191
export SAFEHUB_E13_SH_PORT=$((18190 + 2*LANE))
export SAFEHUB_E13_SVC_PORT=$((18191 + 2*LANE))
export SAFEHUB_E13_NS="l$LANE"
export SAFEHUB_E13_ONLY="$ONLY"
export SAFEHUB_E13_ART="${SAFEHUB_E13_ART:-$HOME/e13-artifacts/lane$LANE}"
export SAFEHUB_E13_STATE="$HOME/e13-run-l$LANE"
exec bash "$(dirname "$0")/run_e13_sweep.sh"
