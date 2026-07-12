#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail
mode=${1:-}; shift || true
case "$mode" in
  create) [[ ${1:-} == --output && -n ${2:-} ]] || exit 2; out=$2; umask 077; mkdir -p "$(dirname "$out")"; printf '{"schema_version":1,"token_b64":"fixture"}\n' >"$out";;
  validate-replay) [[ ${1:-} == --input && -s ${2:-} ]] || exit 2; exit 0;;
  *) exit 2;;
esac
