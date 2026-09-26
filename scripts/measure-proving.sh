#!/usr/bin/env bash
# Measures `bb prove` time and peak memory for every step circuit that has a
# Prover.toml, with all cores and with 4 threads, and writes
# docs/data/prove-times.json. Proofs are verified. Run from the repo root with
# nargo and bb at the mise.toml pins (`mise run install:zk-toolchain`).
#
#   scripts/measure-proving.sh "<machine description>"
set -euo pipefail
machine="${1:?usage: scripts/measure-proving.sh \"<machine description>\"}"
nargo="${NARGO:-$HOME/.nargo/bin/nargo}"
bb="${BB:-$HOME/.bb/bb}"
cores="$(getconf _NPROCESSORS_ONLN)"
work="$(mktemp -d)"
samples="$(cd rust && cargo run -q -p eid-vectors -- samples)"
rows=()
while read -r p; do
  "$nargo" execute --package "$p" >/dev/null
  "$bb" write_vk -b "target/$p.json" -o "$work/$p" -t noir-recursive >/dev/null
  for th in "$cores" 4; do
    log="$work/time.log"
    HARDWARE_CONCURRENCY=$th /usr/bin/time -l "$bb" prove -b "target/$p.json" -w "target/$p.gz" \
      -k "$work/$p/vk" -o "$work/$p-$th" -t noir-recursive >/dev/null 2>"$log" \
      || HARDWARE_CONCURRENCY=$th /usr/bin/time -v "$bb" prove -b "target/$p.json" -w "target/$p.gz" \
      -k "$work/$p/vk" -o "$work/$p-$th" -t noir-recursive >/dev/null 2>"$log"
    secs="$(awk '/ real /{print $1} /Elapsed \(wall clock\)/{split($NF,a,":"); print a[1]*60+a[2]}' "$log" | head -1)"
    peak="$(awk '/peak memory footprint/{print $1} /Maximum resident set size/{print $NF*1024}' "$log" | head -1)"
    rows+=("{\"package\":\"$p\",\"threads\":$th,\"seconds\":$secs,\"peak_bytes\":$peak}")
    echo "$p threads=$th ${secs}s" >&2
  done
  "$bb" verify -k "$work/$p/vk" -p "$work/$p-$cores/proof" -i "$work/$p-$cores/public_inputs" -t noir-recursive >/dev/null
done <<< "$samples"
bbv="$("$bb" --version)"
nv="$("$nargo" --version | head -1 | awk '{print $4}')"
{
  printf '{\n  "machine": "%s",\n  "bb": "%s",\n  "nargo": "%s",\n  "target": "noir-recursive",\n  "date": "%s",\n  "runs": [\n' \
    "$machine" "$bbv" "$nv" "$(date -u +%Y-%m-%d)"
  (IFS=$',\n'; printf '    %s' "${rows[*]}" | sed 's/},{/},\n    {/g')
  printf '\n  ]\n}\n'
} > docs/data/prove-times.json
echo "wrote docs/data/prove-times.json" >&2
