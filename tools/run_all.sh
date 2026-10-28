#!/bin/bash
# Devirtualize a batch of VMEnter entries, one process per entry: NoVmp can
# segfault and a crash must not kill the batch. NOVMP_TIME_LIMIT bounds each
# lift (see the core patches); a spinning VM fails fast instead of hanging.
#
# usage: run_all.sh <image> <vms-file> <outdir> [section]
#   image    target PE
#   vms-file list of entry RVAs (hex), e.g. from vmscan.py
#   section  protected section name (default: auto-detect from the first entry)
set -u
EXE=${1:?usage: run_all.sh <image> <vms-file> <outdir> [section]}
VMS=${2:?missing vms-file}
OUT=${3:?missing outdir}
SEC=${4:-auto}
NOVMP_BIN=${NOVMP_BIN:-$(dirname "$0")/../build/NoVmp/AnimeNoVMP}
BASE=${BASE:-auto}
SUMMARY=${SUMMARY:-$OUT/summary.tsv}
export NOVMP_TIME_LIMIT=${NOVMP_TIME_LIMIT:-60}
mkdir -p "$OUT"; : > "$SUMMARY"

first=$(head -1 "$VMS")
if [ "$SEC" = auto ] || [ "$BASE" = auto ]; then
  # derive section name + image base from the PE through vmscan's stderr helper
  eval "$(python3 "$(dirname "$0")/vmscan.py" "$EXE" --verbose 2>&1 >/dev/null | head -1 | sed 's/.*found in \([A-Za-z0-9._-]*\)).*/SEC_AUTO=\1/')" || true
  SEC=${SEC_AUTO:-.vmp0}
  BASE=$(python3 - "$EXE" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read(4096)
pe = struct.unpack_from('<I', d, 0x3c)[0]
print(hex(struct.unpack_from('<Q', d, pe+24+24)[0]))
PY
)
fi

for rva in $(cat "$VMS"); do
  log="$OUT/one_$rva.log"
  timeout 150 "$NOVMP_BIN" "$EXE" -sections "$SEC" -base "$BASE" -vms "$rva" > "$log" 2>&1
  code=$?
  lifted=$(grep -ac 'Lifted & optimized' "$log" 2>/dev/null)
  stats=$(grep -a 'Instruction count' "$log" | tr -s ' ' | sed 's/^ //')
  reason=$(grep -aoE 'time budget exceeded|skipped branch to unmapped vip|Invalid VIP\.|Whoooops hit switch case|invalid virtual jump' "$log" 2>/dev/null | head -1)
  printf '%s\t%s\t%s\t%s\t%s\n' "$rva" "$code" "$lifted" "$stats" "$reason" >> "$SUMMARY"
  echo "$rva exit=$code lifted=$lifted $stats $reason"
done
echo "DONE -> $SUMMARY"
