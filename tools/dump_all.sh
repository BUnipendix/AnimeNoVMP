#!/bin/bash
# Render every .vtil in <dir> to readable pseudo-assembly.
# usage: dump_all.sh <vtil-dir> [out-dir]
set -u
VMS=${1:?usage: dump_all.sh <vtil-dir> [out-dir]}
VUTILS=${VUTILS:-$HOME/Documents/git-repo/VTIL-Utils/build/vtil}
OUT=${2:-$VMS/dump}
mkdir -p "$OUT"
n=0
for f in "$VMS"/*.vtil; do
  [ -e "$f" ] || break
  "$VUTILS" dump "$f" > "$OUT/$(basename "$f").txt" 2>/dev/null
  n=$((n+1))
done
echo "dumped $n -> $OUT/"
