#!/bin/bash
# Compile every lifted .vtil in <dir> to x86-64 machine code via VTIL-Utils.
# usage: compile_all.sh <vtil-dir> [vtildir-out]
set -u
VMS=${1:?usage: compile_all.sh <vtil-dir> [out-dir]}
VUTILS=${VUTILS:-$HOME/Documents/git-repo/VTIL-Utils/build/vtil}
cd "$VMS"
mkdir -p "${2:-compiled}"
n=0; ok=0
for f in *.optimized.vtil; do
  [ -e "$f" ] || break
  n=$((n+1))
  "$VUTILS" compile "$f" >/dev/null 2>&1 && ok=$((ok+1))
done
echo "compiled $ok/$n -> ${2:-compiled}/"
