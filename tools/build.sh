#!/bin/bash
# Build AnimeNoVMP + vtildump + novmp-run. VTIL-Core and linux-pe are git
# submodules (patched forks; see .gitmodules) — this script checks them out.
# Requires: cmake>=3.16, ninja, g++ (C++20). Network: only for the one-time
# capstone/keystone clone into the deps dir (see contrib/upstream-patches/
# 02-keystone-cstdint.patch and 06-deps-cmake4.patch for the two local fixes
# the dep copies carry).
#
# NOVMP_DEPS  override the dependency source dir (default ~/Documents/git-repo/deps,
#             holding capstone/ and keystone/ clones at the pinned commits)
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "$HERE"
git submodule update --init --recursive
DEPS=${NOVMP_DEPS:-$HOME/Documents/git-repo/deps}
if [ ! -d "$DEPS/capstone" ] || [ ! -d "$DEPS/keystone" ]; then
  echo "[!] missing deps under $DEPS — clone capstone @d71c95b0 / keystone @e1547852 first" >&2
  exit 1
fi
# Empty CMAKE_ROOT in the sandbox breaks every cmake invocation; unset it.
env -u CMAKE_ROOT cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DFETCHCONTENT_SOURCE_DIR_CAPSTONE="$DEPS/capstone" \
  -DFETCHCONTENT_SOURCE_DIR_KEYSTONE="$DEPS/keystone"
env -u CMAKE_ROOT cmake --build build -j"$(nproc)"
echo "[+] done: $HERE/build/NoVmp/AnimeNoVMP, build/vtildump/vtildump, build/supervisor/novmp-run"
