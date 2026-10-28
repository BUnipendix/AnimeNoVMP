cmake_minimum_required(VERSION 3.15)
project(AnimeNoVMP)

# Dependency sources. By default the git submodules are used (patched forks
# of VTIL-Core and linux-pe; see .gitmodules and contrib/upstream-patches/).
# Point these at your own trees to override them:
#   cmake -B build -DNOVMP_VTIL_SOURCE_DIR=/path/to/VTIL-Core -DNOVMP_LPE_SOURCE_DIR=/path/to/linux-pe
#
# Local patch: these knobs are prefixed with NOVMP_ on purpose. A variable
# named VTIL_SOURCE_DIR collides with the <Project>_SOURCE_DIR cache entry
# CMake writes for VTIL's own project() calls — after any re-configure (e.g.
# CONFIGURE_DEPENDS globbing new sources) the collision silently repointed the
# build at the inner VTIL/ directory and broke include propagation.
set(NOVMP_VTIL_SOURCE_DIR "" CACHE PATH "VTIL-Core source tree override (defaults to the submodule)")
set(NOVMP_LPE_SOURCE_DIR "" CACHE PATH "linux-pe source tree override (defaults to the submodule)")

if(NOVMP_VTIL_SOURCE_DIR)
	add_subdirectory("${NOVMP_VTIL_SOURCE_DIR}" VTIL-Core)
else()
	add_subdirectory(VTIL-Core)
endif()
if(NOVMP_LPE_SOURCE_DIR)
	add_subdirectory("${NOVMP_LPE_SOURCE_DIR}" linux-pe)
else()
	add_subdirectory(linux-pe)
endif()
add_subdirectory(NoVmp)
add_subdirectory(vtildump)
# The batch supervisor drives per-entry worker processes through a POSIX
# shell workflow (dirent.h iteration, signal handling) — Unix only.
if(UNIX)
	add_subdirectory(supervisor)
endif()
