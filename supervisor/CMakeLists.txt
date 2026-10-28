add_executable(novmp-run novmp-run.cpp)
# Intentionally no VTIL/linux-pe dependency: the supervisor only spawns and
# monitors worker processes, keeping it a small standalone binary.
target_compile_features(novmp-run PRIVATE cxx_std_17)
