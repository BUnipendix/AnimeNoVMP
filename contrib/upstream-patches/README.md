# Ready-to-send upstream patches

These are the dependency fixes this tree carries, as standalone patches
against the pinned upstream revisions, in case the upstream projects want
them directly:

| patch | upstream project | pinned rev |
|---|---|---|
| 02-keystone-cstdint.patch | keystone-engine/keystone | e154785 |
| 03a/03b-vtil-*.patch | vtil-project/VTIL-Core | 25861ca |
| 04a/04b-linuxpe-*.patch | can1357/linux-pe | 30aae56 |

The same changes are already committed to the vendored copies in this
repository (see `vendor:` commits).

- `05-vtil-crash-guards.patch` — four defensive guards fixing hard crashes on
  adversarial IR, all found via gdb on real protected images (recovered 12 of
  13 crashing routines):
  1. `auxiliaries.cpp` (analyze_branch): memory variables can carry an
     already-end defining iterator; `std::next` dereferences the null entry.
  2. `symex/variable.cpp` (test_access): end iterators reach the operand
     loops from `is_alive`/`written_by`.
  3. `routine/routine_helpers.hpp` (enumerate_instructions): the loop used
     `is_valid()` which is `!is_end() || !is_begin()` — true for end
     iterators of non-empty blocks; the walk dereferences the null entry.
  4. `trace/tracer.cpp` (rtrace_primitive): an unchecked null trace result
     is dereferenced.
