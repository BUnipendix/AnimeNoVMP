# Known limitations

A batch run over a heavily virtualized image typically splits into the
following classes (see `run_all.sh` / `novmp-run` summary TSV):

| Class | Meaning | Status |
|---|---|---|
| `ok` | Routine lifted to VTIL and optimized | success |
| `budget` | The lift or an optimizer pass did not terminate within the wall-clock budget | narrow: the walk-side optional refinements (constant-pool fix, block-local optimizer, branch analysis, shape probes) and exit refinements are slice-bounded with latches and degrade faithfully; the residue is giant routines (100k+ lifted instructions) whose plain walk needs more than the budget — they convert with a larger `-t` |
| `vmenter-shape` | Discovery noise: a scanned stub whose entry does not match a known vmenter shape | expected for stubs that are not true VM entries |
| `vm-depth` | Nested VM re-entry exceeded the depth cap | open |
| `invalid-vip` | The virtual instruction pointer left the mapped image | open |
| `deobfuscate` | The unroll started at a native (non-entry) stub and died in encrypted data | expected: no recovery value |
| `assertion` | Lifter assertion; the batch driver isolates these so the run continues | report the entry |
| `crash:<signal>` | Hard crash; isolated per entry by the supervisor | report the entry |

Notes:

- Runtime-computed dispatches (register-assembled jump targets, stack-loaded
  exits) are modeled faithfully as symbolic jumps rather than resolved —
  evidence lands in `failures/` for offline profiling.
- Entries that are **mutated but not virtualized** (native mutation, no VM)
  are expected to fail; this tool only lifts virtual machines.
- Output fidelity: the optimized VTIL (and its x86-64 compilation) is a
  semantic re-expression, not a byte-identical reconstruction. Always verify
  behaviour of the compiled output against the original routine.
