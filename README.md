<p align="center">
  <a href="https://www.vtil.org/">
    <img width="256" heigth="256" src="https://raw.githubusercontent.com/can1357/NoVmp/master/assets/logo.png">
  </a>
  
  <h1 align="center">AnimeNoVMP</h1>
  
  <p align="center">
    <a href="https://ci.appveyor.com/project/can1357/NoVmp">
      <img src="https://img.shields.io/appveyor/build/can1357/NoVmp?logo=appveyor&style=flat-square" alt="appveyor-ci"/>
    </a>
    <a href="https://github.com/can1357/NoVmp/blob/master/LICENSE.md">
      <img src="https://img.shields.io/github/license/can1357/NoVmp.svg?style=flat-square" alt="license"/>
    </a>
  </p>
  
  <p align="center">
    A static devirtualizer for VMProtect x64 3.x powered by VTIL.
  </p>
</p>

### VMProtect? Nope.
NoVmp is a project devirtualizing VMProtect x64 3.0 - 3.5 (latest) into optimized VTIL and optionally recompiling back to x64 using the [Virtual-machine Translation Intermediate Language](https://github.com/vtil-project/VTIL-Core) library. It is rather experimental and is mostly a PoC I wanted to release. Most things can be improved especially with the new NativeLifters repo, but it did not exist back in the time this was written.

# Usage
NoVmp  accepts **unpacked binaries**, so if your binary is packed you'll have to dump it first, additionally if you did dump it using a tool like Scylla, you'll have to provide the original image base using the `-base` parameter like so:

`-base 0x14000000` 

By default NoVmp will parse every single jump into a VM, if you are only interested in a number of **specific** virtualized routines you can use the `-vms` parameter like so with relative virtual addresses:

`-vms 0x729B81 0x72521`

These addresses should be pointing at the VMEnter, as shown below:

![VMEnter](https://raw.githubusercontent.com/can1357/NoVmp/master/assets/vmenter.png)

By default section discovery is automatic, but in case your calls are not being chained you should try adding the VMProtect section name into the section list using `-sections` as shown below:

`-sections .xxx0 .yyy0`

Note that the `.<vmp>1` section is the merged VMProtect DLL which should not be inputted.

Additionally you can use any of the following switches:
- `-noopt`: Disables optimization.
- `-opt:constant`: Optimizes the VMProtect Ultra constant obfuscation out.
- `-experimental:recompile`: Enables the experimental x64 compiler.

# Known bugs
- Known issues from VTIL-Core, mainly the lack of jump table support and propagation passes taking too long/not being great which are being worked on.
- Binaries compiled with relocations stripped are not fully supported yet.
- Experimental compiler is a borderline broken demo, issues related to it should not be submitted as it'll be reworked and will be in VTIL-Core.

# License
NoVmp is licensed under the GNU General Public License v3.

---

## About this fork

**AnimeNoVMP** is a maintained fork of NoVmp that turns the original proof of
concept into a practical batch pipeline with a hardened lifting core. It is
hardened and tuned against the aggressive VMProtect configurations found in
newer builds of a certain anime game and similar commercial protected
software, where the original tool fails or hangs on a large fraction of
virtualized routines.

### What this fork adds

- **VMProtect jump-table (virtual switch) resolution.** Upstream throws
  `Whoooops hit switch case...` whenever a VJMP target cannot be
  constant-folded. This fork recovers the relative jump table
  (`target = addend + (int32)table[i]`) straight from the image, forks the
  lift into every in-VM target, and treats dispatch-out-of-VM exits
  faithfully. To our knowledge no other open-source VMProtect devirtualizer
  (NoVmp, vmpattack, MogVMP, NoVmpy) implements this.
- **Safety guards.** Branches whose target falls outside any mapped section
  are skipped instead of crashing the lift; the deobfuscation unroll is
  bounded.
- **Per-VM wall-clock budget** (`NOVMP_TIME_LIMIT`, default 120 s, `0`
  disables). Real-world VMs occasionally spin forever; the budget makes them
  fail fast so batch runs keep moving.
- **Slice-bounded refinements.** Every symbolic refinement the lifter makes
  (exit destinations, branch analysis, shape probes, the block-local
  optimizer and the constant-pool fix) runs under a wall-clock slice
  (`NOVMP_RTRACE_BUDGET`, default 10 s, `0` disables) and degrades to a
  faithful symbolic fallback when the slice expires; optional refinements
  latch off for the rest of the routine after diverging repeatedly. A
  divergent refinement costs a slice, never the whole budget.
- **Optional verbose tracing** behind `NOVMP_VERBOSE=1`.
- **Modern toolchain support.** Builds out of the box with current GCC,
  CMake and Ninja; VTIL-Core and linux-pe are vendored (pinned, with small
  compiler fixes) so the tree is self-contained.
- **vtildump**, a small utility that renders `.vtil` routines into readable
  pseudo-assembly.
- **Batch tooling** (`tools/`):
  - `vmscan.py` — find VMEnter entries and emit the entry list for the
    engine. The scan mode follows the image layout automatically
    (cross-branch references for classic/single-shell images, direct stub
    shape for dual-shell ones) and its output matches the engine's own
    discovery; `--mode raw` keeps the legacy shape-only scan for debugging.
  - `run_all.sh` — per-entry isolated batch devirtualization with a TSV
    summary (one crashing entry never kills the batch).
  - `compile_all.sh` / `dump_all.sh` — drive
    [VTIL-Utils](https://github.com/vtil-project/VTIL-Utils) to emit real
    x86-64 machine code or readable dumps for every lifted routine.

### Dependencies

VTIL-Core and linux-pe are git **submodules** pointing at patched forks
(`BUnipendix/VTIL-Core` and `BUnipendix/linux-pe`, branch `animenovmp`);
clone with `--recurse-submodules` or let `tools/build.sh` fetch them. The
forks carry the hardening patches (crash guards, depth caps, sub-budget
plumbing) and `contrib/upstream-patches/` holds the same changes as
standalone patches for upstreaming. To use your own trees instead:

```bash
cmake -B build -DNOVMP_VTIL_SOURCE_DIR=/path/to/your/VTIL-Core -DNOVMP_LPE_SOURCE_DIR=/path/to/your/linux-pe
```

### Building

```bash
tools/build.sh            # cmake + ninja; needs g++ (C++20)
# fully offline: pre-fetch capstone/keystone and point DEPS at them
DEPS=/tmp/deps tools/build.sh
# through a proxy: PROXY=socks5h://127.0.0.1:1080 tools/build.sh
```

For x86-64 code generation build VTIL-Utils separately (`vtil compile`), see
`tools/compile_all.sh`.

### Supervised batch operation (novmp-run)

`novmp-run` (built next to `NoVmp`) drives the worker **one process per
vmenter entry**, so a segfault or a hang kills exactly that entry and never
the batch. Results come from each worker's `-report` JSONL line; workers that
die by signal are classified as `crash:<signal>`:

```bash
build/supervisor/novmp-run game.exe vms.txt -o out/ -j 4 -t 60 \
    -sections .upx0 -base 0x140000000
# out/summary.tsv   one line per entry: rva <tab> class
# out/<rva>.jsonl   the worker's report line (ok/error + reason)
# out/logs/<rva>.log full worker log
```

The worker itself also accepts `-report <file>` directly for one-shot batch
use (`-vms` accepts many entries per process; a crash there still loses the
remaining entries, hence the supervisor). Errors are classified
(`budget`, `invalid-vip`, `switch-case`, `invalid-vjmp`, `assertion`,
`vmenter-shape`, `unroll-bound`, `left-image`, `deobfuscate`, `error`);
unknown vmenter generations are dumped to `failures/` for offline profiling.

### Adaptation profiles

`-profile <file.toml>` describes *how* an image is protected — patterns and
shapes, never concrete addresses — so new protector generations adapt via
configuration instead of code changes.

**Without `-profile` the profile is auto-detected from the image's section
layout** (a `.vmp` section selects the classic VMProtect 3.x defaults; a
single `.upx0` packer section selects cross-branch discovery; `.upx0` +
`.upx1` selects the dual-shell layout with stub-target discovery).
Unrecognized layouts fail loudly — pass an explicit profile:

```bash
AnimeNoVMP game.exe -profile profiles/anime-classic-dual.toml
```

`profiles/default.toml` mirrors the built-in classic VMProtect 3.x behavior;
`profiles/anime-classic-dual.toml` adapts the older dual-shell layout (two
packer sections, stubs without cross-section references). See the comments
inside those files.

### Typical session

```bash
tools/vmscan.py game.exe --verbose > vms.txt   # find VMEnter stubs
tools/run_all.sh game.exe vms.txt out/         # devirtualize the batch
tools/compile_all.sh out/                      # .vtil -> x86-64
tools/dump_all.sh out/                         # .vtil -> readable dump
```

### Known limitations

See [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md). Not every virtualized
routine lifts cleanly; failure classes and their meaning are documented
there.

### Credits

- Original NoVmp by [Can Bölük](https://github.com/can1357) — GPL-3.0.
- [VTIL](https://github.com/vtil-project/VTIL-Core) and
  [VTIL-Utils](https://github.com/vtil-project/VTIL-Utils) by the VTIL
  project.
- This fork keeps the original license (GPL-3.0).
