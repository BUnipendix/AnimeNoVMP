#!/usr/bin/env python3
"""Scan a PE for VMProtect VMEnter stubs (AnimeNoVMP-compatible entry list).

Two scan modes, selected automatically from the image's section layout (the
same decision table as the engine's profile auto-detection) or forced via
--mode:

  cross-branch   classic VMProtect 3.x and merged single-shell images
                 (.vmp section, or a single .upx0 packer section): scan
                 executable sections for E8/E9 branches that jump into a
                 DIFFERENT executable section and land on a
                 `68 <imm32> E8 <rel32>` vmenter stub. This mirrors the
                 engine's classic discovery rule, so the output matches what
                 a worker run would discover.

  stub-target    dual-shell images (.upx0 + .upx1): the stubs are not
                 referenced through ordinary cross-section branches, so scan
                 the stub shape itself — `68 <imm32> (E8|E9) <rel32>` — and
                 keep hits whose branch lands inside one of the packer
                 sections.

  raw            legacy shape-only scan (kept for debugging; on single-shell
                 images the packed VM stream itself matches the shape
                 thousands of times, so expect heavy noise).

usage: vmscan.py <image> [--mode cross-branch|stub-target|raw]
                [--target-section NAME] [--verbose]
       --target-section NAME  only keep stubs whose branch lands in NAME
                              (auto default: the packer section(s))
       --verbose              print per-hit detail and a grouped summary
"""
import struct, sys, re

def detect_layout(secs):
    names = {n for n, *_ in secs}
    if '.vmp' in names:
        return 'cross-branch', ['.vmp']
    if '.upx0' in names and '.upx1' in names:
        return 'stub-target', ['.upx0', '.upx1']
    if '.upx0' in names:
        return 'cross-branch', ['.upx0']
    return 'raw', None

def main():
    args = sys.argv[1:]
    if '--help' in args or '-h' in args:
        print(__doc__)
        return 0
    verbose = '--verbose' in args
    mode = None
    tgt_sec_filter = None
    if '--mode' in args:
        i = args.index('--mode')
        mode = args[i + 1]
        del args[i:i + 2]
    if '--target-section' in args:
        i = args.index('--target-section')
        tgt_sec_filter = args[i + 1]
        del args[i:i + 2]
    args = [a for a in args if not a.startswith('--')]
    if not args:
        raise SystemExit(__doc__)
    path = args[0]
    d = open(path, 'rb').read(8192)
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    if d[:2] != b'MZ' or d[pe:pe+4] != b'PE\0\0':
        raise SystemExit('not a PE file')
    machine = struct.unpack_from('<H', d, pe+4)[0]
    if machine != 0x8664:
        print('[!] warning: not an x86-64 image', file=sys.stderr)
    nsec = struct.unpack_from('<H', d, pe+6)[0]
    optsize = struct.unpack_from('<H', d, pe+20)[0]
    secs = []
    for i in range(nsec):
        s = d[pe+24+optsize+40*i:pe+24+optsize+40*i+40]
        name = s[:8].rstrip(b'\0').decode(errors='replace')
        vsz, va, rsz, rp = struct.unpack_from('<IIII', s, 8)
        chars = struct.unpack_from('<I', s, 36)[0]
        if rsz:
            secs.append((name, va, vsz, rp, rsz, chars))
    blob = open(path, 'rb').read()

    auto_mode, auto_targets = detect_layout(secs)
    if not mode or mode == 'auto':
        mode = auto_mode
    if not tgt_sec_filter and mode == 'stub-target' and auto_targets:
        tgt_sec_filter = auto_targets
    if verbose:
        print(f'[vmscan] layout mode={mode} target-sections={tgt_sec_filter}', file=sys.stderr)

    def section_of(rva):
        for name, va, vsz, rp, rsz, ch in secs:
            if va <= rva < va + max(vsz, rsz):
                return name, va, rp, rsz, ch
        return None

    def exec_sec(rva):
        s = section_of(rva)
        if s and (s[4] & 0x20000000):
            return s
        return None

    hits = []
    if mode in ('raw', 'stub-target'):
        # Shape scan: `68 <imm32> (E8|E9) <rel32>` — keep hits whose branch
        # lands in an executable section (stub-target additionally requires a
        # packer-section target via the filter below). The zero-width
        # lookahead makes matches overlap-safe: a plain finditer would skip a
        # stub starting inside the span of the previous match (real loss on
        # dense packer sections).
        for name, va, vsz, rp, rsz, ch in secs:
            if not (ch & 0x20000000) or not rsz:
                continue
            text = blob[rp:rp+rsz]
            for m in re.finditer(rb'(?=\x68(....)([\xe8\xe9])(....))', text, re.DOTALL):
                off = m.start()
                imm = struct.unpack('<I', m.group(1))[0]
                rel = struct.unpack('<i', m.group(3))[0]
                tgt = (va + off + 5 + 5 + rel) & 0xFFFFFFFF   # end of the 10-byte stub
                stub_rva = va + off
                ts = exec_sec(tgt)
                if ts:
                    hits.append((stub_rva, imm, tgt, name, ts[0]))
    else:
        # cross-branch: E8/E9 jumping into a DIFFERENT executable section and
        # landing on `68 <imm32> E8 <rel32>` — mirrors the engine's classic
        # discovery rule, so the output is the set the engine would lift.
        # Overlap-safe for the same reason as above (the engine scans
        # byte-by-byte; every position must be tested).
        for name, va, vsz, rp, rsz, ch in secs:
            if not (ch & 0x20000000) or not rsz:
                continue
            text = blob[rp:rp+rsz]
            for m in re.finditer(rb'(?=[\xe8\xe9](....))', text, re.DOTALL):
                off = m.start()
                rel = struct.unpack('<i', text[off+1:off+5])[0]
                tgt = (va + off + 5 + rel) & 0xFFFFFFFF
                ts = exec_sec(tgt)
                if not ts or ts[0] == name:
                    continue
                tva, trp = ts[1], ts[2]
                toff = tgt - tva
                stub = blob[trp+toff:trp+toff+6]
                if len(stub) == 6 and stub[0] == 0x68 and stub[5] == 0xE8:
                    imm = struct.unpack('<I', stub[1:5])[0]
                    hits.append((tgt, imm, tgt, name, ts[0]))
    # dedup & sort
    seen, out = set(), []
    for h in sorted(hits):
        if h[0] in seen: continue
        seen.add(h[0]); out.append(h)
    if tgt_sec_filter:
        tgt_set = set(tgt_sec_filter) if isinstance(tgt_sec_filter, (list, tuple)) else {tgt_sec_filter}
        out = [h for h in out if h[4] in tgt_set]
    if verbose:
        for stub_rva, imm, tgt, sec, tsec in out:
            print(f'{stub_rva:#010x}  push {imm:#010x} -> {tgt:#010x} [{tsec}] (found in {sec})', file=sys.stderr)
        from collections import Counter
        by_tgt = Counter(h[4] for h in out)
        print(f'[vmscan] {len(out)} candidate vmenters (mode={mode}, filtered={tgt_sec_filter})', file=sys.stderr)
        for name, cnt in by_tgt.most_common():
            print(f'[vmscan]   target section {name:12s} {cnt}', file=sys.stderr)
    for stub_rva, *_ in out:
        print(f'{stub_rva:#x}')

if __name__ == '__main__':
    main()
