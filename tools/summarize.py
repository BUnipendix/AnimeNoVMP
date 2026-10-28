#!/usr/bin/env python3
"""Summarize batch devirtualization runs and diff them against baselines.

A batch run (run_all.sh or novmp-run) writes one JSONL result per entry plus a
summary.tsv. This tool renders class histograms and, when baselines are given,
audits the diff between runs:

- conversions  : baseline failure -> ok (good)
- regressions  : baseline ok     -> failure (must investigate)
- ins changes  : both ok but instruction counts differ, split into
  * premature-level : the *unoptimized* count changed — the lift itself
    produced different code (semantic face; investigate)
  * optimized-only  : only the optimized count changed — the optimizer ran
    longer/shorter under load (noise face; usually benign)

Two methodology notes baked in from production runs:
- .vtil output files are NOT byte-deterministic across runs (serialized UIDs
  derive from pointers), so quality comparison must use the JSONL ins/blocks
  vectors, never file hashes.
- a routine whose whole walk fits in the budget produces a stable premature
  count; only the optimized count is sensitive to machine load.

usage:
  summarize.py OUT_DIR [OUT_DIR ...] [--baseline DIR]...
"""
import argparse
import glob
import json
import os
import sys


def classify(result: dict) -> str:
    if result.get("status") == "ok":
        return "ok"
    return result.get("class", "?")


def load_dir(outdir: str) -> dict:
    results = {}
    for f in glob.glob(os.path.join(outdir, "*.jsonl")):
        rva = os.path.basename(f)[:-6]
        try:
            with open(f) as fh:
                results[rva.lower()] = json.load(fh)
        except (json.JSONDecodeError, OSError):
            results[rva.lower()] = {"status": "error", "class": "unreadable"}
    return results


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Summarize batch runs and audit diffs against baselines.")
    ap.add_argument("outdir", nargs="+", help="batch output dir(s) (contain *.jsonl)")
    ap.add_argument("--baseline", action="append", default=[],
                    metavar="DIR", help="baseline output dir to diff against (repeatable)")
    args = ap.parse_args()

    baselines = {}
    for bdir in args.baseline:
        baselines.update(load_dir(bdir))

    rc = 0
    for outdir in args.outdir:
        results = load_dir(outdir)
        if not results:
            print(f"{outdir}: no results found", file=sys.stderr)
            rc = 1
            continue

        hist: dict = {}
        for r in results.values():
            c = classify(r)
            hist[c] = hist.get(c, 0) + 1
        n = sum(hist.values())
        ok = hist.get("ok", 0)
        parts = "  ".join(f"{c}={k}" for c, k in sorted(hist.items()) if c != "ok")
        print(f"{outdir}: {ok}/{n} ok ({100.0 * ok / n:.1f}%)" + (f"  {parts}" if parts else ""))

        if not baselines:
            continue

        conversions, regressions, prem, opt = [], [], [], []
        for rva, new in sorted(results.items()):
            base = baselines.get(rva)
            if base is None:
                continue
            nc, bc = classify(new), classify(base)
            if bc != "ok" and nc == "ok":
                conversions.append((rva, bc))
            elif bc == "ok" and nc != "ok":
                regressions.append((rva, nc))
            elif bc == "ok" and nc == "ok":
                bi, ni = base.get("ins"), new.get("ins")
                if bi and ni and bi != ni:
                    if bi[0] != ni[0]:
                        prem.append((rva, bi, ni))
                    else:
                        opt.append(rva)

        for rva, bc in conversions:
            print(f"  converted   {rva}: {bc} -> ok")
        for rva, nc in regressions:
            print(f"  REGRESSION  {rva}: ok -> {nc}")
        for rva, bi, ni in prem:
            print(f"  ins(pre)    {rva}: {bi} -> {ni}")
        if opt:
            print(f"  ins(opt)    {len(opt)} optimizer-noise entries: {' '.join(opt)}")

        if regressions:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
