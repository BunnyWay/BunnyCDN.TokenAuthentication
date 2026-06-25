#!/usr/bin/env python3
"""Assert every signer's emitted tokens match the reference e2e/vectors.json.

Each language's CI job runs its emitter (signing the shared e2e/inputs.json
cases) and produces a JSON object {name: token}. This compares each of those to
the committed vectors.json (the reference produced by gen_vectors.py). If any
SDK drifts, its tokens won't match and CI fails.

Usage:  python e2e/compare_vectors.py tokens-go.json tokens-node.json ...
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv):
    if not argv:
        print("usage: compare_vectors.py <emit1.json> [emit2.json ...]", file=sys.stderr)
        return 2

    vectors = load(os.path.join(HERE, "vectors.json"))
    expected = {v["name"]: v["token"] for v in vectors["vectors"]}
    signable = [c["name"] for c in load(os.path.join(HERE, "inputs.json"))["cases"]]

    total_fail = 0
    for path in argv:
        lang = os.path.basename(path).replace("tokens-", "").replace(".json", "")
        emit = load(path)
        fails = []
        for name in signable:
            if name not in emit:
                fails.append(f"{name}: MISSING from {lang} output")
            elif emit[name] != expected[name]:
                fails.append(f"{name}: {lang}={emit[name]!r} != canonical={expected[name]!r}")
        extra = set(emit) - set(signable)
        if extra:
            fails.append(f"unexpected names from {lang}: {sorted(extra)}")

        if fails:
            total_fail += len(fails)
            print(f"FAIL {lang}:")
            for m in fails:
                print("   " + m)
        else:
            print(f"ok   {lang}: all {len(signable)} tokens match canonical vectors.json")

    print(f"\ncompare_vectors: {len(argv)} signer(s) checked, {total_fail} mismatch(es)")
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
