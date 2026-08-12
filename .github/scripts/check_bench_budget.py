#!/usr/bin/env python3
"""Enforce the hard-fail performance budgets in docs/10-PERF-BUDGET.md.

docs/10 states the budgets are enforced rather than aspirational, and gives
both a target and a hard-fail figure for each. Only the hard-fail figures are
gated here: a GitHub runner is not the reference machine in docs/10 (an
i7-14700KF with NVMe), so failing a build on the target figure would be
measuring the runner rather than the code.

Criterion writes `target/criterion/<group>/<bench>/new/estimates.json`, with
`mean.point_estimate` in nanoseconds.
"""

from __future__ import annotations

import json
import pathlib
import sys

NS_PER_MS = 1_000_000

# (criterion group, criterion bench) -> budget, in milliseconds.
#
# docs/10: "Catalog load + automaton build | < 50 ms | 250 ms".  The two are
# measured separately here and share one budget, so each is checked against the
# whole and their sum is checked as well.
COMBINED_BUDGET_MS = 250.0
COMBINED: list[tuple[str, str]] = [
    ("catalog_parse", "example_catalog"),
    ("automaton_build", "aho_corasick"),
]

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRITERION = ROOT / "target" / "criterion"


def mean_ms(group: str, bench: str) -> float:
    estimates = CRITERION / group / bench / "new" / "estimates.json"
    if not estimates.is_file():
        raise SystemExit(
            f"::error::no criterion estimates at {estimates.relative_to(ROOT)} — "
            "did `cargo bench --bench scan_corpus` run?"
        )
    with estimates.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return float(data["mean"]["point_estimate"]) / NS_PER_MS


def main() -> int:
    total = 0.0
    failed = False

    for group, bench in COMBINED:
        measured = mean_ms(group, bench)
        total += measured
        status = "ok" if measured <= COMBINED_BUDGET_MS else "OVER BUDGET"
        print(f"{group}/{bench}: {measured:.3f} ms (hard fail {COMBINED_BUDGET_MS} ms) {status}")
        if measured > COMBINED_BUDGET_MS:
            failed = True
            print(
                f"::error::{group}/{bench} took {measured:.3f} ms, over the "
                f"{COMBINED_BUDGET_MS} ms hard-fail budget in docs/10-PERF-BUDGET.md"
            )

    print(f"catalog load + automaton build: {total:.3f} ms (hard fail {COMBINED_BUDGET_MS} ms)")
    if total > COMBINED_BUDGET_MS:
        failed = True
        print(
            f"::error::catalog load + automaton build took {total:.3f} ms, over the "
            f"{COMBINED_BUDGET_MS} ms hard-fail budget in docs/10-PERF-BUDGET.md"
        )

    # Regression detection is deliberately not a gate yet. Criterion compares
    # against a baseline in target/criterion, which does not survive between
    # runs, and a 15 % threshold on a shared runner would flake more often than
    # it would catch anything. The absolute budgets above hold in the meantime.
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
