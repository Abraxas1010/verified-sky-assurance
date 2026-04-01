#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

PATTERNS = {
    "testBatchVerifyMixedResults": 8_500_000,
    "testPositiveFixtureVerifiesAndRegisters": 7_000_000,
    "testRejectsMismatchedBundleHashBinding": 2_250_000,
    "testRejectsNonTranscriptQueryPosition": 2_250_000,
    "testRejectsTamperedFRIFold": 2_250_000,
    "testRejectsTamperedFinalConstant": 2_250_000,
}


def main() -> int:
    result = subprocess.run(
        ["forge", "test", "--match-contract", "SKYPositiveFixtureTest"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode

    output = result.stdout + "\n" + result.stderr
    seen: dict[str, int] = {}
    for name, budget in PATTERNS.items():
        match = re.search(rf"\[PASS\]\s+{re.escape(name)}\(\)\s+\(gas:\s+(\d+)\)", output)
        if not match:
            print(f"missing gas report for {name}")
            return 1
        gas = int(match.group(1))
        seen[name] = gas
        if gas > budget:
            print(f"gas budget exceeded for {name}: {gas} > {budget}")
            return 1

    print("Gas budgets OK")
    for name, gas in seen.items():
        print(f"  {name}: {gas}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
