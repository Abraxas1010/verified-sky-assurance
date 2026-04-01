#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from assurance.attestation import verify_attestation
from assurance.models import Bundle, ObligationResult


def main() -> int:
    if len(sys.argv) != 4:
        print("Usage: verify_attestation.py <attestation.json> <bundle.json> <results.json>", file=sys.stderr)
        return 2
    attestation = json.loads(Path(sys.argv[1]).read_text())
    bundle = Bundle.from_dict(json.loads(Path(sys.argv[2]).read_text()))
    results = [ObligationResult(**item) for item in json.loads(Path(sys.argv[3]).read_text())]
    ok = verify_attestation(attestation, bundle, results)
    print("VALID" if ok else "INVALID")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
