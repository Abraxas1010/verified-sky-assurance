"""Reference SKY reducer — same algorithm as the open-source sky-proof-checker.

This is the canonical reducer used by the service. It MUST produce identical
results to all four open-source implementations (Python, Rust, TypeScript, Go).
"""
from __future__ import annotations

from typing import Any

from assurance.models import Obligation, ObligationResult, Bundle


# ── Combinator reduction (identical to sky-proof-checker/python/sky_checker.py)

def _is_app(c: Any) -> bool:
    return isinstance(c, list) and len(c) == 3 and c[0] == "app"


def _app(f: Any, a: Any) -> list:
    return ["app", f, a]


def step(c: Any) -> Any | None:
    """One leftmost-outermost SKY reduction step. Returns None if normal form."""
    if not _is_app(c):
        return None
    f, a = c[1], c[2]
    if f == "Y":
        return _app(a, _app("Y", a))
    if _is_app(f):
        ff, fa = f[1], f[2]
        if ff == "K":
            return fa
        if _is_app(ff):
            fff, ffa = ff[1], ff[2]
            if fff == "S":
                return _app(_app(ffa, a), _app(fa, a))
            r = step(ff)
            if r is not None:
                return _app(_app(r, fa), a)
            r = step(f)
            if r is not None:
                return _app(r, a)
            return None
        r = step(f)
        if r is not None:
            return _app(r, a)
        return None
    r = step(f)
    if r is not None:
        return _app(r, a)
    return None


def reduce(c: Any, fuel: int) -> tuple[Any, int]:
    """Reduce for up to fuel steps. Returns (result, steps_used)."""
    for i in range(fuel):
        c2 = step(c)
        if c2 is None:
            return c, i
        c = c2
    return c, fuel


def reduce_with_trace(c: Any, fuel: int) -> tuple[Any, int, list[dict]]:
    """Reduce with trace recording for STARK attestation.

    Returns (result, steps_used, trace) where trace is a list of
    {step, rule, term_hash_before, term_hash_after} dicts.
    """
    import hashlib, json
    trace: list[dict] = []
    for i in range(fuel):
        before_hash = hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()[:16]
        c2 = step(c)
        if c2 is None:
            trace.append({"step": i, "rule": "HALT", "hash": before_hash})
            return c, i, trace
        # Determine which rule fired
        rule = _identify_rule(c)
        after_hash = hashlib.sha256(json.dumps(c2, sort_keys=True).encode()).hexdigest()[:16]
        trace.append({
            "step": i, "rule": rule,
            "hash_before": before_hash, "hash_after": after_hash,
        })
        c = c2
    return c, fuel, trace


def _identify_rule(c: Any) -> str:
    """Identify which rule would fire on this term."""
    if not _is_app(c):
        return "HALT"
    f, a = c[1], c[2]
    if f == "Y":
        return "Y"
    if _is_app(f):
        ff, fa = f[1], f[2]
        if ff == "K":
            return "K"
        if _is_app(ff) and ff[1] == "S":
            return "S"
    return "REDUCE"


def decode_bool(c: Any) -> bool | None:
    """Decode Church boolean: K = true, K (S K K) = false."""
    if c == "K":
        return True
    if _is_app(c) and _is_app(c[1]) and c[1][1] == "K" and c[1][2] == "S" and c[2] == "K":
        return False
    if _is_app(c) and c[1] == "K":
        i = c[2]
        if _is_app(i) and _is_app(i[1]) and i[1][1] == "S" and i[1][2] == "K" and i[2] == "K":
            return False
    return None


# ── Bundle verification ──────────────────────────────────────────────

def verify_obligation(ob: Obligation) -> ObligationResult:
    """Verify a single obligation."""
    if ob.compiled_check is None:
        return ObligationResult(id=ob.id, checked=False, error="no compiled_check")
    result, steps = reduce(ob.compiled_check, ob.fuel)
    decoded = decode_bool(result)
    ok = (ob.expected_result == "true" and decoded is True) or \
         (ob.expected_result == "false" and decoded is False)
    return ObligationResult(
        id=ob.id, checked=ok, steps_used=steps, decoded=decoded,
    )


def verify_bundle(bundle: Bundle) -> tuple[bool, list[ObligationResult]]:
    """Verify all obligations in a bundle. Returns (all_ok, results)."""
    results = [verify_obligation(ob) for ob in bundle.obligations]
    all_ok = all(r.checked for r in results) and len(results) > 0
    return all_ok, results
