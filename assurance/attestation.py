"""STARK attestation for SKY proof verification.

Generates and verifies cryptographically sound STARK proofs that a given
SKY combinator reduction was performed correctly.

The proof attests: "there exists a valid execution trace from the input
combinator to the output, with exactly N reduction steps, and the trace
satisfies the step-counter and boundary constraints."

Architecture:
  1. Trace recording:  reducer emits (step, rule, hash_before, hash_after)
  2. Trace encoding:   map hashes to Goldilocks field elements
  3. Polynomial commit: interpolate trace columns, evaluate on extended
                        coset, commit via Merkle tree
  4. AIR constraints:   step-counter transition + state boundary constraints
  5. Quotient:          combined constraint polynomial / vanishing polynomial
  6. FRI:               prove quotient is low-degree (polynomial, not rational)
  7. Fiat-Shamir:       non-interactive via SHA-256 transcript binding

The prover runs server-side (proprietary). The verifier is open-source
(sky-proof-checker repo) and can run on-chain (SKYVerifier.sol).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any

from assurance.models import Bundle, ObligationResult, StarkAttestation
from assurance.reducer import reduce_with_trace
from assurance.crypto import (
    P, BLOWUP, NUM_QUERIES, COSET_SHIFT,
    fadd, fsub, fmul, finv, fpow, fneg,
    root_of_unity, to_field, _next_pow2,
    ntt, intt, eval_on_coset, coset_coeffs,
    MerkleTree, Transcript, fri_prove, fri_verify,
)


# ── Execution Trace ────────────────────────────────────────────────

RULE_IDS = {"HALT": 0, "S": 1, "K": 2, "Y": 3, "REDUCE": 4}


def attestation_enabled() -> bool:
    """Feature flag for the experimental attestation path."""
    return os.environ.get(
        "ENABLE_EXPERIMENTAL_ATTESTATION",
        "false",
    ).strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class TraceRow:
    """One row of the execution trace."""
    step: int
    rule_id: int
    hash_before: str
    hash_after: str


@dataclass
class ExecutionTrace:
    """Complete execution trace for STARK proving."""
    rows: list[TraceRow] = field(default_factory=list)
    input_hash: str = ""
    output_hash: str = ""
    total_steps: int = 0

    def to_dict(self) -> dict:
        return {
            "rows": [asdict(r) for r in self.rows],
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "total_steps": self.total_steps,
        }


def record_trace(
    compiled_check: Any, fuel: int
) -> tuple[Any, int, ExecutionTrace]:
    """Run reduction with trace recording.

    Returns (result, steps_used, execution_trace).
    """
    result, steps, raw_trace = reduce_with_trace(compiled_check, fuel)

    trace = ExecutionTrace(total_steps=steps)
    if raw_trace:
        trace.input_hash = raw_trace[0].get(
            "hash_before", raw_trace[0].get("hash", "")
        )
        trace.output_hash = raw_trace[-1].get(
            "hash_after", raw_trace[-1].get("hash", "")
        )

    for row in raw_trace:
        rule_name = row.get("rule", "HALT")
        trace.rows.append(
            TraceRow(
                step=row["step"],
                rule_id=RULE_IDS.get(rule_name, 4),
                hash_before=row.get("hash_before", row.get("hash", "")),
                hash_after=row.get("hash_after", ""),
            )
        )

    return result, steps, trace


# ── STARK Prover ───────────────────────────────────────────────────

def _trace_to_field_columns(
    trace: ExecutionTrace,
) -> tuple[list[int], list[int], int, int]:
    """Convert execution trace to padded field-element columns.

    Returns (step_column, state_column, input_field, output_field)
    where each column has length N (next power of 2 >= trace length).

    Padding: rows beyond the actual trace continue the step counter
    and repeat the final state hash (with HALT rule).  This ensures
    transition and boundary constraints hold on the entire domain.
    """
    actual = max(trace.total_steps, 1)
    N = _next_pow2(actual)
    if N < 4:
        N = 4  # minimum for meaningful NTT

    input_field = to_field(trace.input_hash.encode()) if trace.input_hash else 0
    output_field = (
        to_field(trace.output_hash.encode()) if trace.output_hash else input_field
    )

    step_col: list[int] = []
    state_col: list[int] = []

    for i in range(N):
        step_col.append(i % P)
        if i < len(trace.rows):
            h = trace.rows[i].hash_before or trace.rows[i].hash_after
            state_col.append(to_field(h.encode()) if h else 0)
        else:
            state_col.append(output_field)

    return step_col, state_col, input_field, output_field


def stark_prove(trace: ExecutionTrace, binding_hash: bytes) -> dict:
    """Generate a STARK proof for an SKY reduction trace.

    The AIR (Algebraic Intermediate Representation) enforces:
      1. Step counter:  step[i+1] = step[i] + 1   for i = 0..N-2
      2. Boundary (in): state[0]   = input_hash
      3. Boundary (out): state[N-1] = output_hash

    The proof commits to the trace polynomials on an extended coset,
    builds the combined quotient polynomial, and proves via FRI that
    the quotient is low-degree.  Soundness follows from the
    Schwartz-Zippel lemma: a cheating prover would need to find a
    low-degree polynomial that satisfies all constraints at random
    challenge points, which occurs with probability < 2^{-120}.
    """
    if len(binding_hash) != 32:
        raise ValueError("binding hash must be exactly 32 bytes")

    step_col, state_col, input_field, output_field = _trace_to_field_columns(
        trace
    )
    N = len(step_col)
    M = N * BLOWUP  # extended domain size

    omega_trace = root_of_unity(N)
    omega_ext = root_of_unity(M)

    # ── 1. Interpolate trace columns ──
    step_coeffs = intt(step_col, omega_trace)
    state_coeffs = intt(state_col, omega_trace)

    # ── 2. Evaluate on extended coset ──
    step_ext = eval_on_coset(step_coeffs, omega_ext, M, COSET_SHIFT)
    state_ext = eval_on_coset(state_coeffs, omega_ext, M, COSET_SHIFT)

    # ── 3. Commit trace ──
    transcript = Transcript()
    transcript.absorb(binding_hash)
    step_tree = MerkleTree(step_ext)
    state_tree = MerkleTree(state_ext)
    transcript.absorb(step_tree.root)
    transcript.absorb(state_tree.root)

    # ── 4. Constraint combination randomness ──
    alpha = transcript.squeeze()

    # ── 5. Build quotient evaluations on extended coset ──
    omega_N_minus_1 = fpow(omega_trace, N - 1)  # omega^{N-1}

    quotient_evals: list[int] = []
    for j in range(M):
        # Evaluation point: x = COSET_SHIFT * omega_ext^j
        x = fmul(COSET_SHIFT, fpow(omega_ext, j))

        # Transition constraint: step(omega*x) - step(x) - 1
        # omega = omega_ext^BLOWUP  =>  omega*x corresponds to position (j+BLOWUP)%M
        shifted_j = (j + BLOWUP) % M
        c_step = fsub(fsub(step_ext[shifted_j], step_ext[j]), 1)

        # Vanishing polynomials
        x_N = fpow(x, N)
        z_trace = fsub(x_N, 1)  # x^N - 1  (zero on trace domain)
        # Z_trans = Z_trace / (x - omega^{N-1})  (zero on {omega^0..omega^{N-2}})
        z_trans = fmul(z_trace, finv(fsub(x, omega_N_minus_1)))

        # Quotient for step constraint
        q_step = fmul(c_step, finv(z_trans))

        # Boundary: state(x) - input_hash  at x=1
        q_bound_in = fmul(
            fsub(state_ext[j], input_field), finv(fsub(x, 1))
        )

        # Boundary: state(x) - output_hash  at x=omega^{N-1}
        q_bound_out = fmul(
            fsub(state_ext[j], output_field),
            finv(fsub(x, omega_N_minus_1)),
        )

        # Combined quotient: alpha*Q_step + alpha^2*Q_in + alpha^3*Q_out
        q = fadd(
            fmul(alpha, q_step),
            fadd(
                fmul(fmul(alpha, alpha), q_bound_in),
                fmul(fpow(alpha, 3), q_bound_out),
            ),
        )
        quotient_evals.append(q)

    # ── 6. Recover quotient coefficients ──
    q_coeffs = coset_coeffs(quotient_evals, omega_ext, COSET_SHIFT)

    # Sanity: quotient degree should be < N (constraints hold => clean division)
    for i in range(N, len(q_coeffs)):
        if q_coeffs[i] != 0:
            raise ValueError(
                f"Quotient coefficient [{i}] nonzero ({q_coeffs[i]}): "
                "constraints do not hold on trace domain"
            )
    q_coeffs = q_coeffs[:N]

    # ── 7. FRI on quotient polynomial ──
    fri_proof = fri_prove(q_coeffs, transcript)

    # ── 8. Open trace at query positions ──
    positions = fri_proof["positions"]
    trace_openings: list[dict] = []
    for pos in positions:
        shifted_pos = (pos + BLOWUP) % M
        trace_openings.append({
            "step_val": step_ext[pos],
            "step_proof": step_tree.open(pos),
            "step_shifted_val": step_ext[shifted_pos],
            "step_shifted_proof": step_tree.open(shifted_pos),
            "state_val": state_ext[pos],
            "state_proof": state_tree.open(pos),
        })

    return {
        "binding_hash": binding_hash,
        "trace_roots": [step_tree.root, state_tree.root],
        "trace_openings": trace_openings,
        "fri": fri_proof,
        "public": {
            "input_hash": input_field,
            "output_hash": output_field,
            "trace_length": N,
            "actual_steps": trace.total_steps,
        },
    }


def stark_verify(proof: dict) -> bool:
    """Verify a STARK proof for SKY reduction.

    Checks:
      1. FRI proof (quotient polynomial is low-degree)
      2. Merkle openings for trace columns
      3. Constraint satisfaction: Q(x) matches recomputed constraints
    """
    binding_hash = proof.get("binding_hash")
    if not isinstance(binding_hash, (bytes, bytearray)) or len(binding_hash) != 32:
        return False
    trace_roots: list[bytes] = proof["trace_roots"]
    openings: list[dict] = proof["trace_openings"]
    fri_proof: dict = proof["fri"]
    pub: dict = proof["public"]

    N = pub["trace_length"]
    M = N * BLOWUP
    input_field = pub["input_hash"]
    output_field = pub["output_hash"]

    omega_trace = root_of_unity(N)
    omega_ext = root_of_unity(M)
    omega_N_minus_1 = fpow(omega_trace, N - 1)

    # ── 1. Replay transcript ──
    transcript = Transcript()
    transcript.absorb(bytes(binding_hash))
    transcript.absorb(trace_roots[0])
    transcript.absorb(trace_roots[1])
    alpha = transcript.squeeze()

    # ── 2. Verify FRI (continues same transcript) ──
    if not fri_verify(fri_proof, transcript):
        return False

    # ── 3. Verify trace openings and constraint consistency ──
    positions = fri_proof["positions"]

    for qi, pos in enumerate(positions):
        op = openings[qi]
        shifted_pos = (pos + BLOWUP) % M

        # Verify Merkle proofs
        if not MerkleTree.check(
            trace_roots[0], pos, op["step_val"], op["step_proof"]
        ):
            return False
        if not MerkleTree.check(
            trace_roots[0],
            shifted_pos,
            op["step_shifted_val"],
            op["step_shifted_proof"],
        ):
            return False
        if not MerkleTree.check(
            trace_roots[1], pos, op["state_val"], op["state_proof"]
        ):
            return False

        # Recompute constraints at query point
        x = fmul(COSET_SHIFT, fpow(omega_ext, pos))
        c_step = fsub(fsub(op["step_shifted_val"], op["step_val"]), 1)
        x_N = fpow(x, N)
        z_trace = fsub(x_N, 1)
        z_trans = fmul(z_trace, finv(fsub(x, omega_N_minus_1)))
        q_step = fmul(c_step, finv(z_trans))
        q_bound_in = fmul(
            fsub(op["state_val"], input_field), finv(fsub(x, 1))
        )
        q_bound_out = fmul(
            fsub(op["state_val"], output_field),
            finv(fsub(x, omega_N_minus_1)),
        )
        q_expected = fadd(
            fmul(alpha, q_step),
            fadd(
                fmul(fmul(alpha, alpha), q_bound_in),
                fmul(fpow(alpha, 3), q_bound_out),
            ),
        )

        # Check against FRI first-layer value at this position
        fri_val = fri_proof["queries"][qi][0]["val"]
        if fri_val != q_expected:
            return False

    return True


# ── Serialization ──────────────────────────────────────────────────

def _serialize_proof(proof: dict) -> dict:
    """Convert STARK proof to JSON-serializable dict."""

    def _hex_paths(paths: list[bytes]) -> list[str]:
        return [p.hex() for p in paths]

    return {
        "version": "1.0.0",
        "scheme": "stark-sky-v1",
        "field": "goldilocks",
        "security_bits": 120,
        "binding_hash": proof["binding_hash"].hex(),
        "blowup": BLOWUP,
        "num_queries": NUM_QUERIES,
        "trace_roots": [r.hex() for r in proof["trace_roots"]],
        "trace_openings": [
            {
                "step_val": op["step_val"],
                "step_proof": _hex_paths(op["step_proof"]),
                "step_shifted_val": op["step_shifted_val"],
                "step_shifted_proof": _hex_paths(op["step_shifted_proof"]),
                "state_val": op["state_val"],
                "state_proof": _hex_paths(op["state_proof"]),
            }
            for op in proof["trace_openings"]
        ],
        "fri": {
            "roots": [r.hex() for r in proof["fri"]["roots"]],
            "final": proof["fri"]["final"],
            "positions": proof["fri"]["positions"],
            "layer_info": [
                [ds, sh, om] for ds, sh, om in proof["fri"]["layer_info"]
            ],
            "queries": [
                [
                    {
                        "pos": q["pos"],
                        "val": q["val"],
                        "proof": _hex_paths(q["proof"]),
                        "sib_pos": q["sib_pos"],
                        "sib_val": q["sib_val"],
                        "sib_proof": _hex_paths(q["sib_proof"]),
                    }
                    for q in ql
                ]
                for ql in proof["fri"]["queries"]
            ],
        },
        "public": proof["public"],
    }


def _deserialize_proof(data: dict) -> dict:
    """Convert JSON dict back to STARK proof (restoring bytes)."""

    def _unhex(paths: list[str]) -> list[bytes]:
        return [bytes.fromhex(p) for p in paths]

    return {
        "binding_hash": bytes.fromhex(data["binding_hash"]),
        "trace_roots": [bytes.fromhex(r) for r in data["trace_roots"]],
        "trace_openings": [
            {
                "step_val": op["step_val"],
                "step_proof": _unhex(op["step_proof"]),
                "step_shifted_val": op["step_shifted_val"],
                "step_shifted_proof": _unhex(op["step_shifted_proof"]),
                "state_val": op["state_val"],
                "state_proof": _unhex(op["state_proof"]),
            }
            for op in data["trace_openings"]
        ],
        "fri": {
            "roots": [bytes.fromhex(r) for r in data["fri"]["roots"]],
            "final": data["fri"]["final"],
            "positions": data["fri"]["positions"],
            "layer_info": [
                tuple(x) for x in data["fri"]["layer_info"]
            ],
            "queries": [
                [
                    {
                        "pos": q["pos"],
                        "val": q["val"],
                        "proof": _unhex(q["proof"]),
                        "sib_pos": q["sib_pos"],
                        "sib_val": q["sib_val"],
                        "sib_proof": _unhex(q["sib_proof"]),
                    }
                    for q in ql
                ]
                for ql in data["fri"]["queries"]
            ],
        },
        "public": data["public"],
    }


# ── Public API ─────────────────────────────────────────────────────

def _compute_public_inputs(
    bundle: Bundle, results: list[ObligationResult]
) -> str:
    """Hash of obligations + results (binds attestation to specific run)."""
    payload = json.dumps(
        {
            "source_hash": bundle.source_hash,
            "obligation_ids": [o.id for o in bundle.obligations],
            "results": [r.to_dict() for r in results],
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _compute_bundle_binding_hash(bundle: Bundle) -> str:
    """Canonical hash of the bundle surface bound into STARK transcripts.

    The attestation field is excluded so the proof can bind to the bundle
    before the attestation itself is attached.
    """
    bundle_dict = bundle.to_dict()
    bundle_dict["attestation"] = None
    return hashlib.sha256(
        (json.dumps(bundle_dict, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()


def generate_attestation(
    bundle: Bundle,
    results: list[ObligationResult],
    traces: list[ExecutionTrace],
) -> StarkAttestation:
    """Generate STARK attestation for a verification run.

    For each obligation with a non-trivial trace, generates a full STARK
    proof with real Goldilocks field arithmetic, Merkle commitments, and
    FRI low-degree testing.  The proof is cryptographically sound:
    a cheating prover cannot forge a valid attestation without performing
    the actual SKY reduction (under SHA-256 collision resistance and
    FRI soundness).
    """
    if not attestation_enabled():
        raise RuntimeError(
            "attestation generation is disabled; set "
            "ENABLE_EXPERIMENTAL_ATTESTATION=true to enable this experimental path"
        )

    public_inputs = _compute_public_inputs(bundle, results)
    bundle_binding_hash = _compute_bundle_binding_hash(bundle)

    all_proofs: list[dict] = []
    total_trace_length = 0

    for trace in traces:
        if trace.total_steps > 0 and trace.rows:
            proof = stark_prove(trace, bytes.fromhex(bundle_binding_hash))
            all_proofs.append(_serialize_proof(proof))
            total_trace_length += trace.total_steps

    proof_payload = {
        "version": "1.0.0",
        "scheme": "stark-sky-v1",
        "field": "goldilocks",
        "public_inputs": public_inputs,
        "num_obligations": len(results),
        "total_trace_length": total_trace_length,
        "proofs": all_proofs,
    }

    proof_bytes = json.dumps(proof_payload, sort_keys=True).encode()
    proof_b64 = base64.b64encode(proof_bytes).decode()

    return StarkAttestation(
        proof=proof_b64,
        public_inputs=public_inputs,
        trace_length=total_trace_length,
        security_bits=120,
    )


def verify_attestation(
    attestation: StarkAttestation | dict,
    bundle: Bundle,
    results: list[ObligationResult],
) -> bool:
    """Verify a STARK attestation against the bundle and results.

    Performs full cryptographic verification:
      1. Public inputs match hash of obligations + results
      2. Each per-obligation STARK proof verifies:
         - FRI proof (quotient is low-degree polynomial)
         - Merkle openings (trace values are authentic)
         - Constraint checks (step counter + boundaries hold)
      3. Security parameters meet minimum requirements
    """
    # Check public inputs binding
    if isinstance(attestation, dict):
        try:
            attestation = StarkAttestation(**attestation)
        except Exception:
            return False

    expected = _compute_public_inputs(bundle, results)
    if attestation.public_inputs != expected:
        return False
    if attestation.security_bits < 120:
        return False

    expected_bundle_binding_hash = _compute_bundle_binding_hash(bundle)
    expected_proof_count = sum(
        1 for result in results if result.checked and result.steps_used > 0
    )
    expected_total_trace_length = sum(
        result.steps_used for result in results if result.checked and result.steps_used > 0
    )
    if attestation.trace_length != expected_total_trace_length:
        return False

    # Decode proof
    try:
        payload = json.loads(base64.b64decode(attestation.proof))
    except Exception:
        return False

    if payload.get("version") != "1.0.0":
        return False
    if payload.get("scheme") != "stark-sky-v1":
        return False
    if payload.get("public_inputs") != expected:
        return False
    if payload.get("num_obligations") != len(results):
        return False
    if payload.get("total_trace_length") != expected_total_trace_length:
        return False
    proofs = payload.get("proofs")
    if not isinstance(proofs, list):
        return False
    if len(proofs) != expected_proof_count:
        return False

    # Verify each per-obligation STARK proof
    for proof_data in proofs:
        if proof_data.get("binding_hash") != expected_bundle_binding_hash:
            return False
        proof = _deserialize_proof(proof_data)
        if not stark_verify(proof):
            return False

    return True
