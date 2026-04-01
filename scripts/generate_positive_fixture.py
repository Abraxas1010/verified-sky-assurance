#!/usr/bin/env python3
"""Generate a positive STARK fixture for local on-chain assurance tests."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
FIXTURES = ROOT / "test" / "fixtures"

sys.path.insert(0, str(ROOT))

from assurance.attestation import (
    _compute_bundle_binding_hash,
    generate_attestation,
    record_trace,
)
from assurance.models import Bundle, Obligation
from assurance.reducer import verify_bundle


def _hex_bytes32(value: str) -> str:
    return f"hex\"{value}\""


def _sol_bytes32_array(values: list[str], indent: str) -> str:
    lines = [f"{indent}bytes32[] memory arr = new bytes32[]({len(values)});"]
    for idx, value in enumerate(values):
        lines.append(f"{indent}arr[{idx}] = {_hex_bytes32(value)};")
    lines.append(f"{indent}return arr;")
    return "\n".join(lines)


def _emit_bytes32_array_fn(name: str, values: list[str]) -> str:
    return (
        f"    function {name}() private pure returns (bytes32[] memory) {{\n"
        f"{_sol_bytes32_array(values, '        ')}\n"
        "    }\n"
    )


def _emit_trace_openings(trace_openings: list[dict]) -> str:
    lines: list[str] = [
        "    function _traceOpenings() internal pure returns (SKYVerifier.QueryOpening[] memory traceOpenings) {",
        f"        traceOpenings = new SKYVerifier.QueryOpening[]({len(trace_openings)});",
    ]
    for idx, opening in enumerate(trace_openings):
        lines.extend(
            [
                "        {",
                f"            traceOpenings[{idx}] = SKYVerifier.QueryOpening({{",
                f"                stepVal: {opening['step_val']},",
                "                stepProof: " + f"_traceStepProof{idx}(),",
                f"                stepShiftedVal: {opening['step_shifted_val']},",
                "                stepShiftedProof: " + f"_traceStepShiftedProof{idx}(),",
                f"                stateVal: {opening['state_val']},",
                "                stateProof: " + f"_traceStateProof{idx}()",
                "            });",
                "        }",
            ]
        )
    lines.append("    }")
    return "\n".join(lines)


def _emit_fri_openings(fri_queries: list[list[dict]]) -> str:
    lines: list[str] = [
        "    function _friOpenings() internal pure returns (SKYVerifier.FRILayerOpening[][] memory friOpenings) {",
        f"        friOpenings = new SKYVerifier.FRILayerOpening[][]({len(fri_queries)});",
    ]
    for qi, query_layers in enumerate(fri_queries):
        lines.append(f"        friOpenings[{qi}] = new SKYVerifier.FRILayerOpening[]({len(query_layers)});")
        for li, layer in enumerate(query_layers):
            lines.extend(
                [
                    "        {",
                    f"            friOpenings[{qi}][{li}] = SKYVerifier.FRILayerOpening({{",
                    f"                pos: {layer['pos']},",
                    f"                val: {layer['val']},",
                    "                proof: " + f"_friProof_{qi}_{li}(),",
                    f"                sibPos: {layer['sib_pos']},",
                    f"                sibVal: {layer['sib_val']},",
                    "                sibProof: " + f"_friSibProof_{qi}_{li}()",
                    "            });",
                    "        }",
                ]
            )
    lines.append("    }")
    return "\n".join(lines)


def _emit_proof_fn(proof: dict, bundle_hash: str) -> str:
    fri_layer_info = proof["fri"]["layer_info"]
    lines = [
        "    function bundleHash() internal pure returns (bytes32) {",
        f"        return {_hex_bytes32(bundle_hash)};",
        "    }",
        "",
        "    function load()",
        "        internal",
        "        pure",
        "        returns (",
        "            SKYVerifier.STARKProof memory proof,",
        "            SKYVerifier.QueryOpening[] memory traceOpenings,",
        "            SKYVerifier.FRILayerOpening[][] memory friOpenings",
        "        )",
        "    {",
        f"        proof.bindingHash = {_hex_bytes32(proof['binding_hash'])};",
        f"        proof.stepTraceRoot = {_hex_bytes32(proof['trace_roots'][0])};",
        f"        proof.stateTraceRoot = {_hex_bytes32(proof['trace_roots'][1])};",
        f"        proof.traceLength = {proof['public']['trace_length']};",
        f"        proof.inputHash = {proof['public']['input_hash']};",
        f"        proof.outputHash = {proof['public']['output_hash']};",
        "        proof.friRoots = _friRoots();",
        f"        proof.friFinal = {proof['fri']['final']};",
        f"        proof.friLayerDomainSizes = new uint256[]({len(fri_layer_info)});",
        f"        proof.friLayerShifts = new uint256[]({len(fri_layer_info)});",
        f"        proof.friLayerOmegas = new uint256[]({len(fri_layer_info)});",
    ]
    for idx, (domain_size, shift, omega) in enumerate(fri_layer_info):
        lines.extend(
            [
                f"        proof.friLayerDomainSizes[{idx}] = {domain_size};",
                f"        proof.friLayerShifts[{idx}] = {shift};",
                f"        proof.friLayerOmegas[{idx}] = {omega};",
            ]
        )
    positions = proof["fri"]["positions"]
    lines.append(f"        proof.queryPositions = new uint256[]({len(positions)});")
    for idx, pos in enumerate(positions):
        lines.append(f"        proof.queryPositions[{idx}] = {pos};")
    lines.extend(
        [
            "        traceOpenings = _traceOpenings();",
            "        friOpenings = _friOpenings();",
            "    }",
        ]
    )
    return "\n".join(lines)


def generate_fixture_source(bundle_hash: str, proof: dict) -> str:
    helper_functions: list[str] = []
    for idx, opening in enumerate(proof["trace_openings"]):
        helper_functions.extend(
            [
                _emit_bytes32_array_fn(f"_traceStepProof{idx}", opening["step_proof"]),
                _emit_bytes32_array_fn(
                    f"_traceStepShiftedProof{idx}",
                    opening["step_shifted_proof"],
                ),
                _emit_bytes32_array_fn(f"_traceStateProof{idx}", opening["state_proof"]),
            ]
        )
    for qi, query_layers in enumerate(proof["fri"]["queries"]):
        for li, layer in enumerate(query_layers):
            helper_functions.extend(
                [
                    _emit_bytes32_array_fn(f"_friProof_{qi}_{li}", layer["proof"]),
                    _emit_bytes32_array_fn(f"_friSibProof_{qi}_{li}", layer["sib_proof"]),
                ]
            )
    helper_functions.append(_emit_bytes32_array_fn("_friRoots", proof["fri"]["roots"]))
    helper_functions.append(_emit_trace_openings(proof["trace_openings"]))
    helper_functions.append(_emit_fri_openings(proof["fri"]["queries"]))
    helper_functions.append(_emit_proof_fn(proof, bundle_hash))
    body = "\n\n".join(helper_functions)
    return f"""// SPDX-License-Identifier: LicenseRef-Apoth3osis-License-Stack-v1
pragma solidity ^0.8.20;

import "../../contracts/SKYVerifier.sol";

// Generated by scripts/generate_positive_fixture.py. Do not edit by hand.
library PositiveProofFixture {{
{body}
}}
"""


def main() -> int:
    os.environ["ENABLE_EXPERIMENTAL_ATTESTATION"] = "true"

    bundle = Bundle(
        source_hash="fixture-k-rule-demo",
        description="Positive fixture for end-to-end on-chain verification.",
        obligations=[
            Obligation(
                id="k_rule_demo",
                compiled_check=["app", ["app", "K", "K"], ["app", ["app", "S", "K"], "K"]],
                expected_result="true",
            )
        ],
    )
    _, results = verify_bundle(bundle)
    _, _, trace = record_trace(bundle.obligations[0].compiled_check, bundle.obligations[0].fuel)
    attestation = generate_attestation(bundle, results, [trace])
    payload = json.loads(base64.b64decode(attestation.proof))
    proof = payload["proofs"][0]

    bundle_dict = bundle.to_dict()
    bundle_hash = _compute_bundle_binding_hash(bundle)

    EXAMPLES.mkdir(parents=True, exist_ok=True)
    FIXTURES.mkdir(parents=True, exist_ok=True)
    (EXAMPLES / "positive_bundle.json").write_text(json.dumps(bundle_dict, indent=2, sort_keys=True) + "\n")
    (EXAMPLES / "positive_results.json").write_text(
        json.dumps([result.to_dict() for result in results], indent=2, sort_keys=True) + "\n"
    )
    (EXAMPLES / "positive_attestation.json").write_text(
        json.dumps(attestation.to_dict(), indent=2, sort_keys=True) + "\n"
    )
    (FIXTURES / "PositiveProofFixture.sol").write_text(generate_fixture_source(bundle_hash, proof))
    print("Generated positive fixture:")
    print(f"  bundle hash: {bundle_hash}")
    print(f"  solidity fixture: {FIXTURES / 'PositiveProofFixture.sol'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
