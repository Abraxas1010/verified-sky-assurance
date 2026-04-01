#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from assurance.attestation import generate_attestation, record_trace, verify_attestation
from assurance.models import Bundle, Obligation, ObligationResult
from assurance.reducer import verify_bundle

ROOT = Path(__file__).resolve().parent.parent


class AssuranceTests(unittest.TestCase):
    POSITIVE_CORPUS = [
        (
            "trivial_true",
            "K",
        ),
        (
            "identity_combinator",
            ["app", ["app", ["app", "S", "K"], "K"], "K"],
        ),
        (
            "k_rule_demo",
            ["app", ["app", "K", "K"], ["app", ["app", "S", "K"], "K"]],
        ),
    ]

    def _load_positive_fixture(self):
        bundle = Bundle.from_dict(json.loads((ROOT / "examples" / "positive_bundle.json").read_text()))
        results = [
            ObligationResult(**item)
            for item in json.loads((ROOT / "examples" / "positive_results.json").read_text())
        ]
        attestation = json.loads((ROOT / "examples" / "positive_attestation.json").read_text())
        return bundle, results, attestation

    def test_docs_and_contracts_exist(self):
        for path in [
            ROOT / "docs" / "security_model.md",
            ROOT / "docs" / "onchain_limitations.md",
            ROOT / "contracts" / "SKYVerifier.sol",
            ROOT / "contracts" / "SKYBundleRegistry.sol",
        ]:
            self.assertTrue(path.exists(), msg=f"missing {path}")

    def test_generated_attestation_verifies(self):
        os.environ["ENABLE_EXPERIMENTAL_ATTESTATION"] = "true"
        bundle = Bundle(obligations=[Obligation(id="t", compiled_check="K", expected_result="true")])
        _, results = verify_bundle(bundle)
        attestation = generate_attestation(bundle, results, [])
        self.assertTrue(verify_attestation(attestation.to_dict(), bundle, results))

    def test_attestation_requires_explicit_flag(self):
        os.environ.pop("ENABLE_EXPERIMENTAL_ATTESTATION", None)
        bundle = Bundle(obligations=[Obligation(id="t", compiled_check="K", expected_result="true")])
        _, results = verify_bundle(bundle)
        with self.assertRaises(RuntimeError):
            generate_attestation(bundle, results, [])

    def test_cli_rejects_malformed_attestation(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "python" / "verify_attestation.py"), str(ROOT / "examples" / "attestation.json"), str(ROOT / "examples" / "bundle.json"), str(ROOT / "examples" / "results.json")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_positive_attestation_fixture_verifies(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "python" / "verify_attestation.py"), str(ROOT / "examples" / "positive_attestation.json"), str(ROOT / "examples" / "positive_bundle.json"), str(ROOT / "examples" / "positive_results.json")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_positive_corpus_generates_and_verifies(self):
        os.environ["ENABLE_EXPERIMENTAL_ATTESTATION"] = "true"
        for obligation_id, compiled_check in self.POSITIVE_CORPUS:
            with self.subTest(obligation_id=obligation_id):
                bundle = Bundle(
                    source_hash=f"corpus-{obligation_id}",
                    obligations=[
                        Obligation(
                            id=obligation_id,
                            compiled_check=compiled_check,
                            expected_result="true",
                        )
                    ],
                )
                _, results = verify_bundle(bundle)
                _, _, trace = record_trace(
                    bundle.obligations[0].compiled_check,
                    bundle.obligations[0].fuel,
                )
                attestation = generate_attestation(bundle, results, [trace]).to_dict()
                self.assertTrue(verify_attestation(attestation, bundle, results))

    def test_attestation_rejects_empty_proof_payload(self):
        bundle, results, attestation = self._load_positive_fixture()
        payload = json.loads(base64.b64decode(attestation["proof"]))
        payload["proofs"] = []
        attestation["proof"] = base64.b64encode(
            json.dumps(payload, sort_keys=True).encode()
        ).decode()
        self.assertFalse(verify_attestation(attestation, bundle, results))

    def test_attestation_rejects_wrong_bundle_binding(self):
        bundle, results, attestation = self._load_positive_fixture()
        payload = json.loads(base64.b64decode(attestation["proof"]))
        payload["proofs"][0]["binding_hash"] = "00" * 32
        attestation["proof"] = base64.b64encode(
            json.dumps(payload, sort_keys=True).encode()
        ).decode()
        self.assertFalse(verify_attestation(attestation, bundle, results))

    def test_attestation_rejects_wrong_trace_length(self):
        bundle, results, attestation = self._load_positive_fixture()
        attestation["trace_length"] += 1
        self.assertFalse(verify_attestation(attestation, bundle, results))

    def test_attestation_rejects_low_security_bits(self):
        bundle, results, attestation = self._load_positive_fixture()
        attestation["security_bits"] = 64
        self.assertFalse(verify_attestation(attestation, bundle, results))

    def test_attestation_rejects_wrong_num_obligations(self):
        bundle, results, attestation = self._load_positive_fixture()
        payload = json.loads(base64.b64decode(attestation["proof"]))
        payload["num_obligations"] += 1
        attestation["proof"] = base64.b64encode(
            json.dumps(payload, sort_keys=True).encode()
        ).decode()
        self.assertFalse(verify_attestation(attestation, bundle, results))

    def test_foundry_contract_harness(self):
        result = subprocess.run(
            ["forge", "test"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
