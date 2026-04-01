// SPDX-License-Identifier: LicenseRef-Apoth3osis-License-Stack-v1
pragma solidity ^0.8.20;

import "../contracts/SKYBundleRegistry.sol";
import "../contracts/SKYVerifier.sol";
import "./TestBase.sol";
import "./fixtures/PositiveProofFixture.sol";

contract SKYPositiveFixtureTest is TestBase {
    function _load()
        internal
        returns (
            SKYVerifier verifier,
            SKYVerifier.STARKProof memory proof,
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings,
            bytes32 bundleHash
        )
    {
        verifier = new SKYVerifier();
        (proof, traceOpenings, friOpenings) = PositiveProofFixture.load();
        bundleHash = PositiveProofFixture.bundleHash();
    }

    function testPositiveFixtureVerifiesAndRegisters() public {
        (
            SKYVerifier verifier,
            SKYVerifier.STARKProof memory proof,
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings,
            bytes32 bundleHash
        ) = _load();

        bool ok = verifier.verify(bundleHash, proof, traceOpenings, friOpenings);
        assertTrue(ok, "positive STARK fixture must verify");

        (bool verified, uint256 verifiedAt) = verifier.isVerified(bundleHash);
        assertTrue(verified, "bundle must be marked verified");
        assertTrue(verifiedAt > 0, "verification timestamp missing");

        SKYBundleRegistry registry = new SKYBundleRegistry(address(verifier));
        registry.register(bundleHash, "k_rule_demo", "fixture", 1);
        assertEq(registry.registeredCount(), 1, "registry must contain the verified bundle");
    }

    function testRejectsTamperedFRIFold() public {
        (
            SKYVerifier verifier,
            SKYVerifier.STARKProof memory proof,
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings,
            bytes32 bundleHash
        ) = _load();
        bundleHash;

        friOpenings[0][1].val += 1;
        bool ok = verifier.verifySTARK(proof, traceOpenings, friOpenings);
        assertFalse(ok, "tampered folded value must reject");
    }

    function testRejectsTamperedFinalConstant() public {
        (
            SKYVerifier verifier,
            SKYVerifier.STARKProof memory proof,
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings,
            bytes32 bundleHash
        ) = _load();
        bundleHash;

        proof.friFinal += 1;
        bool ok = verifier.verifySTARK(proof, traceOpenings, friOpenings);
        assertFalse(ok, "tampered final constant must reject");
    }

    function testRejectsNonTranscriptQueryPosition() public {
        (
            SKYVerifier verifier,
            SKYVerifier.STARKProof memory proof,
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings,
            bytes32 bundleHash
        ) = _load();
        bundleHash;

        proof.queryPositions[0] = (proof.queryPositions[0] + 1) % proof.friLayerDomainSizes[0];
        bool ok = verifier.verifySTARK(proof, traceOpenings, friOpenings);
        assertFalse(ok, "query positions must be transcript-derived");
    }

    function testRejectsMismatchedBundleHashBinding() public {
        (
            SKYVerifier verifier,
            SKYVerifier.STARKProof memory proof,
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings,
            bytes32 bundleHash
        ) = _load();
        bundleHash;

        bytes32 wrongHash = keccak256("wrong-bundle");
        bool ok = verifier.verify(wrongHash, proof, traceOpenings, friOpenings);
        assertFalse(ok, "proof must not verify against a different bundle hash");

        (bool verified, uint256 verifiedAt) = verifier.isVerified(wrongHash);
        assertFalse(verified, "wrong bundle hash must not be recorded");
        assertEq(verifiedAt, 0, "wrong bundle hash must not get a timestamp");
    }
}
