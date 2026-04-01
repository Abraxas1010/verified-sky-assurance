// SPDX-License-Identifier: LicenseRef-Apoth3osis-License-Stack-v1
pragma solidity ^0.8.20;

import "../contracts/SKYVerifier.sol";
import "./TestBase.sol";

contract SKYVerifierTest is TestBase {
    function _proofWithLength(uint256 traceLength)
        internal
        pure
        returns (SKYVerifier.STARKProof memory proof)
    {
        proof.traceLength = traceLength;
        proof.friRoots = new bytes32[](0);
        proof.friLayerDomainSizes = new uint256[](0);
        proof.friLayerShifts = new uint256[](0);
        proof.friLayerOmegas = new uint256[](0);
        proof.queryPositions = new uint256[](30);
    }

    function _openings()
        internal
        pure
        returns (
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings
        )
    {
        traceOpenings = new SKYVerifier.QueryOpening[](30);
        friOpenings = new SKYVerifier.FRILayerOpening[][](30);
        for (uint256 i = 0; i < 30; i++) {
            traceOpenings[i] = SKYVerifier.QueryOpening({
                stepVal: 0,
                stepProof: new bytes32[](0),
                stepShiftedVal: 0,
                stepShiftedProof: new bytes32[](0),
                stateVal: 0,
                stateProof: new bytes32[](0)
            });
            friOpenings[i] = new SKYVerifier.FRILayerOpening[](0);
        }
    }

    function testRejectsZeroTraceLength() public {
        SKYVerifier verifier = new SKYVerifier();
        SKYVerifier.STARKProof memory proof = _proofWithLength(0);
        (
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings
        ) = _openings();
        bool ok = verifier.verifySTARK(proof, traceOpenings, friOpenings);
        assertFalse(ok, "zero trace length must reject");
    }

    function testRejectsNonPowerOfTwoTraceLength() public {
        SKYVerifier verifier = new SKYVerifier();
        SKYVerifier.STARKProof memory proof = _proofWithLength(3);
        (
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings
        ) = _openings();
        bool ok = verifier.verifySTARK(proof, traceOpenings, friOpenings);
        assertFalse(ok, "non power-of-two trace length must reject");
    }

    function testInvalidProofDoesNotRecordVerification() public {
        SKYVerifier verifier = new SKYVerifier();
        bytes32 bundleHash = keccak256("invalid-bundle");
        SKYVerifier.STARKProof memory proof = _proofWithLength(4);
        (
            SKYVerifier.QueryOpening[] memory traceOpenings,
            SKYVerifier.FRILayerOpening[][] memory friOpenings
        ) = _openings();
        bool ok = verifier.verify(bundleHash, proof, traceOpenings, friOpenings);
        (bool verified, uint256 verifiedAt) = verifier.isVerified(bundleHash);
        assertFalse(ok, "invalid proof must fail");
        assertFalse(verified, "invalid proof must not mark bundle verified");
        assertEq(verifiedAt, 0, "invalid proof must not record timestamp");
    }
}
