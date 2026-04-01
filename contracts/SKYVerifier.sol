// SPDX-License-Identifier: LicenseRef-Apoth3osis-License-Stack-v1
pragma solidity ^0.8.20;

/**
 * @title GoldilocksField
 * @notice Arithmetic over the Goldilocks prime field (p = 2^64 - 2^32 + 1).
 * @dev Same field used by the off-chain STARK prover.  All STARK verification
 *      arithmetic operates in this field.
 */
library GoldilocksField {
    uint256 internal constant P = 18446744069414584321;
    uint256 internal constant GENERATOR = 7;

    function fadd(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, P);
    }

    function fsub(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, P - (b % P), P);
    }

    function fmul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, P);
    }

    function fpow(uint256 base, uint256 exp) internal pure returns (uint256) {
        uint256 result = 1;
        base = base % P;
        while (exp > 0) {
            if (exp & 1 == 1) {
                result = mulmod(result, base, P);
            }
            exp >>= 1;
            base = mulmod(base, base, P);
        }
        return result;
    }

    function finv(uint256 a) internal pure returns (uint256) {
        require(a != 0, "inverse of zero");
        return fpow(a, P - 2);
    }

    function rootOfUnity(uint256 n) internal pure returns (uint256) {
        return fpow(GENERATOR, (P - 1) / n);
    }
}

library SKYEncoding {
    function byteSwap64(uint64 value) internal pure returns (uint64) {
        value = ((value & 0xFF00FF00FF00FF00) >> 8) | ((value & 0x00FF00FF00FF00FF) << 8);
        value = ((value & 0xFFFF0000FFFF0000) >> 16) | ((value & 0x0000FFFF0000FFFF) << 16);
        value = (value >> 32) | (value << 32);
        return value;
    }

    function littleEndianBytes(uint64 value) internal pure returns (bytes8) {
        return bytes8(byteSwap64(value));
    }

    function byteSwap32(uint32 value) internal pure returns (uint32) {
        value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
        value = (value >> 16) | (value << 16);
        return value;
    }

    function littleEndianBytes32(uint32 value) internal pure returns (bytes4) {
        return bytes4(byteSwap32(value));
    }

    function first8BytesLittleEndian(bytes32 value) internal pure returns (uint256 acc) {
        for (uint256 i = 0; i < 8; i++) {
            acc |= uint256(uint8(value[i])) << (8 * i);
        }
    }
}

/**
 * @title MerkleVerifier
 * @notice SHA-256 Merkle tree verification with domain-separated hashing.
 * @dev Matches the off-chain MerkleTree implementation:
 *      leaf = SHA256(0x00 || value), node = SHA256(0x01 || left || right)
 */
library MerkleVerifier {
    function hashLeaf(uint64 value) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(bytes1(0x00), SKYEncoding.littleEndianBytes(value))
        );
    }

    function hashNode(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x01), left, right));
    }

    function verify(
        bytes32 root,
        uint256 index,
        uint64 value,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        bytes32 current = hashLeaf(value);
        for (uint256 i = 0; i < proof.length; i++) {
            if (index & 1 == 1) {
                current = hashNode(proof[i], current);
            } else {
                current = hashNode(current, proof[i]);
            }
            index >>= 1;
        }
        return current == root;
    }
}

/**
 * @title SKYVerifier
 * @notice On-chain verifier for STARK-attested SKY proof bundles.
 * @dev Verifies STARK proofs over the Goldilocks field using:
 *      - SHA-256 Merkle tree authentication
 *      - FRI folding consistency checks
 *      - AIR constraint evaluation (step counter + state boundaries)
 *      - Fiat-Shamir transcript replay for challenge derivation
 *
 *      Trust model: trusts the STARK scheme (FRI soundness + SHA-256
 *      collision resistance) and the three SKY reduction rules.
 *      Does NOT trust the prover, Lean compiler, or any off-chain service.
 */
contract SKYVerifier {
    using GoldilocksField for uint256;

    string public constant SCHEMA_VERSION = "1.0.0";
    uint256 public constant MIN_SECURITY_BITS = 120;
    uint256 public constant BLOWUP = 8;
    uint256 public constant NUM_QUERIES = 30;
    uint256 public constant COSET_SHIFT = 7;

    event BundleVerified(
        bytes32 indexed bundleHash,
        bytes32 publicInputs,
        uint256 traceLength,
        uint256 timestamp
    );

    event VerificationFailed(bytes32 indexed bundleHash, string reason);

    mapping(bytes32 => VerificationRecord) public verifiedBundles;

    struct VerificationRecord {
        bytes32 publicInputs;
        uint256 traceLength;
        uint256 verifiedAt;
        bool verified;
    }

    /// @notice Per-query opening data for STARK verification
    struct QueryOpening {
        uint64 stepVal;
        bytes32[] stepProof;
        uint64 stepShiftedVal;
        bytes32[] stepShiftedProof;
        uint64 stateVal;
        bytes32[] stateProof;
    }

    /// @notice FRI layer opening for a single query at a single layer
    struct FRILayerOpening {
        uint256 pos;
        uint64 val;
        bytes32[] proof;
        uint256 sibPos;
        uint64 sibVal;
        bytes32[] sibProof;
    }

    /// @notice Complete STARK proof for one obligation
    struct STARKProof {
        bytes32 bindingHash;
        bytes32 stepTraceRoot;
        bytes32 stateTraceRoot;
        uint256 traceLength;         // N (power of 2)
        uint256 inputHash;           // field element
        uint256 outputHash;          // field element
        bytes32[] friRoots;          // Merkle roots per FRI layer
        uint256 friFinal;            // final constant value
        uint256[] friLayerDomainSizes;
        uint256[] friLayerShifts;
        uint256[] friLayerOmegas;
        uint256[] queryPositions;
    }

    function _expectedFRILayers(uint256 traceLength) internal pure returns (uint256 layers) {
        while (traceLength > 1) {
            traceLength >>= 1;
            layers += 1;
        }
    }

    function _transcriptSqueeze(bytes32 state, uint32 counter) internal pure returns (uint256) {
        return SKYEncoding.first8BytesLittleEndian(
            sha256(abi.encodePacked(state, SKYEncoding.littleEndianBytes32(counter)))
        ) % GoldilocksField.P;
    }

    /**
     * @notice Verify a single STARK proof's structural integrity.
     * @dev Checks FRI Merkle openings and constraint consistency at
     *      each query position.  Full on-chain verification with real
     *      Goldilocks field arithmetic.
     */
    function verifySTARK(
        STARKProof calldata proof,
        QueryOpening[] calldata traceOpenings,
        FRILayerOpening[][] calldata friOpenings
    ) public pure returns (bool) {
        uint256 N = proof.traceLength;
        uint256 M = N * BLOWUP;

        // Validate parameters
        if (N == 0 || N > 1 << 20) return false;
        if (N & (N - 1) != 0) return false;  // must be power of 2
        if (proof.inputHash >= GoldilocksField.P) return false;
        if (proof.outputHash >= GoldilocksField.P) return false;
        if (proof.friFinal >= GoldilocksField.P) return false;
        if (proof.queryPositions.length != NUM_QUERIES) return false;
        if (traceOpenings.length != NUM_QUERIES) return false;
        if (friOpenings.length != NUM_QUERIES) return false;
        if (proof.friRoots.length == 0) return false;
        if (proof.friRoots.length != proof.friLayerDomainSizes.length) return false;
        if (proof.friRoots.length != proof.friLayerShifts.length) return false;
        if (proof.friRoots.length != proof.friLayerOmegas.length) return false;
        if (proof.friRoots.length != _expectedFRILayers(N)) return false;

        uint256 omegaTrace = GoldilocksField.rootOfUnity(N);
        uint256 omegaExt = GoldilocksField.rootOfUnity(M);
        uint256 omegaNm1 = GoldilocksField.fpow(omegaTrace, N - 1);
        uint256 inv2 = GoldilocksField.finv(2);
        if (proof.bindingHash == bytes32(0)) return false;

        // Replay Fiat-Shamir to get alpha
        bytes32 transcriptState = sha256(bytes("sky-stark-v1"));
        transcriptState = sha256(abi.encodePacked(transcriptState, proof.bindingHash));
        uint32 transcriptCounter = 0;
        transcriptState = sha256(abi.encodePacked(transcriptState, proof.stepTraceRoot));
        transcriptState = sha256(abi.encodePacked(transcriptState, proof.stateTraceRoot));
        uint256 alpha = _transcriptSqueeze(transcriptState, transcriptCounter);
        transcriptCounter += 1;

        uint256[] memory betas = new uint256[](proof.friRoots.length);
        uint256 expectedDomainSize = M;
        uint256 expectedShift = COSET_SHIFT;
        for (uint256 li = 0; li < proof.friRoots.length; li++) {
            if (proof.friLayerDomainSizes[li] != expectedDomainSize) return false;
            if (proof.friLayerShifts[li] != expectedShift) return false;
            if (proof.friLayerOmegas[li] != GoldilocksField.rootOfUnity(expectedDomainSize)) return false;
            transcriptState = sha256(abi.encodePacked(transcriptState, proof.friRoots[li]));
            transcriptCounter = 0;
            betas[li] = _transcriptSqueeze(transcriptState, transcriptCounter);
            transcriptCounter += 1;
            expectedDomainSize >>= 1;
            expectedShift = GoldilocksField.fmul(expectedShift, expectedShift);
        }
        transcriptState = sha256(
            abi.encodePacked(transcriptState, SKYEncoding.littleEndianBytes(uint64(proof.friFinal)))
        );
        transcriptCounter = 0;

        // Check each query
        for (uint256 qi = 0; qi < NUM_QUERIES; qi++) {
            uint256 pos = _transcriptSqueeze(transcriptState, transcriptCounter) % proof.friLayerDomainSizes[0];
            transcriptCounter += 1;
            if (proof.queryPositions[qi] != pos) return false;
            QueryOpening calldata op = traceOpenings[qi];
            if (friOpenings[qi].length != proof.friRoots.length) return false;

            // Verify trace Merkle proofs
            if (!MerkleVerifier.verify(
                proof.stepTraceRoot, pos, op.stepVal, op.stepProof
            )) return false;

            uint256 shiftedPos = (pos + BLOWUP) % M;
            if (!MerkleVerifier.verify(
                proof.stepTraceRoot, shiftedPos,
                op.stepShiftedVal, op.stepShiftedProof
            )) return false;

            if (!MerkleVerifier.verify(
                proof.stateTraceRoot, pos, op.stateVal, op.stateProof
            )) return false;

            // Evaluate constraints at query point
            uint256 x = GoldilocksField.fmul(
                COSET_SHIFT,
                GoldilocksField.fpow(omegaExt, pos)
            );

            // Step constraint: step(omega*x) - step(x) - 1
            uint256 cStep = GoldilocksField.fsub(
                GoldilocksField.fsub(uint256(op.stepShiftedVal), uint256(op.stepVal)),
                1
            );

            // Vanishing: Z_trans = (x^N - 1) / (x - omega^{N-1})
            uint256 xN = GoldilocksField.fpow(x, N);
            uint256 zTrace = GoldilocksField.fsub(xN, 1);
            uint256 zTrans = GoldilocksField.fmul(
                zTrace,
                GoldilocksField.finv(GoldilocksField.fsub(x, omegaNm1))
            );

            uint256 qStep = GoldilocksField.fmul(cStep, GoldilocksField.finv(zTrans));

            // Boundary constraints
            uint256 qBoundIn = GoldilocksField.fmul(
                GoldilocksField.fsub(uint256(op.stateVal), proof.inputHash),
                GoldilocksField.finv(GoldilocksField.fsub(x, 1))
            );
            uint256 qBoundOut = GoldilocksField.fmul(
                GoldilocksField.fsub(uint256(op.stateVal), proof.outputHash),
                GoldilocksField.finv(GoldilocksField.fsub(x, omegaNm1))
            );

            // Combined quotient
            uint256 qExpected = GoldilocksField.fadd(
                GoldilocksField.fmul(alpha, qStep),
                GoldilocksField.fadd(
                    GoldilocksField.fmul(GoldilocksField.fmul(alpha, alpha), qBoundIn),
                    GoldilocksField.fmul(GoldilocksField.fpow(alpha, 3), qBoundOut)
                )
            );

            // Check FRI first-layer value matches quotient
            if (friOpenings.length > qi && friOpenings[qi].length > 0) {
                if (uint256(friOpenings[qi][0].val) != qExpected) return false;
            }

            // Verify each FRI layer and the fold relation into the next layer.
            uint256 currentPos = pos;
            for (uint256 li = 0; li < friOpenings[qi].length; li++) {
                FRILayerOpening calldata fl = friOpenings[qi][li];
                uint256 ds = proof.friLayerDomainSizes[li];
                uint256 halfDs = ds / 2;
                if (fl.pos != currentPos) return false;
                if (fl.sibPos != (currentPos + halfDs) % ds) return false;
                if (!MerkleVerifier.verify(
                    proof.friRoots[li], fl.pos, fl.val, fl.proof
                )) return false;
                if (!MerkleVerifier.verify(
                    proof.friRoots[li], fl.sibPos, fl.sibVal, fl.sibProof
                )) return false;

                uint256 xFri = GoldilocksField.fmul(
                    proof.friLayerShifts[li],
                    GoldilocksField.fpow(proof.friLayerOmegas[li], fl.pos)
                );
                uint256 sum = GoldilocksField.fadd(uint256(fl.val), uint256(fl.sibVal));
                uint256 diff = GoldilocksField.fsub(uint256(fl.val), uint256(fl.sibVal));
                uint256 inv2x = GoldilocksField.finv(GoldilocksField.fmul(2, xFri));
                uint256 folded = GoldilocksField.fadd(
                    GoldilocksField.fmul(sum, inv2),
                    GoldilocksField.fmul(betas[li], GoldilocksField.fmul(diff, inv2x))
                );

                if (li + 1 < friOpenings[qi].length) {
                    if (uint256(friOpenings[qi][li + 1].val) != folded) return false;
                } else {
                    if (folded != proof.friFinal) return false;
                }

                currentPos = currentPos % halfDs;
            }
        }

        return true;
    }

    /**
     * @notice Verify and record a STARK attestation for an SKY bundle.
     */
    function verify(
        bytes32 bundleHash,
        STARKProof calldata proof,
        QueryOpening[] calldata traceOpenings,
        FRILayerOpening[][] calldata friOpenings
    ) external returns (bool valid) {
        if (bundleHash != proof.bindingHash) {
            emit VerificationFailed(bundleHash, "bundle hash does not match proof binding");
            return false;
        }
        valid = verifySTARK(proof, traceOpenings, friOpenings);

        if (valid) {
            verifiedBundles[bundleHash] = VerificationRecord({
                publicInputs: sha256(abi.encodePacked(proof.inputHash, proof.outputHash)),
                traceLength: proof.traceLength,
                verifiedAt: block.timestamp,
                verified: true
            });
            emit BundleVerified(
                bundleHash,
                verifiedBundles[bundleHash].publicInputs,
                proof.traceLength,
                block.timestamp
            );
        } else {
            emit VerificationFailed(bundleHash, "STARK verification failed");
        }
    }

    function isVerified(bytes32 bundleHash) external view returns (bool verified, uint256 verifiedAt) {
        VerificationRecord storage record = verifiedBundles[bundleHash];
        return (record.verified, record.verifiedAt);
    }

    function verifyBatch(
        bytes32[] calldata bundleHashes,
        STARKProof[] calldata proofs,
        QueryOpening[][] calldata traceOpenings,
        FRILayerOpening[][][] calldata friOpenings
    ) external returns (bool[] memory results) {
        require(bundleHashes.length == proofs.length, "Length mismatch");
        results = new bool[](bundleHashes.length);
        for (uint256 i = 0; i < bundleHashes.length; i++) {
            results[i] = this.verify(
                bundleHashes[i], proofs[i], traceOpenings[i], friOpenings[i]
            );
        }
    }
}
