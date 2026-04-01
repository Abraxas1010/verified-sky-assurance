// SPDX-License-Identifier: LicenseRef-Apoth3osis-License-Stack-v1
pragma solidity ^0.8.20;

import "./SKYVerifier.sol";

/**
 * @title SKYBundleRegistry
 * @notice On-chain registry of verified SKY proof bundles.
 */
contract SKYBundleRegistry {
    SKYVerifier public immutable verifier;

    struct BundleMetadata {
        string sourceDescription;
        string leanVersion;
        uint256 obligationCount;
        bytes32 bundleHash;
        uint256 registeredAt;
        address registeredBy;
    }

    mapping(bytes32 => BundleMetadata) public registry;
    bytes32[] public registeredBundles;

    event BundleRegistered(bytes32 indexed bundleHash, string description, address registeredBy);

    constructor(address _verifier) {
        verifier = SKYVerifier(_verifier);
    }

    function register(
        bytes32 bundleHash,
        string calldata description,
        string calldata leanVersion,
        uint256 obligationCount
    ) external {
        (bool verified,) = verifier.isVerified(bundleHash);
        require(verified, "Bundle must be verified first");
        require(registry[bundleHash].registeredAt == 0, "Already registered");

        registry[bundleHash] = BundleMetadata({
            sourceDescription: description,
            leanVersion: leanVersion,
            obligationCount: obligationCount,
            bundleHash: bundleHash,
            registeredAt: block.timestamp,
            registeredBy: msg.sender
        });
        registeredBundles.push(bundleHash);
        emit BundleRegistered(bundleHash, description, msg.sender);
    }

    function registeredCount() external view returns (uint256) {
        return registeredBundles.length;
    }
}
