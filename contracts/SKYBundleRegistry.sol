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

    struct AggregateReceiptMetadata {
        bytes32 bundleHash;
        bytes32 aggregateHash;
        bytes32 rootHash;
        string description;
        uint256 requiredShardCount;
        uint256 receiptCount;
        uint256 registeredAt;
        address registeredBy;
    }

    mapping(bytes32 => BundleMetadata) public registry;
    mapping(bytes32 => AggregateReceiptMetadata) public aggregateRegistry;
    bytes32[] public registeredBundles;
    bytes32[] public registeredAggregates;

    event BundleRegistered(bytes32 indexed bundleHash, string description, address registeredBy);
    event AggregateReceiptRegistered(
        bytes32 indexed aggregateHash,
        bytes32 indexed bundleHash,
        bytes32 rootHash,
        address registeredBy
    );

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

    function registerAggregateReceipt(
        bytes32 bundleHash,
        bytes32 aggregateHash,
        bytes32 rootHash,
        string calldata description,
        uint256 requiredShardCount,
        uint256 receiptCount
    ) external {
        require(registry[bundleHash].registeredAt != 0, "Bundle must be registered first");
        require(aggregateHash != bytes32(0), "Aggregate hash required");
        require(rootHash != bytes32(0), "Root hash required");
        require(requiredShardCount > 0, "Required shards must be non-zero");
        require(receiptCount >= requiredShardCount, "Receipt count below required shard count");
        require(aggregateRegistry[aggregateHash].registeredAt == 0, "Aggregate already registered");

        aggregateRegistry[aggregateHash] = AggregateReceiptMetadata({
            bundleHash: bundleHash,
            aggregateHash: aggregateHash,
            rootHash: rootHash,
            description: description,
            requiredShardCount: requiredShardCount,
            receiptCount: receiptCount,
            registeredAt: block.timestamp,
            registeredBy: msg.sender
        });
        registeredAggregates.push(aggregateHash);
        emit AggregateReceiptRegistered(aggregateHash, bundleHash, rootHash, msg.sender);
    }

    function registeredAggregateCount() external view returns (uint256) {
        return registeredAggregates.length;
    }
}
