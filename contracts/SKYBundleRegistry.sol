// SPDX-License-Identifier: LicenseRef-Apoth3osis-License-Stack-v1
pragma solidity ^0.8.20;

contract SKYBundleRegistry {
    struct BundleRecord {
        bytes32 manifestHash;
        uint256 registeredAt;
        address registrar;
    }

    mapping(bytes32 => BundleRecord) public bundles;

    event BundleRegistered(bytes32 indexed bundleHash, bytes32 manifestHash, address registrar);

    function registerBundle(bytes32 bundleHash, bytes32 manifestHash) external {
        bundles[bundleHash] = BundleRecord({
            manifestHash: manifestHash,
            registeredAt: block.timestamp,
            registrar: msg.sender
        });
        emit BundleRegistered(bundleHash, manifestHash, msg.sender);
    }
}
