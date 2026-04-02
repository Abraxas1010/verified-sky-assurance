// SPDX-License-Identifier: LicenseRef-Apoth3osis-License-Stack-v1
pragma solidity ^0.8.20;

import "../contracts/SKYBundleRegistry.sol";
import "./TestBase.sol";

contract MockVerifierFalse {
    function isVerified(bytes32) external pure returns (bool verified, uint256 verifiedAt) {
        return (false, 0);
    }
}

contract MockVerifierTrue {
    function isVerified(bytes32) external pure returns (bool verified, uint256 verifiedAt) {
        return (true, 123);
    }
}

contract SKYBundleRegistryTest is TestBase {
    function testRejectsUnverifiedBundle() public {
        SKYBundleRegistry registry = new SKYBundleRegistry(address(new MockVerifierFalse()));
        bytes32 bundleHash = keccak256("bundle-unverified");
        (bool ok,) = address(registry).call(
            abi.encodeWithSelector(
                registry.register.selector,
                bundleHash,
                "demo",
                "Lean4",
                1
            )
        );
        assertFalse(ok, "unverified bundle must revert");
        assertEq(registry.registeredCount(), 0, "registry must stay empty");
    }

    function testRegistersVerifiedBundle() public {
        SKYBundleRegistry registry = new SKYBundleRegistry(address(new MockVerifierTrue()));
        bytes32 bundleHash = keccak256("bundle-verified");
        registry.register(bundleHash, "demo", "Lean4", 2);
        (
            string memory sourceDescription,
            string memory leanVersion,
            uint256 obligationCount,
            bytes32 storedBundleHash,
            uint256 registeredAt,
            address registeredBy
        ) = registry.registry(bundleHash);
        assertEq(registry.registeredCount(), 1, "registry must contain one bundle");
        assertEq(storedBundleHash, bundleHash, "stored bundle hash mismatch");
        assertEq(obligationCount, 2, "obligation count mismatch");
        assertTrue(bytes(sourceDescription).length > 0, "missing source description");
        assertTrue(bytes(leanVersion).length > 0, "missing Lean version");
        assertTrue(registeredAt > 0, "registration timestamp missing");
        assertEq(registeredBy, address(this), "registeredBy mismatch");
    }

    function testRejectsDuplicateRegistration() public {
        SKYBundleRegistry registry = new SKYBundleRegistry(address(new MockVerifierTrue()));
        bytes32 bundleHash = keccak256("bundle-verified");
        registry.register(bundleHash, "demo", "Lean4", 2);
        (bool ok,) = address(registry).call(
            abi.encodeWithSelector(
                registry.register.selector,
                bundleHash,
                "demo",
                "Lean4",
                2
            )
        );
        assertFalse(ok, "duplicate registration must revert");
        assertEq(registry.registeredCount(), 1, "registry count must remain stable");
    }

    function testRejectsAggregateReceiptForUnregisteredBundle() public {
        SKYBundleRegistry registry = new SKYBundleRegistry(address(new MockVerifierTrue()));
        bytes32 bundleHash = keccak256("bundle-verified");
        bytes32 aggregateHash = keccak256("aggregate");
        bytes32 rootHash = keccak256("root");

        (bool ok,) = address(registry).call(
            abi.encodeWithSelector(
                registry.registerAggregateReceipt.selector,
                bundleHash,
                aggregateHash,
                rootHash,
                "aggregate-demo",
                2,
                2
            )
        );

        assertFalse(ok, "aggregate registration must require a registered bundle");
        assertEq(registry.registeredAggregateCount(), 0, "aggregate registry must stay empty");
    }

    function testRejectsAggregateReceiptWithInsufficientCoverage() public {
        SKYBundleRegistry registry = new SKYBundleRegistry(address(new MockVerifierTrue()));
        bytes32 bundleHash = keccak256("bundle-verified");
        registry.register(bundleHash, "demo", "Lean4", 2);

        (bool ok,) = address(registry).call(
            abi.encodeWithSelector(
                registry.registerAggregateReceipt.selector,
                bundleHash,
                keccak256("aggregate"),
                keccak256("root"),
                "aggregate-demo",
                3,
                2
            )
        );

        assertFalse(ok, "aggregate registration must require enough receipts");
        assertEq(registry.registeredAggregateCount(), 0, "aggregate registry must stay empty");
    }

    function testRegistersAggregateReceiptBinding() public {
        SKYBundleRegistry registry = new SKYBundleRegistry(address(new MockVerifierTrue()));
        bytes32 bundleHash = keccak256("bundle-verified");
        bytes32 aggregateHash = keccak256("aggregate");
        bytes32 rootHash = keccak256("root");

        registry.register(bundleHash, "demo", "Lean4", 2);
        registry.registerAggregateReceipt(bundleHash, aggregateHash, rootHash, "aggregate-demo", 2, 3);

        (
            bytes32 storedBundleHash,
            bytes32 storedAggregateHash,
            bytes32 storedRootHash,
            string memory description,
            uint256 requiredShardCount,
            uint256 receiptCount,
            uint256 registeredAt,
            address registeredBy
        ) = registry.aggregateRegistry(aggregateHash);

        assertEq(registry.registeredAggregateCount(), 1, "aggregate registry must contain one receipt");
        assertEq(storedBundleHash, bundleHash, "aggregate bundle hash mismatch");
        assertEq(storedAggregateHash, aggregateHash, "aggregate hash mismatch");
        assertEq(storedRootHash, rootHash, "root hash mismatch");
        assertEq(requiredShardCount, 2, "required shard count mismatch");
        assertEq(receiptCount, 3, "receipt count mismatch");
        assertTrue(bytes(description).length > 0, "missing aggregate description");
        assertTrue(registeredAt > 0, "aggregate registration timestamp missing");
        assertEq(registeredBy, address(this), "aggregate registeredBy mismatch");
    }

    function testRejectsDuplicateAggregateReceiptRegistration() public {
        SKYBundleRegistry registry = new SKYBundleRegistry(address(new MockVerifierTrue()));
        bytes32 bundleHash = keccak256("bundle-verified");
        bytes32 aggregateHash = keccak256("aggregate");
        bytes32 rootHash = keccak256("root");

        registry.register(bundleHash, "demo", "Lean4", 2);
        registry.registerAggregateReceipt(bundleHash, aggregateHash, rootHash, "aggregate-demo", 2, 2);

        (bool ok,) = address(registry).call(
            abi.encodeWithSelector(
                registry.registerAggregateReceipt.selector,
                bundleHash,
                aggregateHash,
                rootHash,
                "aggregate-demo",
                2,
                2
            )
        );

        assertFalse(ok, "duplicate aggregate registration must revert");
        assertEq(registry.registeredAggregateCount(), 1, "aggregate registry count must remain stable");
    }
}
