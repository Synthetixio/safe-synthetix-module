// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "cannon-std/Cannon.sol";

import "../src/SynthetixSafeModule.sol";

contract SynthetixSafeModuleTest is Test {
    using Cannon for Vm;

    SynthetixSafeModule module;
    ISafe pdaoSafe;
    ISafe safe;

    event VetoThresholdChanged(uint256 threshold);

    function setUp() public {
        module = SynthetixSafeModule(vm.getAddress("SynthetixSafeModule"));
        safe = ISafe(vm.getAddress("target_safe.Safe"));
        pdaoSafe = ISafe(vm.getAddress("pdao_safe.Safe"));
    }

    function testInitialState() public view {
        assert(safe.getThreshold() > 0);
        assert(safe.isModuleEnabled(address(module)));
    }

    function testFailSetVetoThresholdRequiresOwner() public {
        module.setVetoThreshold(1);
    }

    function testFailSetVetoThresholdTooHigh() public {
        vm.startPrank(address(pdaoSafe));
        module.setVetoThreshold(100);
        vm.stopPrank();
    }

    function testSetVetoThreshold() public {
        vm.startPrank(address(pdaoSafe));
        vm.expectEmit();

        // We emit the event we expect to see.
        emit VetoThresholdChanged(1);

        module.setVetoThreshold(1);
        vm.stopPrank();

        assertEq(module.vetoThreshold(), 1);
    }

    function testResetSafeSigners(address pdaoStart, address councilStart, uint256 pdaoCount, uint256 councilCount)
        public
    {
        pdaoCount = bound(pdaoCount, 1, 20);
        councilCount = bound(councilCount, 1, 20); // council can have 0 elected signers--in which caes the pdao is only controller
        vm.assume(pdaoStart > address(0x1)); // must be greater than gnosis safe sentinel address
        vm.assume(councilStart > address(0x1));

        address[] memory pdaoSigners = makeIncreasingArray(pdaoStart, pdaoCount);
        address[] memory councilSigners = makeIncreasingArray(councilStart, councilCount);

        makeBasicSafeConfig(pdaoSigners, councilSigners);

        address[] memory targetOwners = safe.getOwners();

        // ensure the lengths match up
        assert(targetOwners.length <= councilSigners.length + pdaoSigners.length);

        // ensure all the signers are included
        for (uint256 i = 0; i < targetOwners.length; i++) {
            console.log("checking that owner is included", targetOwners[i]);
            assert(arrayContains(pdaoSigners, targetOwners[i]) || arrayContains(councilSigners, targetOwners[i]));
        }

        // repeat of setting safe signers should result in no real
        module.resetSafeSigners(safe);

        address[] memory newTargetOwners = safe.getOwners();

        // ensure the lengths match up
        assertEq(targetOwners.length, newTargetOwners.length);

        // ensure all the signers are included
        for (uint256 i = 0; i < targetOwners.length; i++) {
            console.log("checking that owner is included", targetOwners[i]);
            assert(arrayContains(targetOwners, newTargetOwners[i]));
        }

        // assert that the correct number of signers are required
        assertEq(safe.getThreshold(), pdaoCount / 2 + 1 + module.vetoThreshold());
    }

    function testCheckTransactionFull() public {
        uint256[] memory pdaoPrivateKeys = makeSignersArray(1234, 10);
        uint256[] memory councilPrivateKeys = makeSignersArray(6789, 10);
        makeBasicSafeConfig(getAddrsFromSigners(pdaoPrivateKeys), getAddrsFromSigners(councilPrivateKeys));

        // check that a regular signature works
        // using removeOwner because its an easy way to verify the pdao is signing correctly
        address addrToRemove = vm.addr(councilPrivateKeys[councilPrivateKeys.length - 1]);
        execSafeTxn(
            address(safe),
            abi.encodeWithSelector(ISafe.removeOwner.selector, 0x1, addrToRemove, 1),
            arrayConcat(pdaoPrivateKeys, councilPrivateKeys)
        );

        assert(!safe.isOwner(addrToRemove));
    }

    function testCheckTransactionMinSigs() public {
        uint256[] memory pdaoPrivateKeys = makeSignersArray(1234, 9);
        uint256[] memory councilPrivateKeys = makeSignersArray(6789, 10);
        makeBasicSafeConfig(getAddrsFromSigners(pdaoPrivateKeys), getAddrsFromSigners(councilPrivateKeys));

        address addrToRemove = vm.addr(councilPrivateKeys[councilPrivateKeys.length - 1]);

        execSafeTxn(
            address(safe),
            abi.encodeWithSelector(ISafe.removeOwner.selector, 0x1, addrToRemove, 1),
            arrayConcat(arraySlice(pdaoPrivateKeys, 0, 5), arraySlice(councilPrivateKeys, 0, 5))
        );

        assert(!safe.isOwner(addrToRemove));
    }

    function testFailCheckTransactionWithInsufficientVetoSigners() public {
        uint256[] memory pdaoPrivateKeys = makeSignersArray(1234, 10);
        uint256[] memory councilPrivateKeys = makeSignersArray(6789, 10);
        makeBasicSafeConfig(getAddrsFromSigners(pdaoPrivateKeys), getAddrsFromSigners(councilPrivateKeys));

        // check that it fails with insufficient pdao signers
        execSafeTxn(
            address(safe),
            abi.encodeWithSelector(
                ISafe.removeOwner.selector, 0x1, vm.addr(councilPrivateKeys[councilPrivateKeys.length - 1]), 1
            ),
            arrayConcat(arraySlice(pdaoPrivateKeys, 0, 5), arraySlice(councilPrivateKeys, 0, 5))
        );
    }

    function testFailCheckTransactionWithInsufficientCouncilSigners() public {
        uint256[] memory pdaoPrivateKeys = makeSignersArray(1234, 10);
        uint256[] memory councilPrivateKeys = makeSignersArray(6789, 10);
        makeBasicSafeConfig(getAddrsFromSigners(pdaoPrivateKeys), getAddrsFromSigners(councilPrivateKeys));

        // check that it fails with insufficient council signers
        execSafeTxn(
            address(safe),
            abi.encodeWithSelector(
                ISafe.removeOwner.selector, 0x1, vm.addr(councilPrivateKeys[councilPrivateKeys.length - 1]), 1
            ),
            arrayConcat(arraySlice(pdaoPrivateKeys, 0, 5), arraySlice(councilPrivateKeys, 0, 4))
        );
    }

    function arrayContains(address[] memory list, address target) internal pure returns (bool) {
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == target) {
                return true;
            }
        }

        return false;
    }

    function arrayConcat(uint256[] memory l1, uint256[] memory l2) internal pure returns (uint256[] memory concatted) {
        concatted = new uint[](l1.length + l2.length);
        for (uint256 i = 0; i < l1.length; i++) {
            concatted[i] = l1[i];
        }

        for (uint256 i = 0; i < l2.length; i++) {
            concatted[l1.length + i] = l2[i];
        }
    }

    function arraySlice(uint256[] memory l1, uint256 start, uint256 length)
        internal
        pure
        returns (uint256[] memory sliced)
    {
        sliced = new uint[](length);
        for (uint256 i = start; i < start + length; i++) {
            sliced[i - start] = l1[i];
        }
    }

    function makeIncreasingArray(address start, uint256 count) internal pure returns (address[] memory) {
        address[] memory d = new address[](count);
        for (uint160 i = 0; i < count; i++) {
            d[i] = address(uint160(start) + i);
        }

        return d;
    }

    function makeSignersArray(uint32 start, uint256 count) internal pure returns (uint256[] memory privKeys) {
        string memory mnemonic = "test test test test test test test test test test test junk";
        uint256[] memory d = new uint[](count);
        for (uint32 i = 0; i < count; i++) {
            d[i] = vm.deriveKey(mnemonic, start + i);
        }

        return d;
    }

    function getAddrsFromSigners(uint256[] memory privateKeys) internal pure returns (address[] memory addrs) {
        addrs = new address[](privateKeys.length);
        for (uint256 i = 0; i < privateKeys.length; i++) {
            addrs[i] = vm.addr(privateKeys[i]);
        }
    }

    function makeBasicSafeConfig(address[] memory pdaoSigners, address[] memory councilSigners) internal {
        address[] memory prevOwners = pdaoSafe.getOwners();

        vm.startPrank(address(pdaoSafe));
        for (uint256 i = 0; i < pdaoSigners.length; i++) {
            pdaoSafe.addOwnerWithThreshold(pdaoSigners[i], 1);
        }

        for (uint256 i = 0; i < prevOwners.length; i++) {
            pdaoSafe.removeOwner(pdaoSigners[0], prevOwners[i], 1);
        }
        vm.stopPrank();

        vm.mockCall(
            vm.getAddress("election_module.CoreProxy"),
            abi.encodeWithSelector(IElectionModule.getCouncilMembers.selector),
            abi.encode(councilSigners)
        );

        module.resetSafeSigners(safe);
    }

    function execSafeTxn(address to, bytes memory data, uint256[] memory signers) internal {
        // gnosis safe requires signers to be in ascending order to verify no duplicates
        quickSortAddresses(signers, 0, int256(signers.length - 1));

        bytes memory sigs = new bytes(0x41 * (signers.length));

        // figure out the thing we need to sign
        bytes memory txHashData = safe.encodeTransactionData(
            // Transaction info
            to,
            0, // value
            data,
            Enum.Operation.Call,
            0, // safeTxGas
            // Payment info
            0, // baseGas
            0, // gasPrice
            address(0), // gasToken
            address(0), // refundReceiver
            // Signature info
            safe.nonce()
        );

        bytes32 h = keccak256(txHashData);

        for (uint256 i = 0; i < signers.length; i++) {
            signatureStore(sigs, i, signers[i], h);
        }

        // one of the signers is the sender
        vm.prank(vm.addr(signers[0]));
        safe.execTransaction(
            to,
            0, // value
            data,
            Enum.Operation.Call,
            0, // safeTxGas
            0, // baseGas
            0, // gasPrice
            address(0), // gasToken
            payable(address(0)), // refundReceiver
            sigs
        );
    }

    function signatureStore(bytes memory signatures, uint256 pos, uint256 key, bytes32 h) internal pure {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, h);
        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            mstore(add(signatures, add(signaturePos, 0x20)), r)
            mstore(add(signatures, add(signaturePos, 0x40)), s)
            mstore8(add(signatures, add(signaturePos, 0x60)), v)
        }
    }

    function quickSortAddresses(uint256[] memory arr, int256 left, int256 right) internal pure {
        int256 i = left;
        int256 j = right;
        if (i == j) return;
        address pivot = vm.addr(arr[uint256(left + (right - left) / 2)]);
        while (i <= j) {
            while (vm.addr(arr[uint256(i)]) < pivot) i++;
            while (pivot < vm.addr(arr[uint256(j)])) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (arr[uint256(j)], arr[uint256(i)]);
                i++;
                j--;
            }
        }
        if (left < j) {
            quickSortAddresses(arr, left, j);
        }
        if (i < right) {
            quickSortAddresses(arr, i, right);
        }
    }
}
