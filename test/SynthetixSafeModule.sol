// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "cannon-std/Cannon.sol";

import "../src/SynthetixSafeModule.sol";

contract CounterScript is Test {
    using Cannon for Vm;

    SynthetixSafeModule module;

    function setUp() public {
        module = SynthetixSafeModule(vm.getAddress("SynthetixSafeModule"));
    }

    function testFailSetPdaoThresholdRequiresOwner() public {
        module.setPdaoThreshold(3);
    }

    function testSetPdaoThreshold() public {
        vm.broadcast(0xDEB48C91bDF743AA0a9025485d2dE08fC502655c);
        module.setPdaoThreshold(3);
    }
}
