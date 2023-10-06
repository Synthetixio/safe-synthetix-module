// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "safe-contracts/contracts/SafeL2.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        SafeL2 dummySafe = deployDummySafe();
    }

    function deployDummySafe() internal returns (SafeL2) {
        bytes32 salt = keccak256("dummySafe");
        bytes32 initCode = hashInitCode(type(SafeL2).creationCode);
        address dummySafe = computeCreate2Address(, initCode);
        if (dummySafe.code.length > 0) {
            return SafeL2(dummySafe);
        }
        return new SafeL2{salt: salt}();
    }
}
