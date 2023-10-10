// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./Deploy.s.sol";

import "../src/interfaces/IOwnableTwoStep.sol";

contract AcceptOwnershipScript is DeployScript {

    function run() public override virtual {
        connect();

        deployAll();

        console.log("using account", account);

        acceptOwnership(vm.envAddress("CC_TOKEN"), register["INFINEX_SAFE"]);
        acceptOwnership(vm.envAddress("INVESTOR_TOKEN"), register["TREASURY_SAFE"]);

        acceptOwnership(vm.envAddress("CORE_CONTRIBUTOR_COUNCIL"), register["CC_TOKEN_SAFE"]);
        acceptOwnership(vm.envAddress("ECOSYSTEM_COUNCIL"), register["CC_TOKEN_SAFE"]);
        acceptOwnership(vm.envAddress("TRADER_COUNCIL"), register["CC_TOKEN_SAFE"]);
        acceptOwnership(vm.envAddress("TREASURY_COUNCIL"), register["CC_TOKEN_SAFE"]);

        disconnect();
    }

    function acceptOwnership(address target, address safe) internal {
        console.log("Accepting Ownership Of", target, "from", safe);
        address currentOwner = IOwnableTwoStep(target).owner();

        if (target == currentOwner) {
            console.log("already owner");
            return;
        }

        Safe(payable(safe)).execTransaction(
            target,
            0,
            abi.encodeWithSelector(IOwnableTwoStep.acceptOwnership.selector),
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            abi.encodePacked(abi.encode(account, bytes32(0)), uint8(1))
        );
    }
}
