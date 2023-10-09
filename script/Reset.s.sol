// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./Deploy.s.sol";

contract ResetScript is DeployScript {

    function run() public virtual override {
        connect();

        deployAll();

        SynthetixSafeModule(register["CC_MODULE"]).resetSafeSigners(ISafe(register["CC_SAFE"]));
        SynthetixSafeModule(register["ECOSYSTEM_MODULE"]).resetSafeSigners(ISafe(register["ECOSYSTEM_SAFE"]));
        SynthetixSafeModule(register["TRADER_MODULE"]).resetSafeSigners(ISafe(register["TRADER_SAFE"]));
        SynthetixSafeModule(register["TREASURY_MODULE"]).resetSafeSigners(ISafe(register["TREASURY_SAFE"]));
        SynthetixSafeModule(register["INFINEX_MODULE"]).resetSafeSigners(ISafe(register["INFINEX_SAFE"]));

        disconnect();
    }
}
