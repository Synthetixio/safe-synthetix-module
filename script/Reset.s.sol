// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./Deploy.s.sol";

contract ResetScript is DeployScript {

    function run() public {
        deployAll();

        connect();

        SynthetixSafeModule(register["CC_MODULE"]).resetSafeSigners(register["CC_SAFE"]);
        SynthetixSafeModule(register["ECOSYSTEM_MODULE"]).resetSafeSigners(register["ECOSYSTEM_SAFE"]);
        SynthetixSafeModule(register["TRADER_MODULE"]).resetSafeSigners(register["TRADER_SAFE"]);
        SynthetixSafeModule(register["TREASURY_MODULE"]).resetSafeSigners(register["TREASURY_SAFE"]);
        SynthetixSafeModule(register["INFINEX_MODULE"]).resetSafeSigners(register["INFINEX_SAFE"]);

        disconnect();
    }
}
