// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "./interfaces/ISafe.sol";

contract SynthetixSafeModuleRegistration {
    /**
     * Called with `delegatecall` by a safe to ensure this module has all the permissions/setup it needs
     */
    function setup(address module) external {
        ISafe(address(this)).enableModule(module);
        ISafe(address(this)).setGuard(module);
    }
}