// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

contract DummySafe {
    function getOwners() external pure returns (address[] memory addresses) {
        addresses = new address[](0);
    }

    function getCouncilMembers() external pure returns (address[] memory addresses) {
        addresses = new address[](0);
    }
}
