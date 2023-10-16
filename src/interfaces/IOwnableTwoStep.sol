// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 < 0.8.20;

interface IOwnableTwoStep {
    function acceptOwnership() external;
    function owner() external view returns (address);
}
