// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

interface ISafe {
    function getOwners() external view returns (address[] memory);
    function addOwnerWithThreshold(address owner, uint256 _threshold) external;
    function removeOwner(
        address prevOwner,
        address owner,
        uint256 _threshold
    ) external;
    function nonce() external returns (uint);
}