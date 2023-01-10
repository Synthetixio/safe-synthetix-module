// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

interface IElectionModule {
    /// @notice Returns the current NFT token holders
    function getCouncilMembers() external view returns (address[] memory);
}