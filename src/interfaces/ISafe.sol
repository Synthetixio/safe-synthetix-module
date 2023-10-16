// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 < 0.8.20;

import {Enum} from "./IGuard.sol";

interface ISafe {
    function getOwners() external view returns (address[] memory);
    function addOwnerWithThreshold(address owner, uint256 _threshold) external;
    function removeOwner(address prevOwner, address owner, uint256 _threshold) external;
    function nonce() external view returns (uint256);
    function setGuard(address guard) external;
    function enableModule(address module) external;
    function isModuleEnabled(address module) external view returns (bool);
    function getThreshold() external view returns (uint256);

    function execTransactionFromModule(address to, uint256 value, bytes memory data, Enum.Operation operation)
        external
        returns (bool success);
    function isOwner(address owner) external view returns (bool);

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success);

    function encodeTransactionData(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes memory);
}
