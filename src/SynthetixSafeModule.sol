// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "./interfaces/IGuard.sol";
import "./interfaces/ISafe.sol";
import "./interfaces/IElectionModule.sol";

import "./SignatureDecoder.sol";

import "forge-std/console.sol";

contract SynthetixSafeModule is IGuard, SignatureDecoder {
    // required constants from gnosis

    // keccak256(
    //     "EIP712Domain(uint256 chainId,address verifyingContract)"
    // );
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    event PdaoThresholdChanged(uint256 threshold);

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    error Unauthorized(address msgSender);
    error InvalidParameter(bytes32 parameter, bytes32 reason);
    error SafeCallFailed(address safe, bytes attemptedCall);
    error InsufficientSigners(bytes32 group, uint256 required, uint256 provided);
    error IncorrectSignature(address curOwner, uint8 v, bytes32 r, bytes32 s);
    error ContractSignaturesUnsupported();

    IElectionModule public electionSystem;

    ISafe public pdaoSafe;

    // the number of votes required from the pdao to pass
    uint256 public pdaoThreshold;

    constructor(IElectionModule _electionSystem, ISafe _pdaoSafe) {
        electionSystem = _electionSystem;
        pdaoSafe = _pdaoSafe;
    }

    function setPdaoThreshold(uint256 threshold) external {
        if (msg.sender != address(pdaoSafe)) {
            revert Unauthorized(msg.sender);
        }

        if (threshold > pdaoSafe.getThreshold()) {
            revert InvalidParameter("threshold", "greater than pdao safe threshold");
        }

        pdaoThreshold = threshold;

        emit PdaoThresholdChanged(threshold);
    }

    /**
     * Ensures that the `safe` configured signers includes both the elected members from the election module, as well as the pdao signers.
     * NOTE: Anyone can call this function, but this function can only set signers to those in the pdao safe and electionSystem. If
     * you are a script kitty looking at this function and are wondering, execute this at your own expense :)
     */
    function resetSafeSigners(ISafe targetSafe) external {
        // get the actual signers to set
        (
            address[] memory electedCouncilSigners,
            uint256 electedCouncilThreshold,
            address[] memory pdaoSigners,
            uint256 pdaoThresh
        ) = getSignerInfo();

        uint256 requiredSigners = electedCouncilThreshold + pdaoThresh;

        // remove all signers currently on the target safe except one (because gnosis does not allow no signers)
        address[] memory oldSigners = targetSafe.getOwners();
        for (uint256 i = 1; i < oldSigners.length; i++) {
            execOnSafe(targetSafe, abi.encodeWithSelector(ISafe.removeOwner.selector, oldSigners[0], oldSigners[i], 1));
        }

        // add new signers to the target safe
        uint256 addedSigners = 0;
        for (uint256 i = 0; i < pdaoSigners.length; i++) {
            if (oldSigners.length > 0 && pdaoSigners[i] == oldSigners[0]) {
                oldSigners = new address[](0);
            } else {
                execOnSafe(
                    targetSafe,
                    abi.encodeWithSelector(
                        ISafe.addOwnerWithThreshold.selector,
                        pdaoSigners[i],
                        requiredSigners < ++addedSigners ? requiredSigners : addedSigners
                    )
                );
            }
        }

        for (uint256 i = 0; i < electedCouncilSigners.length; i++) {
            if (oldSigners.length > 0 && electedCouncilSigners[i] == oldSigners[0]) {
                oldSigners = new address[](0);
            } else if (!targetSafe.isOwner(electedCouncilSigners[i])) {
                execOnSafe(
                    targetSafe,
                    abi.encodeWithSelector(
                        ISafe.addOwnerWithThreshold.selector,
                        electedCouncilSigners[i],
                        requiredSigners < ++addedSigners ? requiredSigners : addedSigners
                    )
                );
            }
        }

        if (oldSigners.length > 0) {
            execOnSafe(
                targetSafe,
                abi.encodeWithSelector(ISafe.removeOwner.selector, pdaoSigners[0], oldSigners[0], requiredSigners)
            );
        }
    }

    /**
     * Ensures that a minimum number of pdao signers have signed this txn
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address
    ) external view {
        bytes memory txHashData;
        {
            txHashData = ISafe(msg.sender).encodeTransactionData(
                // Transaction info
                to,
                value,
                data,
                operation,
                safeTxGas,
                // Payment info
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                // Signature info
                ISafe(msg.sender).nonce() - 1
            );
        }

        (
            address[] memory electedCouncilSigners,
            uint256 electedCouncilThreshold,
            address[] memory pdaoSigners,
            uint256 pdaoThresh
        ) = getSignerInfo();

        uint256 electedCount = 0;
        uint256 pdaoCount = 0;

        uint8 v;
        bytes32 r;
        bytes32 s;
        address lastOwner;
        address curOwner;

        for (uint256 j = 0; j < signatures.length / 65; j++) {
            (v, r, s) = signatureSplit(signatures, j);
            if (v == 0) {
                revert ContractSignaturesUnsupported();
            } else if (v == 1) {
                // v == 1 means that the sender is approving the txn, or its an approvedHash
								// in either case, safe has already verified `r` is valid so we just need to record the value inside here
                curOwner = address(uint160(uint256(r)));
            } else if (v > 30) {
                // To support eth_sign and similar we adjust v and hash the transferHashData with the Ethereum message prefix before applying ecrecover
                curOwner = ecrecover(
                    keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(txHashData))), v - 4, r, s
                );
            } else {
                // Use ecrecover with the messageHash for EOA signatures
                curOwner = ecrecover(keccak256(txHashData), v, r, s);
            }

            // 0 for the recovered owner indicates that an error happened.
            if (curOwner <= lastOwner || curOwner == address(0)) {
                revert IncorrectSignature(curOwner, v, r, s);
            }

            if (electedCount < electedCouncilSigners.length / 2 + 1) {
                for (uint256 i = 0; i < electedCouncilSigners.length; i++) {
                    if (electedCouncilSigners[i] == curOwner) {
                        electedCount++;
                        break;
                    }
                }
            }

            if (pdaoCount < pdaoThreshold) {
                for (uint256 i = 0; i < pdaoSigners.length; i++) {
                    if (pdaoSigners[i] == curOwner) {
                        pdaoCount++;
                        break;
                    }
                }
            }

            lastOwner = curOwner;
        }

        if (electedCount < electedCouncilThreshold) {
            revert InsufficientSigners("council", electedCouncilSigners.length / 2 + 1, electedCount);
        }

        if (pdaoCount < pdaoThresh) {
            revert InsufficientSigners("pdao", pdaoThreshold, pdaoCount);
        }
    }

    function checkAfterExecution(bytes32 txHash, bool success) external {}

    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return interfaceId == type(IGuard).interfaceId // 0xe6d7a83a
            || interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
    }

    // functions ripped from gnosis safe contract needed for verification:

    /// @dev Returns the chain id used by this contract.
    function getChainId() public view returns (uint256) {
        uint256 id;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := chainid()
        }
        return id;
    }

    function getSignerInfo()
        internal
        view
        returns (
            address[] memory electedCouncilSigners,
            uint256 electedCouncilThreshold,
            address[] memory pdaoSigners,
            uint256 pdaoThres
        )
    {
        electedCouncilSigners = electionSystem.getCouncilMembers();
        pdaoSigners = pdaoSafe.getOwners();

        electedCouncilThreshold = electedCouncilSigners.length / 2 + 1;
        pdaoThres = pdaoThreshold;
    }

    function execOnSafe(ISafe safe, bytes memory call) internal {
        bool success = safe.execTransactionFromModule(address(safe), 0, call, Enum.Operation.Call);

        if (!success) {
            revert SafeCallFailed(address(safe), call);
        }
    }
}
