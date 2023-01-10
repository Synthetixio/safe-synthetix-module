// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import "./interfaces/IGuard.sol";
import "./interfaces/ISafe.sol";
import "./interfaces/IElectionModule.sol";

import "./SignatureDecoder.sol";

contract SynthetixSafeModule is IGuard, SignatureDecoder {

    // required constants from gnosis

    // keccak256(
    //     "EIP712Domain(uint256 chainId,address verifyingContract)"
    // );
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;
    ISafe public safe;

    IElectionModule public electionSystem;

    ISafe public pdaoSafe;

    // the number of votes required from the pdao to pass
    uint public pdaoThreshold;

    constructor(ISafe _safe, IElectionModule _electionSystem, ISafe _pdaoSafe) {
        safe = _safe;
        electionSystem = _electionSystem;
        pdaoSafe = _pdaoSafe;
    }

    function setPdaoThreshold(uint threshold) external {
        require(msg.sender == address(pdaoSafe), "pdao only");

        pdaoThreshold = threshold;
    }

    /**
     * Ensures that the `safe` configured signers includes both the elected members from the election module, as well as the pdao signers.
     * NOTE: Anyone can call this function, but this function can only set signers to those in the pdao safe and electionSystem. If
     * you are a script kitty looking at this function and are wondering, execute this at your own expense :)
     */
    function resetSafeSigners() external {
        // get the actual signers to set
        address[] memory electedCouncilSigners = electionSystem.getCouncilMembers();
        address[] memory pdaoSigners = pdaoSafe.getOwners();

        uint requiredSigners = electedCouncilSigners.length / 2 + 1;

        // remove all signers currently on the target safe except one (because gnosis does not allow no signers)
        address[] memory oldSigners = safe.getOwners();
        for (uint i = 1;i < oldSigners.length;i++) {
            safe.removeOwner(oldSigners[0], oldSigners[i], 1);
        }

        // add new signers to the target safe
        for (uint i = 0; i < electedCouncilSigners.length; i++) {
            if (oldSigners.length > 0 && electedCouncilSigners[i] == oldSigners[0]) {
                oldSigners = new address[](0);
            }
            else {
                safe.addOwnerWithThreshold(electedCouncilSigners[i], 1);
            }
        }

        for (uint i = 0; i < pdaoSigners.length; i++) {
            if (oldSigners.length > 0 && pdaoSigners[i] == oldSigners[0]) {
                oldSigners = new address[](0);
            }
            else {
                safe.addOwnerWithThreshold(pdaoSigners[i], requiredSigners);
            }
        }

        if (oldSigners.length > 0) {
            safe.removeOwner(pdaoSigners[pdaoSigners.length - 1], oldSigners[0], requiredSigners);
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
        address msgSender
    ) external {

        bytes memory txHashData;
        {
            txHashData = encodeTransactionData(
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
                safe.nonce() - 1
            );
        }
        
        address[] memory electedCouncilSigners = electionSystem.getCouncilMembers();
        address[] memory pdaoSigners = pdaoSafe.getOwners();

        uint electedCount = 0;
        uint pdaoCount = 0;

        uint8 v;
        bytes32 r;
        bytes32 s;
        address curOwner;

        for (uint j = 0;j < signatures.length / 65;j++) {
            (v, r, s) = signatureSplit(signatures, j);
            if (v == 0) {
                revert("Contract signatures are not supported by this module");
            } else if (v == 1) {
                // v ==1 means that the sender is approving the txn, or its an approvedHash (which we are not going to deal with here)
                curOwner = msgSender;
            } else if (v > 30) {
                // To support eth_sign and similar we adjust v and hash the transferHashData with the Ethereum message prefix before applying ecrecover
                curOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(txHashData))), v - 4, r, s);
            } else {
                // Use ecrecover with the messageHash for EOA signatures
                curOwner = ecrecover(keccak256(txHashData), v, r, s);
            }
            // 0 for the recovered owner indicates that an error happened.
            require(curOwner != address(0), "curOwner != address(0)");

            if (electedCount < electedCouncilSigners.length / 2 + 1) {
                for (uint i = 0;i < electedCouncilSigners.length;i++) {
                    if (electedCouncilSigners[i] == curOwner) {
                        electedCount++;
                        break;
                    }
                }
            }

            if (pdaoCount < pdaoThreshold) {
                for (uint i = 0;i < electedCouncilSigners.length;i++) {
                    if (pdaoSigners[i] == curOwner) {
                        pdaoCount++;
                        break;
                    }
                }
            }
        }

        require(electedCount >= electedCouncilSigners.length / 2 + 1, "Insufficient council signers");
        require(pdaoCount >= pdaoThreshold, "Insufficient pdao signers");
    }

    function checkAfterExecution(bytes32 txHash, bool success) external {}

    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return
            interfaceId == type(IGuard).interfaceId || // 0xe6d7a83a
            interfaceId == type(IERC165).interfaceId; // 0x01ffc9a7
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

    function domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, getChainId(), this));
    }

    /// @dev Returns the bytes that are hashed to be signed by owners.
    /// @param to Destination address.
    /// @param value Ether value.
    /// @param data Data payload.
    /// @param operation Operation type.
    /// @param safeTxGas Gas that should be used for the safe transaction.
    /// @param baseGas Gas costs for that are independent of the transaction execution(e.g. base transaction fee, signature check, payment of the refund)
    /// @param gasPrice Maximum gas price that should be used for this transaction.
    /// @param gasToken Token address (or 0 if ETH) that is used for the payment.
    /// @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
    /// @param _nonce Transaction nonce.
    /// @return Transaction hash bytes.
    function encodeTransactionData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes memory) {
        bytes32 safeTxHash =
            keccak256(
                abi.encode(
                    SAFE_TX_TYPEHASH,
                    to,
                    value,
                    keccak256(data),
                    operation,
                    safeTxGas,
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    _nonce
                )
            );
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), safeTxHash);
    }
}