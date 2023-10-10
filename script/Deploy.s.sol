// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "@openzeppelin/contracts/proxy/Clones.sol";

import "safe-contracts/contracts/SafeL2.sol";
import "safe-contracts/contracts/proxies/SafeProxyFactory.sol";

import {SynthetixSafeModule, IElectionModule, ISafe} from "../src/SynthetixSafeModule.sol";
import {SynthetixSafeModuleRegistration} from "../src/SynthetixSafeModuleRegistration.sol";
import "../src/DummySafe.sol";
import {SynthetixSafeModuleOld} from "../src/SynthetixSafeModuleOld.sol";

contract DeployScript is Script {
    address internal account;

    // TODO change this to 0 when in prod
    uint256 internal customSalt = 1;
    string internal result;

    mapping(string => address) internal register;

    SafeProxyFactory internal factory = SafeProxyFactory(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2);
    address internal singleton = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;

    function setUp() public {}

    function run() public virtual {
        connect();
        deployAll();
        disconnect();

        vm.writeFile(string(abi.encodePacked("deployment.", getChain(getChainId()).name, ".txt")), result);
    }

    function connect() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        account = vm.rememberKey(deployerPrivateKey);

        vm.startBroadcast(account);

        console.log("deployer", account);
    }

    function disconnect() public {
        vm.stopBroadcast();
    }

    function deployAll() public {
        createSafe("CC_TOKEN");
        createSafe("CC");
        createSafe("ECOSYSTEM");
        createSafe("TRADER");
        createSafe("TREASURY");
        createSafe("INFINEX");
    }

    function getChainId() private view returns (uint256 chainId) {
        // Assembly required since `block.chainid` was introduced in 0.8.0.
        assembly {
            chainId := chainid()
        }

        address(this); // Silence warnings in older Solc versions.
    }

    function createSafe(string memory saltString) internal returns (address safe) {
        address[] memory owners = new address[](1);
        owners[0] = account;

        bytes memory data = abi.encodeWithSelector(
            Safe.setup.selector, owners, 1, address(0), "", address(0), address(0), 0, payable(address(0))
        );

        uint256 saltNonce = uint256(keccak256(abi.encodePacked(saltString, customSalt)));
        bytes32 initHash = hashInitCode(abi.encodePacked(factory.proxyCreationCode(), uint256(uint160(singleton))));
        safe = payable(
            computeCreate2Address(keccak256(abi.encodePacked(keccak256(data), saltNonce)), initHash, address(factory))
        );

        result = string(abi.encodePacked(result, saltString, "_SAFE=", vm.toString(safe), "\n"));
        register[string(abi.encodePacked(saltString, "_SAFE"))] = safe;

        if (safe.code.length > 0) {
            return safe;
        }

        factory.createProxyWithNonce(singleton, data, uint256(saltNonce));
    }
}
