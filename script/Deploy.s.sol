// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "@openzeppelin/contracts/proxy/Clones.sol";

import "safe-contracts/contracts/SafeL2.sol";
import "safe-contracts/contracts/proxies/SafeProxyFactory.sol";

import {SynthetixSafeModule, IElectionModule, ISafe} from "../src/SynthetixSafeModule.sol";
import {SynthetixSafeModuleRegistration} from "../src/SynthetixSafeModuleRegistration.sol";
import "../src/DummySafe.sol";

contract DeployScript is Script {
    address internal registration;
    address internal dummySafe;
    address internal account;

    string internal result;
    mapping(string => address) internal register;

    SafeProxyFactory internal factory = SafeProxyFactory(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2);
    address internal singleton = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;

    struct StoreToJson {
        address CC_SAFE;
        address TREASURY_SAFE;
        address INFINEX_SAFE;
    }

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
        registration = getRegistration();
        dummySafe = getDummySafe();

        console.log("DUMMY_SAFE", address(dummySafe));

        deploySafeAndModule("CC_TOKEN", "CC_TOKEN", dummySafe, 0);

        address ccSafe = deploySafeAndModule("CORE_CONTRIBUTOR_COUNCIL", "CC", dummySafe, 0);
        address ecosystemSafe = deploySafeAndModule("ECOSYSTEM_COUNCIL", "ECOSYSTEM", ccSafe, 0);
        address traderSafe = deploySafeAndModule("TRADER_COUNCIL", "TRADER", ecosystemSafe, 0);
        address treasurySafe = deploySafeAndModule("TREASURY_COUNCIL", "TREASURY", traderSafe, 1);
        deploySafeAndModule("", "INFINEX", treasurySafe, 0);
    }

    function getChainId() private view returns (uint256 chainId) {
        // Assembly required since `block.chainid` was introduced in 0.8.0.
        assembly {
            chainId := chainid()
        }

        address(this); // Silence warnings in older Solc versions.
    }

    function deploySafeAndModule(string memory envName, string memory saltName, address prevSafe, uint256 initialVeto)
        internal
        returns (address safe)
    {
        console.log("deploying", envName, saltName, "safe");
        address module = address(
            createSafeModule(
                saltName, bytes(envName).length > 0 ? vm.envAddress(envName) : dummySafe, prevSafe, initialVeto
            )
        );
        return address(createSafe(saltName, module));
    }

    function getSafe() internal returns (address safe) {
        bytes32 initCode = hashInitCode(type(SafeL2).creationCode);
        safe = computeCreate2Address(0, initCode);

        if (address(safe).code.length > 0) {
            return safe;
        }

        new SafeL2{salt: 0}();
    }

    function getDummySafe() internal returns (address dummy) {
        bytes32 initCode = hashInitCode(type(DummySafe).creationCode);
        dummy = computeCreate2Address(0, initCode);

        if (dummy.code.length > 0) {
            return dummy;
        }

        new DummySafe{salt: 0}();
    }

    function getRegistration() internal returns (address module) {
        bytes32 initCode = hashInitCode(type(SynthetixSafeModuleRegistration).creationCode);
        module = computeCreate2Address(0, initCode);

        if (module.code.length > 0) {
            return module;
        }

        new SynthetixSafeModuleRegistration{salt: 0}();
    }

    function createSafe(string memory saltString, address module)
        internal
        returns (Safe safe)
    {
        address[] memory owners = new address[](1);
        owners[0] = account;

        bytes memory data = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            1,
            registration,
            abi.encodeWithSelector(SynthetixSafeModuleRegistration.setup.selector, module),
            address(0),
            address(0),
            0,
            payable(address(0))
        );

        uint256 saltNonce = uint256(keccak256(abi.encodePacked(saltString, module, singleton)));
        bytes32 initHash = hashInitCode(abi.encodePacked(factory.proxyCreationCode(), uint256(uint160(singleton))));
        safe = Safe(payable(computeCreate2Address(keccak256(abi.encodePacked(keccak256(data), saltNonce)), initHash, address(factory))));

        result = string(abi.encodePacked(result, saltString, "_SAFE=", vm.toString(address(safe)), "\n"));
        register[string(abi.encodePacked(saltString, "_SAFE"))] = address(safe);

        if (address(safe).code.length > 0) {
            return safe;
        }

        factory.createProxyWithNonce(singleton, data, uint256(saltNonce));
    }

    function createSafeModule(string memory saltString, address electionModule, address safe, uint256 initialVeto)
        internal
        returns (SynthetixSafeModule module)
    {
        bytes32 salt = keccak256(abi.encodePacked(saltString));
        bytes32 initCode =
            hashInitCode(type(SynthetixSafeModule).creationCode, abi.encode(electionModule, safe, initialVeto));
        module = SynthetixSafeModule(computeCreate2Address(salt, initCode));

        result = string(abi.encodePacked(result, saltString, "_MODULE=", vm.toString(address(module)), "\n"));
        register[string(abi.encodePacked(saltString, "_MODULE"))] = address(module);

        if (address(module).code.length > 0) {
            return module;
        }

        new SynthetixSafeModule{salt: salt}(IElectionModule(electionModule), ISafe(safe), initialVeto);
    }
}
