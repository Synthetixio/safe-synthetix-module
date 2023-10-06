// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "@openzeppelin/contracts/proxy/Clones.sol";

import "safe-contracts/contracts/SafeL2.sol";
import "safe-contracts/contracts/proxies/SafeProxyFactory.sol";

import {SynthetixSafeModule, IElectionModule, ISafe} from "../src/SynthetixSafeModule.sol";
import {SynthetixSafeModuleRegistration} from "../src/SynthetixSafeModuleRegistration.sol";

contract DummySafe {
    function getOwners() external pure returns (address[] memory addresses) {
        addresses = new address[](0);
    }

    function getCouncilMembers() external pure returns (address[] memory addresses) {
        addresses = new address[](0);
    }
}

contract DeployScript is Script {
    address internal registration;
    address internal proxySafe;
    address internal dummySafe;
    address internal account;

    SafeProxyFactory internal factory = SafeProxyFactory(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2);

    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        account = vm.rememberKey(deployerPrivateKey);

        vm.startBroadcast(account);

        console.log(account);

        registration = getRegistration();
        dummySafe = getDummySafe();
        proxySafe = getSafe();

        address ccSafe = deploySafeAndModule("CC_COUNCIL_ADDRESS", "CoreContributor", dummySafe, 0);
        address ccTokenSafe = deploySafeAndModule("CC_TOKEN_ADDRESS", "CCToken", dummySafe, 0);
        address ecosystemSafe = deploySafeAndModule("ECOSYSTEM_COUNCIL_ADDRESS", "Ecosystem", ccSafe, 0);
        address traderSafe = deploySafeAndModule("TRADER_COUNCIL_ADDRESS", "Trader", ecosystemSafe, 0);
        address treasurySafe = deploySafeAndModule("TREASURY_COUNCIL_ADDRESS", "Treasury", traderSafe, 1);
        address infinexSafe = deploySafeAndModule("", "Infinex", treasurySafe, 0);

        console.log("CoreContriubtorSafe", address(ccTokenSafe));
        console.log("TreasurySafe", address(treasurySafe));
        console.log("InfinexSafe", address(infinexSafe));

        vm.stopBroadcast();
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
        return address(createSafe(proxySafe, saltName, module));
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

    function getRegistration() internal returns (address safeAddress) {
        bytes32 initCode = hashInitCode(type(SynthetixSafeModuleRegistration).creationCode);
        safeAddress = computeCreate2Address(0, initCode);

        if (safeAddress.code.length > 0) {
            return safeAddress;
        }

        new SynthetixSafeModuleRegistration{salt: 0}();
    }

    function createSafe(address safeAddress, string memory saltString, address module)
        internal
        returns (SafeL2 safe)
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

        uint256 saltNonce = uint256(keccak256(abi.encodePacked(saltString, module, safeAddress)));
        bytes32 initHash = hashInitCode(abi.encodePacked(factory.proxyCreationCode(), uint256(uint160(safeAddress))));
        safe = SafeL2(payable(computeCreate2Address(keccak256(abi.encodePacked(keccak256(data), saltNonce)), initHash, address(factory))));

        if (address(safe).code.length > 0) {
            return safe;
        }

        console.log(saltString, address(factory.createProxyWithNonce(safeAddress, data, uint256(saltNonce))));
    }

    function createSafeModule(string memory saltString, address electionModule, address safe, uint256 initialVeto)
        internal
        returns (SynthetixSafeModule module)
    {
        bytes32 salt = keccak256(abi.encodePacked(saltString));
        bytes32 initCode =
            hashInitCode(type(SynthetixSafeModule).creationCode, abi.encode(electionModule, safe, initialVeto));
        module = SynthetixSafeModule(computeCreate2Address(salt, initCode));

        if (address(module).code.length > 0) {
            return module;
        }

        new SynthetixSafeModule{salt: salt}(IElectionModule(electionModule), ISafe(safe), initialVeto);
    }
}
