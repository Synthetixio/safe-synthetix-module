// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "@openzeppelin/contracts/proxy/Clones.sol";

import "safe-contracts/contracts/SafeL2.sol";

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

    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        address ECOSYSTEM_COUNCIL_ADDRESS = vm.envAddress("ECOSYSTEM_COUNCIL_ADDRESS");
        address TREASURY_COUNCIL_ADDRESS = vm.envAddress("TREASURY_COUNCIL_ADDRESS");
        address TRADER_COUNCIL_ADDRESS = vm.envAddress("TRADER_COUNCIL_ADDRESS");
        address CC_COUNCIL_ADDRESS = vm.envAddress("CC_COUNCIL_ADDRESS");

        registration = getRegistration();
        dummySafe = getDummySafe();
        proxySafe = getSafe();

        address ccSafe = deploySafeAndModule("CC_COUNCIL_ADDRESS", "CoreContributor", dummySafe, 0);
        address ecosystemSafe = deploySafeAndModule("ECOSYSTEM_COUNCIL_ADDRESS", "Ecosystem", ccSafe, 0);
        address traderSafe = deploySafeAndModule("TRADER_COUNCIL_ADDRESS", "Trader", ecosystemSafe, 0);
        address treasurySafe = deploySafeAndModule("TREASURY_COUNCIL_ADDRESS", "Treasury", traderSafe, 1);
        address infinexSafe = deploySafeAndModule("", "Infinex", treasurySafe, 0);

        console.log("CoreContriubtorSafe", address(ccSafe));
        console.log("TreasurySafe", address(treasurySafe));
        console.log("InfinexSafe", address(infinexSafe));

        vm.stopBroadcast();
    }

    function deploySafeAndModule(string memory envName, string memory saltName, address prevSafe, uint256 initialVeto)
        internal
        returns (address safe)
    {
        address module = bytes(envName).length > 0
            ? address(createSafeModule(saltName, vm.envAddress(envName), prevSafe, initialVeto))
            : dummySafe;
        return address(createSafe(proxySafe, "CCSafe", module, registration));
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

    function createSafe(address safeAddress, string memory saltString, address module, address registration)
        internal
        returns (SafeL2 safe)
    {
        bytes32 salt = keccak256(bytes(saltString));
        safe = SafeL2(payable(Clones.predictDeterministicAddress(safeAddress, salt, CREATE2_FACTORY)));

        if (address(safe).code.length > 0) {
            return safe;
        }

        Clones.cloneDeterministic(safeAddress, salt);

        address[] memory owners = new address[](1);
        owners[0] = 0x0000000000000000000000000000000000000010;

        safe.setup(
            owners,
            1,
            registration,
            abi.encodeWithSelector(SynthetixSafeModuleRegistration.setup.selector, module),
            address(0),
            address(0),
            0,
            payable(address(0))
        );
    }

    function createSafeModule(string memory saltString, address electionModule, address safe, uint256 initialVeto)
        internal
        returns (SynthetixSafeModule module)
    {
        bytes32 salt = keccak256(bytes(saltString));
        bytes32 initCode =
            hashInitCode(type(SynthetixSafeModule).creationCode, abi.encode(electionModule, safe, initialVeto));
        module = SynthetixSafeModule(computeCreate2Address(salt, initCode));

        if (address(module).code.length > 0) {
            return module;
        }

        new SynthetixSafeModule{salt: salt}(IElectionModule(electionModule), ISafe(safe), initialVeto);
    }
}
