// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./Deploy.s.sol";

contract ResetModulesScript is DeployScript {
    address internal registration;
    address internal dummySafe;

    function run() public virtual override {
        connect();

        deployAll();

        registration = getRegistration();
        dummySafe = getDummySafe();

        updateModuleForSafe("CC_TOKEN", vm.envAddress("CC_TOKEN"), dummySafe, false);
        updateModuleForSafe("CC", vm.envAddress("CORE_CONTRIBUTOR_COUNCIL"), dummySafe, true);
        updateModuleForSafe("ECOSYSTEM", vm.envAddress("ECOSYSTEM_COUNCIL"), register["CC_SAFE"], true);
        updateModuleForSafe("TRADER", vm.envAddress("TRADER_COUNCIL"), register["ECOSYSTEM_SAFE"], true);
        updateModuleForSafe("TREASURY", vm.envAddress("TREASURY_COUNCIL"), register["TRADER_SAFE"], true);
        updateModuleForSafe("INFINEX", dummySafe, register['TREASURY_SAFE'], true);

        disconnect();
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

    function updateModuleForSafe(string memory name, address electionModule, address vetoSafe, bool newVersion) internal {
        Safe safe = Safe(payable(register[string(abi.encodePacked(name, "_SAFE"))]));

        address module = createModule(name, electionModule, vetoSafe, newVersion);

        if (!safe.isModuleEnabled(module)) {
            safe.execTransaction(
                registration,
                0,
                abi.encodeWithSelector(SynthetixSafeModuleRegistration.setup.selector, module),
                Enum.Operation.DelegateCall,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                abi.encodePacked(abi.encode(account, bytes32(0)), uint8(1))
            );
        }

        SynthetixSafeModule(module).resetSafeSigners(ISafe(address(safe)));
    }

    function createModule(string memory saltString, address electionModule, address safe, bool inversed)
    internal
    returns (address module)
    {
        bytes32 salt = keccak256(abi.encodePacked(saltString, customSalt));
        if (inversed) {
            bytes32 initCode =
                            hashInitCode(type(SynthetixSafeModule).creationCode, abi.encode(electionModule, safe));
            module = computeCreate2Address(salt, initCode);

            if (address(module).code.length == 0) {
                new SynthetixSafeModule{salt: salt}(IElectionModule(electionModule), ISafe(safe));
            }
        } else {
            bytes32 initCode =
                            hashInitCode(type(SynthetixSafeModuleOld).creationCode, abi.encode(electionModule, safe));

            module = computeCreate2Address(salt, initCode);

            if (address(module).code.length == 0) {
                new SynthetixSafeModuleOld{salt: salt}(IElectionModule(electionModule), ISafe(safe));
            }
        }

        result = string(abi.encodePacked(result, saltString, "_MODULE=", vm.toString(module), "\n"));
        register[string(abi.encodePacked(saltString, "_MODULE"))] = module;
    }
}
