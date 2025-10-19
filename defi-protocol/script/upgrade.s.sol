// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../lib/forge-std/src/Script.sol";
import "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import "../src/Vault.sol";

contract UpgradeVault is Script {
    function run() external {
        address proxyAddress = vm.envAddress("VAULT_PROXY");
        vm.startBroadcast();

        Vault newImplementation = new Vault();
        Vault(proxyAddress).upgradeTo(address(newImplementation));

        console2.log("Vault upgraded at proxy:", proxyAddress);
        console2.log("New implementation:", address(newImplementation));

        vm.stopBroadcast();
    }
}
