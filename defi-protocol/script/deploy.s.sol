// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "../lib/forge-std/src/Script.sol";
import "../src/Token.sol";
import "../src/Strategy.sol";
import "../src/Controller.sol";
import "../src/Vault.sol";

contract DeployProtocol is Script {
    function run() external {
        vm.startBroadcast();

        Token token = new Token();
        token.initialize("ResearchToken", "RST", 1_000_000 ether, msg.sender);

        Strategy strategy = new Strategy();
        Controller controller = new Controller();
        Vault vault = new Vault();

        strategy.initialize(address(token), address(controller), address(vault));
        controller.initialize(address(token), address(strategy));
        vault.initialize(address(token), address(controller));

        strategy.setController(address(controller));
        strategy.setVault(address(vault));

        console2.log("Token:", address(token));
        console2.log("Controller:", address(controller));
        console2.log("Strategy:", address(strategy));
        console2.log("Vault:", address(vault));

        vm.stopBroadcast();
    }
}
