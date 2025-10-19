// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/Token.sol";
import "../src/Strategy.sol";
import "../src/Controller.sol";

contract ControllerTest is Test {
    Token token;
    Strategy strategy;
    Controller controller;
    address user = address(0x123);

    function setUp() public {
        token = new Token();
        token.initialize("ControllerToken", "CTL", 1_000_000 ether, address(this));
        strategy = new Strategy();
        controller = new Controller();
        strategy.initialize(address(token), address(controller), address(0));
        controller.initialize(address(token), address(strategy));
        token.mint(user, 10_000 ether);
        vm.startPrank(user);
        token.approve(address(controller), type(uint256).max);
        vm.stopPrank();
    }

    function testInvestAndHarvest() public {
        vm.startPrank(user);
        controller.invest(1_000 ether);
        vm.stopPrank();

        assertEq(token.balanceOf(address(strategy)), 1_000 ether);

        // simulate yield
        token.mint(address(strategy), 100 ether);
        uint256 harvested = controller.harvest();
        assertEq(harvested, 100 ether, "Harvested yield");
    }
}
