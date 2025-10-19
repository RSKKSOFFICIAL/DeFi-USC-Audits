// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/Token.sol";
import "../src/Strategy.sol";
import "../src/Controller.sol";
import "../src/Vault.sol";

contract VaultTest is Test {
    Token token;
    Strategy strategy;
    Controller controller;
    Vault vault;
    address user1 = address(0xAAA);
    address user2 = address(0xBBB);

    function setUp() public {
        // Deploy contracts
        token = new Token();
        token.initialize("ResearchToken", "RST", 1_000_000 ether, address(this));

        strategy = new Strategy();
        controller = new Controller();
        vault = new Vault();

        // Link and initialize
        strategy.initialize(address(token), address(controller), address(vault));
        controller.initialize(address(token), address(strategy));
        vault.initialize(address(token), address(controller));

        // Grant mutual references
        strategy.setController(address(controller));
        strategy.setVault(address(vault));

        // Mint to users
        token.mint(user1, 10_000 ether);
        token.mint(user2, 10_000 ether);

        vm.startPrank(user1);
        token.approve(address(vault), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(user2);
        token.approve(address(vault), type(uint256).max);
        vm.stopPrank();
    }

    /// 🧩 Test 1: Deposits mint proportional shares
    function testDepositSharesMinted() public {
        vm.startPrank(user1);
        vault.deposit(1_000 ether);
        vm.stopPrank();

        assertEq(vault.totalShares(), 1_000 ether, "Shares should equal deposit on first deposit");
        assertEq(vault.shares(user1), 1_000 ether, "User1 should get all shares");
    }

    /// 🧩 Test 2: Withdraw returns correct amount of tokens
    function testWithdrawReturnsTokens() public {
        vm.startPrank(user1);
        vault.deposit(1_000 ether);
        vm.stopPrank();

        vm.startPrank(user1);
        vault.withdraw(1_000 ether);
        vm.stopPrank();

        assertApproxEqAbs(token.balanceOf(user1), 10_000 ether, 1, "User should get their tokens back");
    }

    /// 🧩 Test 3: Harvest increases vault total assets
    function testHarvestIncreasesAssets() public {
        vm.startPrank(user1);
        vault.deposit(1_000 ether);
        vm.stopPrank();

        // Simulate yield in strategy
        token.mint(address(strategy), 100 ether);

        uint256 beforeAssets = token.balanceOf(address(vault)) + token.balanceOf(address(controller));
        controller.harvest();
        uint256 afterAssets = token.balanceOf(address(vault)) + token.balanceOf(address(controller));

        assertGt(afterAssets, beforeAssets, "Harvest should increase total assets");
    }
}
