// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LendingPool} from "../src/LendingPool.sol";
import {Oracle} from "../src/utils/Oracle.sol";
import {AToken} from "../src/tokens/AToken.sol";
import {DebtToken} from "../src/tokens/DebtToken.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {InterestRateModel} from "../src/utils/InterestRateModel.sol";

contract MockERC20 is ERC20 {
    constructor(string memory n, string memory s, uint256 supply) ERC20(n, s) {
        _mint(msg.sender, supply);
    }

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}

contract LendingPoolTest is Test {
    LendingPool pool;
    Oracle oracle;
    MockERC20 dai;
    MockERC20 weth;
    AToken aDai;
    DebtToken dDai;
    AToken aWeth;
    DebtToken dWeth;

    address alice;
    address bob;

    function setUp() public {
        // --- Setup test accounts ---
        alice = address(0xA11ce);
        bob = address(0xB0b);

        // --- Deploy Oracle and LendingPool ---
        oracle = new Oracle();
        pool = new LendingPool(address(oracle));

        // --- Deploy mock ERC20 tokens ---
        dai = new MockERC20("Mock DAI", "DAI", 1e24); // 1M DAI
        weth = new MockERC20("Mock WETH", "WETH", 1e24); // 1M WETH

        // --- Deploy AToken and DebtToken (owner initially = this test contract) ---
        aDai = new AToken("aDAI", "aDAI", address(this));
        dDai = new DebtToken("dDAI", "dDAI", address(this));
        aWeth = new AToken("aWETH", "aWETH", address(this));
        dWeth = new DebtToken("dWETH", "dWETH", address(this));

        // --- Debug logs (optional) ---
        emit log_named_address("pool owner", pool.owner());
        emit log_named_address("aDai owner (before)", aDai.owner());
        emit log_named_address("aWeth owner (before)", aWeth.owner());
        emit log_named_address("test contract", address(this));

        // --- Set underlying tokens as their owner (address(this) currently owns aTokens) ---
        // No vm.prank needed: aDai.owner() == address(this)
        aDai.setUnderlying(address(dai));
        aWeth.setUnderlying(address(weth));

        // --- Transfer ownership of aTokens and debt tokens to the pool so pool can call setPool() ---
        // AToken::setPool is onlyOwner, so the pool must be owner before listReserve.
        aDai.transferOwnership(address(pool));
        dDai.transferOwnership(address(pool));
        aWeth.transferOwnership(address(pool));
        dWeth.transferOwnership(address(pool));

        emit log_named_address("aDai owner (after)", aDai.owner());
        emit log_named_address("aWeth owner (after)", aWeth.owner());

        // --- Now list reserves as pool owner (pool contract itself executes setPool inside) ---
        // We must call listReserve from the pool's owner (which currently is address(this)),
        // because listReserve itself may be onlyOwner on the pool — but in your contracts pool.owner() is address(this).
        // So call normally (address(this) is the owner of pool in these tests).
        // If pool.owner() were different we'd vm.prank(pool.owner()) around these calls.
        pool.listReserve(
            address(dai),
            aDai,
            dDai,
            InterestRateModel(address(0)),
            true,
            7500,
            8000,
            10500
        );
        pool.listReserve(
            address(weth),
            aWeth,
            dWeth,
            InterestRateModel(address(0)),
            true,
            7000,
            7500,
            10750
        );

        // --- Set prices in oracle ---
        oracle.setPrice(address(dai), int256(1 * 1e8)); // DAI = $1
        oracle.setPrice(address(weth), int256(3000 * 1e8)); // WETH = $3000

        // --- Mint tokens to users ---
        dai.mint(alice, 1000 ether);
        weth.mint(bob, 10 ether);

        // --- Approve pool for transfers from users ---
        vm.prank(alice);
        dai.approve(address(pool), type(uint256).max);
        vm.prank(bob);
        weth.approve(address(pool), type(uint256).max);
    }

    function testDepositBorrowRepayWithdraw() public {
        // --- Alice deposits 1000 DAI ---
        vm.prank(alice);
        pool.deposit(address(dai), 1000 ether);
        assertEq(aDai.balanceOf(alice), 1000 ether, "aDAI balance mismatch");

        // --- Bob deposits 10 WETH ---
        vm.prank(bob);
        pool.deposit(address(weth), 10 ether);
        assertEq(aWeth.balanceOf(bob), 10 ether, "aWETH balance mismatch");

        // --- Bob borrows 1000 DAI ---
        vm.prank(bob);
        pool.borrow(address(dai), 1000 ether);
        assertEq(dDai.balanceOf(bob), 1000 ether, "debt token mismatch");

        // --- Bob repays 500 DAI ---
        dai.mint(bob, 500 ether);
        vm.prank(bob);
        dai.approve(address(pool), 500 ether);
        vm.prank(bob);
        pool.repay(address(dai), 500 ether);
        assertEq(dDai.balanceOf(bob), 500 ether, "partial repay mismatch");

        // --- Alice withdraws 100 DAI ---
        vm.prank(alice);
        pool.withdraw(address(dai), 100 ether);
        assertEq(aDai.balanceOf(alice), 900 ether, "withdraw mismatch");
    }
}
