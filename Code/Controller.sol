// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {OwnableUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC20Upgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/token/ERC20/IERC20Upgradeable.sol";
import "../src/Strategy.sol";

interface IStrategy {
    function invest(uint256 amount) external;
    function withdraw(uint256 amount, address to) external returns (uint256);
    function harvest() external returns (uint256);
}

contract Controller is OwnableUpgradeable, UUPSUpgradeable {
    IERC20Upgradeable public token;
    Strategy public strategy;

    event Invest(address indexed user, uint256 amount);
    event Withdraw(address indexed to, uint256 amount);
    event Harvest(uint256 yieldAmount);

    function initialize(address token_, address strategy_) public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        token = IERC20Upgradeable(token_);
        strategy = Strategy(strategy_);
    }

    function invest(uint256 amount) external {
        require(amount > 0, "zero");
        bool ok = token.transferFrom(msg.sender, address(this), amount);
        require(ok, "transferFrom failed");

        token.approve(address(strategy), amount);
        strategy.invest(amount);

        emit Invest(msg.sender, amount);
    }

    // ✅ Fixed: now accepts a `to` argument
    function withdraw(uint256 amount, address to) external returns (uint256) {
        require(amount > 0, "zero");
        uint256 withdrawn = strategy.withdraw(amount, to);
        emit Withdraw(to, withdrawn);
        return withdrawn;
    }

    function harvest() external onlyOwner returns (uint256) {
        uint256 yieldAmount = strategy.harvest();
        emit Harvest(yieldAmount);
        return yieldAmount;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}