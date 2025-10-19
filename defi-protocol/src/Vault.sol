// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20Upgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/token/ERC20/IERC20Upgradeable.sol";
import {OwnableUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {Initializable} from "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {Controller} from "./Controller.sol";

interface IController {
    function invest(uint256 amount) external;
    function withdraw(uint256 amount, address to) external returns (uint256);
    function harvest() external returns (uint256);
    function strategyBalance() external view returns (uint256);
}

contract Vault is OwnableUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    IERC20Upgradeable public token;
    Controller public controller;

    uint256 public totalShares;
    mapping(address => uint256) public shares;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    function initialize(address token_, address controller_) public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        token = IERC20Upgradeable(token_);
        controller = Controller(controller_);
    }

    /// @notice Deposit tokens into the vault and receive proportional shares
    function deposit(uint256 amount) external nonReentrant {
        require(amount > 0, "zero");

        bool ok = token.transferFrom(msg.sender, address(this), amount);
        require(ok, "transferFrom failed");

        uint256 totalAssets = _totalAssets();
        uint256 sharesToMint = (totalShares == 0 || totalAssets == 0)
            ? amount
            : (amount * totalShares) / totalAssets;

        // Reset approval then approve to prevent issues with tokens like USDT
        token.approve(address(controller), 0);
        token.approve(address(controller), amount);

        controller.invest(amount);

        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;

        emit Deposit(msg.sender, amount);
    }

    /// @notice Withdraw proportional amount of tokens based on shares
function withdraw(uint256 shareAmount) external nonReentrant {
    require(shareAmount > 0, "zero");
    require(shareAmount <= shares[msg.sender], "too much");

    uint256 totalAssets = _totalAssets();
    uint256 withdrawAmount = (shareAmount * totalAssets) / totalShares;

    uint256 bal = token.balanceOf(address(this));
    if (bal < withdrawAmount) {
        uint256 needed = withdrawAmount - bal;
        uint256 withdrawn = controller.withdraw(needed, address(this));
        require(withdrawn >= needed, "insufficient from controller");
    }

    shares[msg.sender] -= shareAmount;
    totalShares -= shareAmount;

    bool ok = token.transfer(msg.sender, withdrawAmount);
    require(ok, "transfer failed");

    emit Withdraw(msg.sender, withdrawAmount);
}

    /// @dev Returns total assets including controller and strategy balances
    function _totalAssets() internal view returns (uint256) {
        uint256 vaultBal = token.balanceOf(address(this));
        uint256 controllerBal = token.balanceOf(address(controller));

        uint256 strategyBal = 0;
        // Safe external view call (won’t revert if strategyBalance not implemented)
        try IController(address(controller)).strategyBalance() returns (uint256 bal) {
            strategyBal = bal;
        } catch {}

        return vaultBal + controllerBal + strategyBal;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
