// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC20Upgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/token/ERC20/IERC20Upgradeable.sol";
import {ReentrancyGuardUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {Initializable} from "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";

import {OwnableUpgradeable} from
    "../lib/openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from
    "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";



/// @notice Simple mock strategy: Controller deposits tokens, strategy holds them and can simulate yield.
/// @dev Strategy holds a reference to token and controller. Owner controls yield simulation and emergency withdrawal.
/// @notice Mock Strategy for testing: holds tokens and simulates yield.
contract Strategy is OwnableUpgradeable, UUPSUpgradeable {
    IERC20Upgradeable public token;
    address public controller;
    address public vault;

    uint256 public invested;

    event Invest(address indexed from, uint256 amount);
    event Withdraw(address indexed to, uint256 amount);
    event Harvest(address indexed to, uint256 yieldAmount);
    event SetController(address indexed controller);
    event SetVault(address indexed vault);
    event SimulatedYield(uint256 amount);

    function initialize(address token_, address controller_, address vault_) public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();

        require(token_ != address(0), "token 0");
        token = IERC20Upgradeable(token_);
        controller = controller_;
        vault = vault_;
    }

    function invest(uint256 amount) external onlyController {
        require(amount > 0, "zero");
        bool ok = token.transferFrom(msg.sender, address(this), amount);
        require(ok, "transferFrom failed");
        invested += amount;
        emit Invest(msg.sender, amount);
    }

    function withdraw(uint256 amount, address to) external onlyController returns (uint256) {
        require(amount > 0, "zero");
        uint256 bal = token.balanceOf(address(this));
        uint256 toSend = amount > bal ? bal : amount;
        if (toSend > 0) {
            bool ok = token.transfer(to, toSend);
            require(ok, "transfer failed");
            if (toSend <= invested) invested -= toSend;
            else invested = 0;
        }
        emit Withdraw(to, toSend);
        return toSend;
    }

    /// Simulate yield (mint externally in tests)
    function simulateYield(uint256 amount) external onlyOwner {
        emit SimulatedYield(amount);
    }

    /// Harvest yield (excess balance)
    function harvest() external onlyOwnerOrController returns (uint256) {
        uint256 bal = token.balanceOf(address(this));
        if (bal <= invested) return 0;

        uint256 yieldAmount = bal - invested;
        address to = vault == address(0) ? controller : vault;

        bool ok = token.transfer(to, yieldAmount);
        require(ok, "transfer failed");

        emit Harvest(to, yieldAmount);
        return yieldAmount;
    }

    function emergencyWithdrawAll(address to) external onlyOwner {
        uint256 bal = token.balanceOf(address(this));
        if (bal > 0) {
            bool ok = token.transfer(to, bal);
            require(ok, "transfer failed");
            invested = 0;
        }
    }

    function setController(address controller_) external onlyOwner {
        controller = controller_;
        emit SetController(controller_);
    }

    function setVault(address vault_) external onlyOwner {
        vault = vault_;
        emit SetVault(vault_);
    }

    modifier onlyController() {
        require(msg.sender == controller, "only controller");
        _;
    }

    modifier onlyOwnerOrController() {
        require(msg.sender == owner() || msg.sender == controller, "only owner/controller");
        _;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    uint256[44] private __gap;
}