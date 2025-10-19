// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Initializable} from "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {ERC20Upgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/token/ERC20/ERC20Upgradeable.sol";
import {OwnableUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "../lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";

/// @notice ERC20 token used for deposits. Upgradeable, owner can mint for tests.
contract Token is ERC20Upgradeable, OwnableUpgradeable, UUPSUpgradeable {
    function initialize(string memory name_, string memory symbol_, uint256 initialSupply, address owner_)
        public
        initializer
    {
        __ERC20_init(name_, symbol_);
        __Ownable_init();
        __UUPSUpgradeable_init();

        if (owner_ != address(0)) {
            transferOwnership(owner_);
        }
        if (initialSupply > 0) {
            _mint(owner_ == address(0) ? msg.sender : owner_, initialSupply);
        }
    }

    /// @notice Convenient mint for test / research; controlled by owner.
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /// @dev UUPS authorization: only owner may upgrade
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    // Storage gap for future upgrades.
    uint256[45] private __gap;
}
