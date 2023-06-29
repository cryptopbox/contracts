// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract ClovToken is ERC20, ERC20Burnable, Ownable {
    using Address for address payable;

    receive() external payable {}

    constructor(address fund) ERC20("ClovToken", "CLOV") {
        _mint(fund, 21000000 * 1e18);
    }

    function mint(
        address account,
        uint256 amount
    ) external onlyOwner {
        require(account != address(0), "ERC20: mint to the zero address");
        _mint(account, amount);
    }

    function withdraw(
        address payable account,
        uint256 amount
    ) external onlyOwner {
        uint256 balance = address(this).balance;
        require(amount <= balance, "ERC20: Insufficient balance");
        Address.sendValue(account, amount);
    }

    function withdrawToken(
        address token,
        address account,
        uint256 amount
    ) external onlyOwner {
        require(token != address(0), "ERC20: withdraw ERC20: token is the zero address");
        require(account != address(0), "ERC20: withdraw ERC20: account is the zero address");
        uint256 balance = IERC20(token).balanceOf(address(this));
        require(amount <= balance, "ERC20: Insufficient token balance");
        IERC20(token).transfer(account, amount);
    }
}
