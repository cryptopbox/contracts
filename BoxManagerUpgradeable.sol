// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract BoxManagerUpgradeable is OwnableUpgradeable {
    IERC20Upgradeable public CLOV;
    IERC721Upgradeable public BOX;

    event OpenBox(address indexed owner, uint256 tokenId, uint256 amount);

    function initialize() public initializer {
        __Ownable_init();
    }

    // set clov address
    function setCloAddress(address _CLOV) external onlyOwner {
        CLOV = IERC20Upgradeable(_CLOV);
    }

    // set nft address
    function setBoxAddress(address _BOX) external onlyOwner {
        BOX = IERC721Upgradeable(_BOX);
    }

    // user openbox by burn nft
    function openBox(uint256 id) external {
        require(
            BOX.ownerOf(id) == msg.sender,
            "ERC721: caller is not the owner"
        );
        BOX.transferFrom(msg.sender, address(this), id);
        // rand 100-300
        uint256 rand = (uint256(
            keccak256(abi.encodePacked(block.timestamp, msg.sender, id))
        ) % 201) + 100;
        CLOV.transfer(msg.sender, rand * 1e18);

        emit OpenBox(msg.sender, id, rand * 1e18);
    }

    // owner withdraw any token
    function withdrawToken(
        address token,
        address account,
        uint256 amount
    ) external onlyOwner {
        require(
            token != address(0),
            "ERC20: withdraw ERC20: token is the zero address"
        );
        require(
            account != address(0),
            "ERC20: withdraw ERC20: account is the zero address"
        );
        uint256 balance = IERC20Upgradeable(token).balanceOf(address(this));
        require(amount <= balance, "ERC20: Insufficient token balance");
        IERC20Upgradeable(token).transfer(account, amount);
    }
}
