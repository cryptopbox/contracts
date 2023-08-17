// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721ReceiverUpgradeable.sol";
import "./libraries/PagingUpgradeable.sol";

contract VaultUpgradeable is
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    IERC721ReceiverUpgradeable
{
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.Bytes32Set;
    using AddressUpgradeable for address;
    using SafeMathUpgradeable for uint256;

    address public signer1;
    address public signer2;

    mapping(uint256 => bool) public orderIds;
    mapping(string => mapping(address => uint256)) public roomBalance;

    event Deposit(address indexed account, address token, uint256 amount);
    event BuyIn(
        address indexed account,
        string roomId,
        address token,
        uint256 amount
    );
    event Withdraw(
        uint256 orderId,
        address token,
        uint256 amount,
        address indexed user,
        address indexed signer
    );


    event WithdrawToken(address indexed account, address token, uint256 amount);
    event WithdrawFromRoom(
        uint256 orderId,
        string roomId,
        address token,
        uint256 amount,
        address indexed user,
        address indexed signer
    );

    function initialize() public initializer {
        __Ownable_init();
    }

    receive() external payable {
        emit Deposit(_msgSender(), address(0), msg.value);
    }

    /**
     * deposit token
     */
    function deposit(address token, uint256 amount) external {
        IERC20Upgradeable(token).transferFrom(
            _msgSender(),
            address(this),
            amount
        );

        emit Deposit(_msgSender(), token, amount);
    }

    /**
     * withdraw token
     */
    function withdraw(
        uint256 orderId,
        address token,
        uint256 amount,
        bytes memory signature,
        bytes memory signature2
    ) external {
        require(orderIds[orderId] == false, "already withdrawn");
        orderIds[orderId] = true;

        bytes32 hash1 = keccak256(
            abi.encode(
                "withdraw",
                address(this),
                msg.sender,
                orderId,
                token,
                amount
            )
        );

        bytes32 hash2 = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash1)
        );

        address signer = recover(hash2, signature);
        address _signer2 = recover(hash2, signature2);

        require(signer == signer1 && _signer2 == signer2, "invalid signer");

        if (token == address(0)) {
            uint256 balance = address(this).balance;
            require(amount <= balance, "Insufficient balance");

            payable(msg.sender).transfer(amount);
        } else {
            IERC20Upgradeable(token).transfer(msg.sender, amount);
        }

        emit Withdraw(orderId, token, amount, msg.sender, signer);
    }

    /**
     * withdraw token anyone
     */
    function withdrawEx(
        uint256 orderId,
        address token,
        address receiver,
        uint256 amount,
        bytes memory signature,
        bytes memory signature2
    ) external {
        require(orderIds[orderId] == false, "already withdrawn");
        orderIds[orderId] = true;

        bytes32 hash1 = keccak256(
            abi.encode(
                "withdraw",
                address(this),
                receiver,
                orderId,
                token,
                amount
            )
        );

        bytes32 hash2 = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash1)
        );

        address signer = recover(hash2, signature);
        address _signer2 = recover(hash2, signature2);

        require(signer == signer1 && _signer2 == signer2, "invalid signer");

        if (token == address(0)) {
            uint256 balance = address(this).balance;
            require(amount <= balance, "Insufficient balance");

            payable(receiver).transfer(amount);
        } else {
            IERC20Upgradeable(token).transfer(receiver, amount);
        }

        emit Withdraw(orderId, token, amount, receiver, signer);
    }

    /**
     * batch withdraw token
     */
    function batchWithdraw(
        uint256[] calldata orderId,
        address[] calldata token,
        address[] calldata receiver,
        uint256[] calldata amount,
        bytes[] memory signature,
        bytes[] memory signature2
    ) external {
        require(orderId.length == token.length, "invalid length");
        require(orderId.length == receiver.length, "invalid length");
        require(orderId.length == amount.length, "invalid length");
        require(orderId.length == signature.length, "invalid length");
        require(orderId.length == signature2.length, "invalid length");

        for (uint256 i = 0; i < orderId.length; i++) {
            this.withdrawEx(
                orderId[i],
                token[i],
                receiver[i],
                amount[i],
                signature[i],
                signature2[i]
            );
        }
    }

    function withdrawBalance(
        address payable account,
        uint256 amount
    ) external onlyOwner {
        uint256 balance = address(this).balance;
        require(amount <= balance, "Insufficient balance");
        AddressUpgradeable.sendValue(account, amount);
    }

    function withdrawToken(
        address token,
        address account,
        uint256 amount
    ) external onlyOwner {
        uint256 balance = IERC20Upgradeable(token).balanceOf(address(this));
        require(amount <= balance, "Insufficient token balance");

        IERC20Upgradeable(token).transfer(account, amount);
        emit WithdrawToken(account, token, amount);
    }

    function buyIn(
        string memory roomId,
        address token,
        uint256 amount
    ) external {
        IERC20Upgradeable(token).transferFrom(
            _msgSender(),
            address(this),
            amount
        );

        roomBalance[roomId][token] = roomBalance[roomId][token].add(amount);

        emit BuyIn(_msgSender(), roomId, token, amount);
    }

    /**
     * withdraw token from room
     */
    function withdrawFromRoom(
        uint256 orderId,
        string memory roomId,
        address token,
        address receiver,
        uint256 amount,
        bytes memory signature
    ) external {
        require(orderIds[orderId] == false, "already withdrawn");
        orderIds[orderId] = true;

        roomBalance[roomId][token] = roomBalance[roomId][token].sub(amount);

        bytes32 hash1 = keccak256(
            abi.encode(
                "withdraw",
                address(this),
                receiver,
                orderId,
                roomId,
                token,
                amount
            )
        );

        bytes32 hash2 = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash1)
        );

        address signer = recover(hash2, signature);

        require(signer == signer1, "invalid signer");

        if (token == address(0)) {
            uint256 balance = address(this).balance;
            require(amount <= balance, "Insufficient balance");

            payable(receiver).transfer(amount);
        } else {
            IERC20Upgradeable(token).transfer(receiver, amount);
        }

        emit WithdrawFromRoom(orderId, roomId, token, amount, receiver, signer);
    }


    function setDev1(address _signer) public onlyOwner {
        signer1 = _signer;
    }

    function setDev2(address _signer) public onlyOwner {
        signer2 = _signer;
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        // Check the signature length
        if (signature.length != 65) {
            revert("ECDSA: invalid signature length");
        }

        // Divide the signature in r, s and v variables
        bytes32 r;
        bytes32 s;
        uint8 v;

        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        return recover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover-bytes32-bytes-} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        require(
            uint256(s) <=
                0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "ECDSA: invalid signature 's' value"
        );
        require(v == 27 || v == 28, "ECDSA: invalid signature 'v' value");

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");

        return signer;
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure override returns (bytes4) {
        return 0x150b7a02;
    }
}
