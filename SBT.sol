// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IERC721.sol";
import "./interfaces/ISBT721.sol";
import "./interfaces/IERC721Metadata.sol";
import "./utils/Context.sol";
import "./utils/Counters.sol";
import "./utils/EnumerableMap.sol";
import "./utils/Strings.sol";
import "./utils/Initializable.sol";

import "./erc/ERC165.sol";
import "./access/AccessControl.sol";

/**
 * An experiment in Soul Bound Tokens (SBT's) following Vitalik's
 * co-authored whitepaper at:
 * https://papers.ssrn.com/sol3/papers.cfm?abstract_id=4105763
 *
 * I propose for a rename to Non-Transferable Tokens NTT's
 */
contract SBT is Initializable, AccessControl, ISBT721, IERC721Metadata {
    using Strings for uint256;
    using Counters for Counters.Counter;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using EnumerableMap for EnumerableMap.UintToAddressMap;

    // Mapping from token ID to owner address
    EnumerableMap.UintToAddressMap private _ownerMap;
    EnumerableMap.AddressToUintMap private _tokenMap;

    // Token Id
    Counters.Counter private _tokenId;

    // Token name
    string public name;

    // Token symbol
    string public symbol;

    // Token URI
    string private _baseTokenURI;

    // Operator
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    function initialize(
        string memory name_,
        string memory symbol_,
        address admin_
    ) public reinitializer(1) {
        name = name_;
        symbol = symbol_;

        // grant DEFAULT_ADMIN_ROLE to contract creator
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(OPERATOR_ROLE, admin_);
    }

    function attest(address to) external returns (uint256) {
        require(
            hasRole(OPERATOR_ROLE, _msgSender()),
            "Only the account with OPERATOR_ROLE can attest the SBT"
        );
        require(to != address(0), "Address is empty");
        require(!_tokenMap.contains(to), "SBT already exists");

        _tokenId.increment();
        uint256 tokenId = _tokenId.current();

        _tokenMap.set(to, tokenId);
        _ownerMap.set(tokenId, to);

        emit Attest(to, tokenId);
        emit Transfer(address(0), to, tokenId);

        return tokenId;
    }

    function claim(bytes memory signature) external returns (uint256) {
        bytes32 hash1 = keccak256(
            abi.encode(
                address(this),
                msg.sender                
            )
        );

        bytes32 hash2 = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash1)
        );

        address signer = recover(hash2, signature);
        require(
            hasRole(OPERATOR_ROLE, signer),
            "Only the account with OPERATOR_ROLE can attest the SBT"
        );
        require(!_tokenMap.contains(_msgSender()), "SBT already exists");

        _tokenId.increment();
        uint256 tokenId = _tokenId.current();

        _tokenMap.set(_msgSender(), tokenId);
        _ownerMap.set(tokenId, _msgSender());

        emit Attest(_msgSender(), tokenId);
        emit Transfer(address(0), _msgSender(), tokenId);

        return tokenId;
    }

    function batchAttest(address[] calldata addrs) external {
        uint256 addrLength = addrs.length;

        require(
            hasRole(OPERATOR_ROLE, _msgSender()),
            "Only the account with OPERATOR_ROLE can attest the SBT"
        );
        require(addrLength <= 100, "The max length of addresses is 100");

        for (uint8 i = 0; i < addrLength; i++) {
            address to = addrs[i];

            if (to == address(0) || _tokenMap.contains(to)) {
                continue;
            }

            _tokenId.increment();
            uint256 tokenId = _tokenId.current();

            _tokenMap.set(to, tokenId);
            _ownerMap.set(tokenId, to);

            emit Attest(to, tokenId);
            emit Transfer(address(0), to, tokenId);
        }
    }

    function revoke(address from) external {
        require(
            hasRole(OPERATOR_ROLE, _msgSender()),
            "Only the account with OPERATOR_ROLE can revoke the SBT"
        );
        require(from != address(0), "Address is empty");
        require(_tokenMap.contains(from), "The account does not have any SBT");

        uint256 tokenId = _tokenMap.get(from);

        _tokenMap.remove(from);
        _ownerMap.remove(tokenId);

        emit Revoke(from, tokenId);
        emit Transfer(from, address(0), tokenId);
    }

    function batchRevoke(address[] calldata addrs) external {
        uint256 addrLength = addrs.length;

        require(
            hasRole(OPERATOR_ROLE, _msgSender()),
            "Only the account with OPERATOR_ROLE can revoke the SBT"
        );
        require(addrLength <= 100, "The max length of addresses is 100");

        for (uint8 i = 0; i < addrLength; i++) {
            address from = addrs[i];

            if (from == address(0) || !_tokenMap.contains(from)) {
                continue;
            }

            uint256 tokenId = _tokenMap.get(from);

            _tokenMap.remove(from);
            _ownerMap.remove(tokenId);

            emit Revoke(from, tokenId);
            emit Transfer(from, address(0), tokenId);
        }
    }

    function burn() external {
        address sender = _msgSender();

        require(
            _tokenMap.contains(sender),
            "The account does not have any SBT"
        );

        uint256 tokenId = _tokenMap.get(sender);

        _tokenMap.remove(sender);
        _ownerMap.remove(tokenId);

        emit Burn(sender, tokenId);
        emit Transfer(sender, address(0), tokenId);
    }

    /**
     * @dev Update _baseTokenURI
     */
    function setBaseTokenURI(string calldata uri) public {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, _msgSender()),
            "Only the account with DEFAULT_ADMIN_ROLE can set the base token URI"
        );

        _baseTokenURI = uri;
    }

    function balanceOf(address owner) external view returns (uint256) {
        (bool success, ) = _tokenMap.tryGet(owner);
        return success ? 1 : 0;
    }

    function tokenIdOf(address from) external view returns (uint256) {
        return _tokenMap.get(from, "The wallet has not attested any SBT");
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        return _ownerMap.get(tokenId, "Invalid tokenId");
    }

    function totalSupply() external view returns (uint256) {
        return _tokenMap.length();
    }

    function isOperator(address account) external view returns (bool) {
        return hasRole(OPERATOR_ROLE, account);
    }

    function isAdmin(address account) external view returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, account);
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) external view returns (string memory) {
        return
            bytes(_baseTokenURI).length > 0
                ? string(abi.encodePacked(_baseTokenURI, tokenId.toString()))
                : "";
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override
        returns (bool)
    {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
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
    function recover(bytes32 hash, bytes memory signature)
        internal
        pure
        returns (address)
    {
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
}
