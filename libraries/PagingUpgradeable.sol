// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;
import "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";

library PagingUpgradeable {
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.UintSet;
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;
    using EnumerableSetUpgradeable for EnumerableSetUpgradeable.Bytes32Set;

    function tokenList(
        uint256 _start,
        uint256 _pageSize,
        EnumerableSetUpgradeable.UintSet storage holderTokens
    ) internal view returns (uint256, uint256[] memory) {
        require(_pageSize <= 50, "The maximum PageSize is 50");
        uint256 total = holderTokens.length();
        uint256 start;
        start = _start * _pageSize;
        require(start <= total, "_start input error");
        uint256 end;
        if (start + _pageSize > holderTokens.length()) {
            end = holderTokens.length();
        } else {
            end = start + _pageSize;
        }
        uint256[] memory tokenIds = new uint256[](end - start);
        uint256 count = 0;
        for (uint256 i = start; i < end; i++) {
            uint256 tokenId = holderTokens.at(i);
            tokenIds[count] = tokenId;
            count++;
        }
        return (total, tokenIds);
    }

    function addressList(
        uint256 _start,
        uint256 _pageSize,
        EnumerableSetUpgradeable.AddressSet storage addressSet
    ) internal view returns (uint256, address[] memory) {
        require(_pageSize <= 50, "The maximum PageSize is 50");
        uint256 total = addressSet.length();
        uint256 start;
        start = _start * _pageSize;
        require(start <= total, "_start input error");
        uint256 end;
        if (start + _pageSize > addressSet.length()) {
            end = addressSet.length();
        } else {
            end = start + _pageSize;
        }
        address[] memory addresses = new address[](end - start);
        uint256 count = 0;
        for (uint256 i = start; i < end; i++) {
            address addr = addressSet.at(i);
            addresses[count] = addr;
            count++;
        }
        return (total, addresses);
    }

    function bytes32List(
        uint256 _start,
        uint256 _pageSize,
        EnumerableSetUpgradeable.Bytes32Set storage bytes32Set
    ) internal view returns (uint256, bytes32[] memory) {
        require(_pageSize <= 50, "The maximum PageSize is 50");
        uint256 total = bytes32Set.length();
        uint256 start;
        start = _start * _pageSize;
        require(start <= total, "_start input error");
        uint256 end;
        if (start + _pageSize > bytes32Set.length()) {
            end = bytes32Set.length();
        } else {
            end = start + _pageSize;
        }
        bytes32[] memory arr = new bytes32[](end - start);
        uint256 count = 0;
        for (uint256 i = start; i < end; i++) {
            bytes32 addr = bytes32Set.at(i);
            arr[count] = addr;
            count++;
        }
        return (total, arr);
    }
}
