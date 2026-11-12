// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "./Ownable.sol";

/// @title Berth registry for Saltmere Harbour (a teaching example).
contract BerthRegistry is Ownable {
    mapping(uint256 => string) public berths;

    event Assigned(uint256 berth, string vessel);

    modifier validBerth(uint256 b) {
        require(b < 12, "no such berth");
        _;
    }

    function assign(uint256 b, string calldata vessel) external onlyOwner validBerth(b) {
        berths[b] = vessel;
        emit Assigned(b, vessel);
    }
}
