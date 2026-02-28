// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

// WARNING: This contract contains intentional vulnerabilities for testing
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: Reentrancy
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call BEFORE state update = reentrancy vulnerability
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount; // State change AFTER external call
    }

    // VULNERABILITY: No access control on sensitive function
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    // VULNERABILITY: Integer overflow (Solidity < 0.8)
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // No SafeMath
    }
}
