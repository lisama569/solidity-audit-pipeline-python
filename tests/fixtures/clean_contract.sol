// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 干净样本：使用受 gas 限制的 transfer，且先更新状态后外呼，无低级调用。
contract CleanPiggyBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
