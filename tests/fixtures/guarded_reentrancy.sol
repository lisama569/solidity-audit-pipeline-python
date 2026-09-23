// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 受锁保护对照样本：
// 同样是"先外呼后更新"，但 withdraw 带结构可识别的互斥锁 modifier，
// 且 call 返回值经 require 检查，因此不应报重入，也不应报危险调用。
contract GuardedVault {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable nonReentrant {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
