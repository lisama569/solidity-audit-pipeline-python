// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 跨函数重入对照样本：
// withdraw 在外呼之后才更新 balances；未加锁的兄弟函数 setBalance
// 同样可写 balances，攻击者重入 setBalance 即可制造不一致。
contract CrossFunctionVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        // 危险点：外部调用发生在状态更新之前，且返回值未检查
        (bool sent, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
        sent;
    }

    // 未加锁的共享状态写入口，使重入可跨函数利用
    function setBalance(address account, uint256 value) public {
        balances[account] = value;
    }
}
