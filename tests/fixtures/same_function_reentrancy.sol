// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// 同函数重入对照样本：
// 外部调用后更新本函数依赖的 balances，且不存在可利用的未加锁兄弟写入口。
contract SameFunctionWallet {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        (bool sent, ) = msg.sender.call{value: amount}("");
        sent;
        balances[msg.sender] -= amount;
    }
}
