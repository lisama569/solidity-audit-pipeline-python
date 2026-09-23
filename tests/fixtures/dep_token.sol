// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
}

// 依赖样本：供多源导入解析测试使用
contract TokenVault {
    IERC20 public token;

    constructor(IERC20 _token) {
        token = _token;
    }
}
