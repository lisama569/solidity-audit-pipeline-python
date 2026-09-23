# Solidity 本地静态审计流水线（Python）

一套面向 Solidity 智能合约的**本地**静态审计流水线，目标是让同一批合约在
**重复提交、提交顺序不同或并发提交**时都得到一致、可复现、可解释的审计结论。

- 纯 Python、零 Solidity 工具链依赖（内置最小词法/语法分析前端）；
- 来源归一化 + 内容哈希去重 + SQLite 持久化 + 多 worker 并发；
- 覆盖**重入**（同函数 / 跨函数）与**危险外部调用**两类规则；
- 多规则命中同一问题自动合并，编号 / 严重度 / 定位稳定可复现；
- 未命中规则时也给出明确结论；
- 来源缺失、导入无法解析、内容非法分别返回**彼此可区分的错误码**。

## 快速开始

```bash
uv sync
uv run uvicorn main:app --port 8000
```

提交一批本地合约（`sources` 为路径+内容的扁平列表，依赖也以文件形式一起提交）：

```bash
curl -s -X POST localhost:8000/audit/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "entry_point": "contracts/Wallet.sol",
    "client_labels": ["demo-001"],
    "sources": [
      {"path": "contracts/Wallet.sol", "content": "contract Wallet { ... }"},
      {"path": "contracts/IToken.sol",   "content": "interface IToken { ... }"}
    ]
  }'
```

- 首次提交返回 **202**（任务已创建）；
- 对相同内容再次提交返回 **200** 且 `deduplicated=true`、任务 id 相同（幂等）；
- `GET /audit/tasks/{id}` 查询状态与最终报告。

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/audit/tasks` | 提交合约（来源非法时 422，错误码可区分；新任务 202 / 去重 200） |
| GET | `/audit/tasks` | 列出全部任务 |
| GET | `/audit/tasks/{id}` | 查询任务与结论（不存在 → 404 `TASK_NOT_FOUND`） |
| POST | `/audit/tasks/{id}/cancel` | 取消（排队立即取消；运行中协作取消；终态 → 409） |
| POST | `/audit/tasks/{id}/retry` | 重试 FAILED / TIMEOUT 任务 |
| GET | `/healthz` | 存活探针 |

## 模块结构

```
audit_pipeline/
  errors.py     稳定错误码（SOURCE_MISSING / UNRESOLVED_IMPORT / INVALID_CONTENT ...）
  models.py     数据模型与任务状态枚举
  parser.py     零依赖 Solidity 词法/结构解析（token、合约、函数、modifier、语句树）
  resolver.py   路径归一化、来源校验、import 闭包解析与稳定拓扑序
  rules.py      REENTRANCY-001 / DANGEROUS-CALL-001 规则与纯函数分析
  engine.py     规则编排、多规则合并去重、稳定排序与编号、内容哈希
  store.py      SQLite 持久化（content_hash 唯一，重启可恢复）
  queue.py      线程安全 FIFO 任务队列
  service.py    幂等提交、状态机、worker 并发、超时/取消/重试、重启恢复
  api.py        FastAPI HTTP 接口
tests/          44 个 pytest 用例（重复/并发/畸形来源/重入对照/生命周期/HTTP）
tests/fixtures/ cross / same / guarded / clean 四类对照 Solidity 样本
docs/           规则、状态语义、可复现性保证与验证方法
```

## 审计规则（摘要）

| 规则 ID | 说明 | 严重度 |
|---|---|---|
| `REENTRANCY-001` | 状态更新前发生外部调用；存在未加锁兄弟写入口为**跨函数** CRITICAL，否则为同函数 HIGH；被结构可识别的互斥锁 modifier 保护时不报 | HIGH / CRITICAL |
| `DANGEROUS-CALL-001` | 任意 `delegatecall`（HIGH）；未检查返回值的低级 `call`（MEDIUM） | MEDIUM / HIGH |

详见 [docs/AUDIT_RULES.md](docs/AUDIT_RULES.md)。

## 任务状态（摘要）

`QUEUED → RUNNING → COMPLETED`；`QUEUED/RUNNING → CANCELLED`；
执行失败或超时在重试额度内自动回 `QUEUED`，额度耗尽为 `FAILED`/`TIMEOUT`
（可显式 retry）。详见 [docs/TASK_LIFECYCLE.md](docs/TASK_LIFECYCLE.md)。

## 可复现性与验证

可复现的关键在于：路径归一化 + 按路径排序的内容 SHA-256 + 纯函数式规则引擎
+ 全序排序编号 + 存储层哈希唯一约束。

```bash
uv run pytest -s     # 打印每个用例的输入标识与判定依据
```

对照样本的预期结论：

- `tests/fixtures/cross_function_reentrancy.sol` → `F-0001 CRITICAL`（跨函数重入）；
- `tests/fixtures/same_function_reentrancy.sol` → `F-0001 HIGH`（同函数重入）；
- `tests/fixtures/guarded_reentrancy.sol` → 无结论（受锁保护 + 返回值检查）；
- `tests/fixtures/clean_contract.sol` → 无结论（先更新状态再用受限 transfer）。

详见 [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md)。

## 失败原因错误码

| 错误码 | 含义 |
|---|---|
| `SOURCE_MISSING` | 入口合约或被 import 的文件未在提交来源中 |
| `UNRESOLVED_IMPORT` | 裸包名、路径越界等无法映射到已提交文件的 import |
| `INVALID_CONTENT` | 空内容、非法字符、未闭合字符串/注释、结构损坏 |
| `INVALID_SUBMISSION` | 空来源、非法/绝对/越界路径、归一化后路径重复 |
| `TASK_NOT_FOUND` / `TASK_STATE_CONFLICT` / `TASK_TIMEOUT` | 任务查询 / 非法状态流转 / 执行超时 |

来源类错误在任何状态写入之前抛出，因此不会产生半成品任务或被静默跳过。

## 说明

本工具用于教学与 CI 辅助筛查，内置解析器为审计目的的最小前端，不替代
完整编译器与专业审计；“未命中规则”仅表示当前规则集覆盖范围内未发现问题。
