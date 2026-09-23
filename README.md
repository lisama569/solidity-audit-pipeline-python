# Solidity 本地静态审计流水线

在现有 FastAPI 服务基础上实现的一套本地静态分析流水线，使同一批合约在**重复提交、
提交顺序不同或并发提交**时都能得到**一致、可复现且可解释**的审计结论。

## 1. 架构总览

```
来源接入 -> 内容校验 -> 导入闭包解析 -> 内容指纹(sha256)
                                              |
                       +----------------------+
                       v
              [ TaskManager ] <--> SQLite (tasks / reports / inputs)
                       |
                       v
               规则引擎(确定性)
                       |
                       v
         命中合并去重 -> 稳定编号/排序 -> AuditReport
```

模块划分：

| 文件 | 职责 |
| --- | --- |
| `app/models.py` | 类型定义：`SourceFile / TaskRecord / Finding / AuditReport`，状态与严重程度枚举 |
| `app/errors.py` | `IngestError`，携带可区分的失败码 |
| `app/ingest.py` | 来源归一、UTF-8 解码、路径校验、import 闭包拓扑解析、内容指纹 |
| `app/rules.py` | 规则：重入（含跨函数重入、锁保护识别）与危险外部调用 |
| `app/engine.py` | 多规则命中合并、稳定编号、严重程度排序、`report_hash` |
| `app/store.py` | SQLite 持久化：任务记录、结论缓存、输入载荷，支持重启恢复 |
| `app/tasks.py` | 任务生命周期：去重、排队、超时、取消、重试、状态 CAS |
| `main.py` | HTTP API（FastAPI） |

## 2. 审计规则

分析器是确定性的轻量静态分析：去注释（保留行号）后按花括号配对解析
`contract / function / modifier`，收集状态变量，再在函数体内定位外部调用与
状态写。**不依赖网络与外部编译器，结果不受时序影响。**

### 2.1 REENTRANCY（重入，HIGH / MEDIUM）

判定：函数体中外部调用（`.call/.delegatecall/.callcode/.send/.transfer`）
**之后**仍存在同一函数内的状态写，或者其后调用的内部/私有函数（传递闭包）
会写状态变量——后者即**跨函数重入**。

- 高危（HIGH）：`call / delegatecall / callcode`
- 中危（MEDIUM）：`send / transfer`

**锁保护豁免**：若函数挂接了带锁语义（`nonReentrant/lock/guard/mutex/...`）
且其修改器体内确实设置锁变量的 modifier，或函数体内存在
`require(!locked)` / `require(locked == ...)` 检查，则不再报重入。

### 2.2 DANGEROUS_EXTERNAL_CALL（危险外部调用，HIGH / MEDIUM / LOW）

- `delegatecall / callcode` -> HIGH
- 低层 `.call` 且返回值未被 `require(...)` 或 `bool` 接收检查 -> MEDIUM
- `.send` 返回值未检查 -> LOW

### 2.3 结论归一

- 同一问题（`文件 + 行 + 合约 + 函数`）被多条规则命中时**合并为一条**，
  `rule_ids` 列出全部命中规则，严重程度取最高；
- `finding_id = F- + sha256(file,line,contract,function,rule_ids)[:12]`，
  与运行次数无关；
- 结论按 `(严重程度降序, 文件, 行, finding_id)` 稳定排序；
- `report_hash` 覆盖全部结论内容，两次审计的哈希相同即结论完全一致；
- 未命中任何规则时返回 `clean=true` 与空 findings，给出明确"无问题"结论。

## 3. 任务状态语义

| 状态 | 语义 |
| --- | --- |
| `QUEUED` | 已去重入队，等待执行 |
| `RUNNING` | 正在审计（attempts 自增，作为并发 CAS 令牌） |
| `SUCCEEDED` | 终态：结论已生成并持久化 |
| `FAILED` | 审计执行异常，可重试，最多 `max_attempts=3` 次 |
| `CANCELLED` | 终态：排队/运行中被取消；过期结果在 CAS 处丢弃 |
| `TIMEOUT` | 终态：超过 `AUDIT_TASK_TIMEOUT`（默认 30s），过期结果丢弃 |

**并发自洽保证**：执行线程在开始（QUEUED->RUNNING）与完成
（RUNNING->SUCCEEDED/FAILED）时都校验 `(状态, attempts)` 令牌；
取消、超时、重试与执行完成的任意交错都不会写出过期或重复结论。

**去重**：任务以归一来源的 sha256 指纹为主键。无论重复多少次、什么并发时序，
相同输入永远返回同一 `task_id`；已完成任务的结论缓存在 `reports` 表，
再次提交直接复用，零重复计算。

**重启恢复**：输入载荷存于 `inputs` 表、结论存于 `reports` 表、任务存于
`tasks` 表。重启时 `QUEUED/RUNNING` 任务自动重新入队，`SUCCEEDED` 结论直接复用，
不丢失任何任务或结论。

## 4. 接入失败原因（彼此可区分，HTTP 400）

| error_code | 触发条件 |
| --- | --- |
| `SOURCE_MISSING` | 提交为空；某个声明文件的内容为空 |
| `INVALID_CONTENT` | 非 UTF-8；空/绝对路径或含 `..` 遍历；重复路径；不含任何 Solidity 结构 |
| `IMPORT_UNRESOLVABLE` | import 目标不在提交的来源集合内；循环导入 |

所有失败在任务创建**之前**拒绝，不产生半成品结果或空壳任务。

## 5. HTTP API

```bash
uv run uvicorn main:app --reload
```

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/audits` | multipart 上传文件，返回 202 + 任务；相同内容幂等 |
| GET | `/audits/{id}` | 查询状态与结论 |
| POST | `/audits/{id}/cancel` | 取消 QUEUED/RUNNING 任务 |
| POST | `/audits/{id}/retry` | 重试 FAILED/TIMEOUT/CANCELLED 任务 |

提交示例：

```bash
curl -s -X POST http://127.0.0.1:8000/audits \
  -F "files=@Vault.sol" | jq
```

## 6. 可复现性保证

1. **顺序无关**：指纹只依赖 `{规范路径, 内容}` 的排序拼接；
2. **并发无关**：指纹去重 + 状态 CAS，16 路并发提交同一合约只产生一个任务、
   一份结论；
3. **结论确定**：规则解析与输出均确定性排序，`finding_id` 与 `report_hash`
   内容寻址；
4. **跨重启一致**：结论按指纹持久化，服务重启后复用同一份结论。

## 7. 验证方法

```bash
uv run pytest -q -s
```

覆盖场景：

- 重复提交 / 16 路并发提交 / 不同输入交错并发：单任务、单结论；
- 畸形来源：空提交、非 UTF-8、非 Solidity 内容、缺失 import，
  分别得到 `SOURCE_MISSING / INVALID_CONTENT / IMPORT_UNRESOLVABLE`；
- 规则对照：**跨函数重入命中** vs **受 nonReentrant 锁保护不命中**、
  delegatecall、未检查返回值的 call、安全合约空结论；
- 任务生命周期：排队取消、执行超时（过期结果不覆盖终态）、
  失败重试、重启后未完成任务重跑与已完成结论复用；
- 端到端 HTTP：提交、查询、幂等并发、404/409 处理。

`-s` 可看到每条用例打印的**输入标识与判定依据**，例如：

```
[rule] 函数内重入 -> REENTRANCY L6 外部 call 调用之后仍存在状态写（函数内重入风险）...
[rule] 受锁保护 -> 无 REENTRANCY 命中（对照通过）
[task] 16 路并发提交 -> 单任务 7b3a..., findings=1 hash=...
```
