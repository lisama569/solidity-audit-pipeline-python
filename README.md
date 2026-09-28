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
| `app/models.py` | 类型定义：`SourceFile / TaskRecord / Finding / AuditReport`，状态与严重程度枚举；以及对比类型 `IssueRef / FindingDelta / ComparisonReport / CompareRecord` |
| `app/errors.py` | `IngestError`，携带可区分的失败码 |
| `app/ingest.py` | 来源归一、UTF-8 解码、路径校验、import 闭包拓扑解析、内容指纹 |
| `app/rules.py` | 规则：重入（含跨函数重入、锁保护识别）与危险外部调用；为每条命中计算与行号/命名/注释无关的 `issue_key` |
| `app/engine.py` | 多规则命中合并、稳定编号、严重程度排序、`report_hash`，并挂接问题稳定身份 `IssueRef` |
| `app/diffing.py` | 纯函数版本对比：按问题稳定身份匹配，分类新增/已修复/仍然存在/严重度变化，稳定编号排序与 `comparison_hash` |
| `app/store.py` | SQLite 持久化：任务、结论、输入载荷、**对比结论**，支持重启恢复 |
| `app/tasks.py` | 单次审计任务生命周期：去重、排队、超时、取消、重试、状态 CAS |
| `app/comparisons.py` | 版本对比任务生命周期：基线校验、按 (新版本,基线) 去重、排队、超时、取消、重试 |
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
- 未命中任何规则时返回 `clean=true` 与空 findings，给出明确"无问题"结论；
- 每条结论还带一组 `IssueRef(rule_id, issue_key, severity)`：`issue_key`
  是**问题的稳定身份**，由规则层从问题代码结构计算，只依赖「归一化函数上下文
  （函数头 + 挖空调用点语句后的函数体）+ 调用点结构 + 涉及的状态写/跨函数
  写」，与行号、用户标识符（函数/变量/参数改名）、注释、代码整体挪动无关。
  它是下面版本对比做跨版本问题匹配的基础。

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

## 5. 版本对比（新版本 vs 历史基线）

提交新版本时可以指定一份**已审计完成**的历史提交作为基线，服务会把两份
`AuditReport` 按问题稳定身份（`rule_id + issue_key`）做多重集匹配，输出：

| 分类 | 语义 |
| --- | --- |
| `NEW` | 基线没有、新版本新出现的问题 |
| `FIXED` | 基线有、新版本已消失的问题 |
| `PERSISTENT` | 两边都在、实质未变的问题 |
| `SEVERITY_CHANGED` | 同一问题仍在，但严重程度变了（如 `send` 升级为未检查 `call`） |

结果含四类各自计数 `counts`、每条差异的稳定编号 `delta_id`、稳定排序，
并显式带 `baseline_task_id / current_task_id`、两份报告哈希与一个
`comparison_hash`，能直观看出是**相对哪份基线**比出来的。

### 5.1 匹配如何经受正常代码演进

匹配身份只看问题的实质结构，因此以下演进**不会**让原问题误报成新增/修复：

- 在文件里插入无关代码、加注释、整体上下挪动（行号变化）；
- 调整函数顺序、把函数整体移动位置；
- 纯重命名：函数名、变量名、参数名变化；
- 调用附带的 `{value:..}/{gas:..}`、实参内容等噪声变化。

只有问题本身实质改变才会体现为差异：调用点之外的结构改变（问题挪到/来自
另一段不同逻辑）、问题被真正删除或新写、或严重程度变化。

> 内容匹配的固有边界：若"删除函数 A 中的问题"与"新增一个结构完全相同、
> 仅函数名不同的函数 B 中的问题"在内容上一模一样（无任何上下文可区分），
> 系统按"纯重命名不算变化"判为仍然存在。要让新增/修复被识别，新旧问题所在
> 的函数上下文需有可区分的结构差异（正常代码演进几乎总是满足）。

同一 `(rule_id, issue_key)` 出现多次时按稳定顺序第 N 个配对（多重集），
同一条问题不会同时被记成新增与已修复；即使两边合计几百条结论，分类、顺序、
编号、统计都确定且唯一。

### 5.2 幂等、隔离与持久化

- 去重键是 `(新版本内容指纹, 基线任务id)`：同一新版本配同一基线，无论重复
  提交、并发提交还是提交先后如何变化，都只产生**一条**对比记录、一份结论；
- 同一新版本用**不同基线**比较，得到各自独立的对比记录与结论，互不干扰、
  不会被当成重复提交复用；
- 对比结论持久化在 `comparisons` 表，服务重启后已算好的结论不丢失，重复
  提交直接复用；
- 对比是纯函数：`comparison_hash` 只依赖两份报告的内容指纹与分类结果，
  不含运行时生成的任务 id，因此同一对报告在任何时序下哈希恒等。

### 5.3 基线拒绝原因（彼此可区分，HTTP 400）

| error_code | 触发条件 |
| --- | --- |
| `BASELINE_NOT_FOUND` | 指定的基线任务不存在 |
| `BASELINE_NOT_READY` | 基线存在但尚未审计完成（非 SUCCEEDED） |
| `BASELINE_MISMATCH` | 基线与当前提交没有任何同名文件，不属于同一合约演进 |
| `NEW_VERSION_NOT_READY` | 对比执行时新版本审计处于失败/超时/取消（任务级 FAILED，可重试） |

基线相关的前两类不匹配在创建任何对比任务**之前**拒绝，**不会**悄悄降级成
单版本审计，也不返回半截对比结果。新版本自身的来源畸形仍按第 4 节的
`SOURCE_MISSING / INVALID_CONTENT / IMPORT_UNRESOLVABLE` 拒绝。

### 5.4 与单次审计的语义、兼容差别

- 单次审计 `POST /audits` 完全保持不变：既有调用、去重、结论格式
  （`Finding` 仅**新增**了一个向后兼容的可选 `issues` 字段，旧消费者不受影响）；
- 对比是叠加的一层用法：`POST /comparisons` 内部会复用/触发新版本的普通
  审计，再与基线报告做纯函数 diff，不重复实现分析逻辑；
- 对比任务与普通任务拥有相同的生命周期语义（排队、超时、取消、失败重试、
  `max_attempts`、状态 CAS），失败重试或取消后重试都不会产生重复对比记录，
  过期结果在 CAS 处被丢弃。

## 6. HTTP API

```bash
uv run uvicorn main:app --reload
```

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/audits` | multipart 上传文件，返回 202 + 任务；相同内容幂等 |
| GET | `/audits/{id}` | 查询状态与结论 |
| POST | `/audits/{id}/cancel` | 取消 QUEUED/RUNNING 任务 |
| POST | `/audits/{id}/retry` | 重试 FAILED/TIMEOUT/CANCELLED 任务 |
| POST | `/comparisons` | 指定 `baseline_task_id` 提交新版本对比（multipart），相同 (新版本,基线) 幂等 |
| GET | `/comparisons/{id}` | 查询对比状态与分类结论 |
| POST | `/comparisons/{id}/cancel` | 取消 QUEUED/RUNNING 对比 |
| POST | `/comparisons/{id}/retry` | 重试 FAILED/TIMEOUT/CANCELLED 对比 |

提交示例：

```bash
curl -s -X POST http://127.0.0.1:8000/audits \
  -F "files=@Vault.sol" | jq
```

版本对比示例（先有一份已完成的基线，再提交新版本）：

```bash
# 1) 提交基线版本并等待完成，拿到 task_id
BASE_ID=$(curl -s -X POST http://127.0.0.1:8000/audits \
  -F "files=@Vault_v1.sol" | jq -r .task_id)

# 2) 提交新版本并指定基线
CID=$(curl -s -X POST http://127.0.0.1:8000/comparisons \
  -F "baseline_task_id=$BASE_ID" \
  -F "files=@Vault_v2.sol" | jq -r .compare_id)

# 3) 轮询对比结果
curl -s http://127.0.0.1:8000/comparisons/$CID | jq '.result.counts, .result.deltas'
```

返回的 `result` 形如：

```json
{
  "baseline_task_id": "…", "current_task_id": "…",
  "baseline_report_hash": "…", "current_report_hash": "…",
  "comparison_hash": "…",
  "counts": {"NEW": 1, "FIXED": 1, "PERSISTENT": 2, "SEVERITY_CHANGED": 1},
  "deltas": [
    {"delta_id": "D-…", "category": "NEW", "rule_id": "DANGEROUS_EXTERNAL_CALL",
     "baseline": null, "current": {"function": "newFn", "line": 8, "…": "…"}}
  ]
}
```

## 7. 可复现性保证

1. **顺序无关**：指纹只依赖 `{规范路径, 内容}` 的排序拼接；
2. **并发无关**：指纹去重 + 状态 CAS，16 路并发提交同一合约只产生一个任务、
   一份结论；
3. **结论确定**：规则解析与输出均确定性排序，`finding_id` 与 `report_hash`
   内容寻址；
4. **跨重启一致**：结论按指纹持久化，服务重启后复用同一份结论；
5. **对比确定**：`app/diffing.compare_reports` 是纯函数，分类/排序/编号/统计
   只取决于两份报告内容；`comparison_hash` 不含任务 id，因此同一对
   (基线,新版本) 无论重复提交、并发还是提交先后，结论逐字节一致；
6. **对比跨重启一致**：对比结论按 (新版本指纹, 基线任务id) 持久化，重启后
   复用；同一新版本对不同基线各自独立、互不覆盖。

本地手工验证对比可复现性：

```bash
uv run uvicorn main:app --reload
# 对同一对 (基线, 新版本) 用 /comparisons 连续/并发提交多次，
# 始终返回同一 compare_id；记录返回里的 comparison_hash。
# 然后 Ctrl-C 停止服务、重新启动，再次提交同一对，
# compare_id 与 comparison_hash 都应与之前完全相同。
```

## 8. 验证方法

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
- 端到端 HTTP：提交、查询、幂等并发、404/409 处理；
- **版本对比（新增）**：新增 / 已修复 / 仍然存在 / 严重程度变化四类分类；
  代码位置整体挪动 + 纯重命名后原问题仍判仍然存在（不抖动）；
  同版本对不同基线各自独立；并发重复提交只产生一条对比记录且结论一致；
  基线不存在 / 未完成 / 不同源分别得到
  `BASELINE_NOT_FOUND / BASELINE_NOT_READY / BASELINE_MISMATCH`（不降级、
  无半截结果）；对比失败重试与排队取消后重试不产生重复记录；
  重启后对比结论不丢；数百条结论下分类/顺序/编号/统计稳定。

`-s` 可看到每条用例打印的**输入标识与判定依据**，例如：

```
[rule] 函数内重入 -> REENTRANCY L6 外部 call 调用之后仍存在状态写（函数内重入风险）...
[rule] 受锁保护 -> 无 REENTRANCY 命中（对照通过）
[task] 16 路并发提交 -> 单任务 7b3a..., findings=1 hash=...
[diff] 四类分类 -> {'NEW': 1, 'FIXED': 1, 'PERSISTENT': 2, 'SEVERITY_CHANGED': 1}
[compare] 12 路并发重复 -> 单对比 a1b2..., hash=...
```
