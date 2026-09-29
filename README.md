# Solidity 本地静态审计流水线

在现有 FastAPI 服务基础上实现的一套本地静态分析流水线，使同一批合约在**重复提交、
提交顺序不同或并发提交**时都能得到**一致、可复现且可解释**的审计结论；并支持把
**新版本与历史基线版本对比**，直接给出新增 / 已修复 / 仍然存在 / 严重程度变化四类
差异，同样保证可复现、可重启恢复且不同基线互不干扰。

## 1. 架构总览

```
来源接入 -> 内容校验 -> 导入闭包解析 -> 内容指纹(sha256)
                                              |
                       +----------------------+
                       v
              [ TaskManager ] <--> SQLite (tasks / reports / inputs / diffs)
                       |
                       v
               规则引擎(确定性)
                       |
                       v
         命中合并去重 -> 稳定编号/排序 -> AuditReport
                       |
   新版本 + 基线版本 -> 跨版本站点签名匹配 -> 分类/统计/稳定排序 -> DiffReport
```

模块划分：

| 文件 | 职责 |
| --- | --- |
| `app/models.py` | 类型定义：`SourceFile / TaskRecord / Finding / AuditReport`、`DiffEntry / DiffReport`，状态、严重程度与差异分类枚举 |
| `app/errors.py` | `IngestError`、`BaselineError`，各自携带可区分的失败码 |
| `app/ingest.py` | 来源归一、UTF-8 解码、路径校验、import 闭包拓扑解析、内容指纹 |
| `app/rules.py` | 规则：重入（含跨函数重入、锁保护识别）、危险外部调用；跨版本站点稳定签名 |
| `app/engine.py` | 多规则命中合并、稳定编号、严重程度排序、`report_hash` |
| `app/diffing.py` | 版本对比：稳定签名配对、四类差异分类、统计与稳定排序、`diff_hash` |
| `app/store.py` | SQLite 持久化：任务记录、结论缓存、对比结论缓存、输入载荷，支持重启恢复 |
| `app/tasks.py` | 任务生命周期：去重、排队、超时、取消、重试、状态 CAS（审计与对比两类任务） |
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

## 3. 版本对比（新版本 vs 历史基线）

在单版本审计之上，支持指定一份**已经审计完成的历史提交作为基线**，提交新版本时
直接产出四类差异，免去人工对照两份报告。

### 3.1 问题如何在两个版本间匹配

每个外部调用站点都会生成一组**跨版本稳定身份信息**，匹配只看问题实质，不看表面
位置。站点身份由三部分组成：

- **合约分组键**：文件 + 合约状态骨架（状态变量声明序列，标识符槽位化），不含
  合约名、不含合约在文件中的序号——前置插入另一个合约不影响它；
- **结构槽位键**：合约分组 + 函数在合约内（全部函数中）的序号 + 该调用点在函数内
  的序号，不含行号与任何函数体内容——纯改名、注释/空白改动、整体上下挪动都不改变；
- **规范化函数体**：去注释、折叠空白后做词法切分，用户自定义标识符按出现顺序
  槽位化（`$0/$1/...`），数字/字符串字面量归一；在此之前先把外部调用形态规范化：
  `.send(x)` / `.transfer(x)` 与 `.call{value: x}(...)` 统一为同一「转账调用」
  形状，不带 `value` 的 `.call(...)` / `.delegatecall(...)` 统一为另一「低层
  调用」形状。（规则引擎识别新语法 `.call{value:…}(…)`；Solidity 0.5 之前的
  旧式 `.call.value(x)(…)` 不在规则识别范围内。）

> 操作符（send/call/delegatecall…）是**严重程度的判定因素**，刻意不作为站点身份；
> 转账金额表达式按普通表达式一起规范化。因此「同一站点把未检查返回值的
> `send(amount)`（低危）改成同样未检查返回值的 `call{value:amount}("")`（中危）」
> 不会被当成两个问题。

最终问题匹配键 = 站点身份 + 该问题命中的**规则集合**。匹配分两阶段：

1. **原位配对**：结构槽位键相同、规则集合相同、规范化函数体一致的结论直接配对；
2. **重排/位移兜底**：剩余结论在同一合约分组内，按规范化函数体与规则集合汇集
   候选，做**最小位移**一一匹配（同槽位优先、函数序号/调用序号距离最近优先），
   覆盖前面插入或删除函数导致的序号位移、函数重排。若某条结论的原槽位在另一侧
   被「函数体已变、且该站点已不再产出任何结论」的调用站点占据（原地修复的直接
   证据，例如给 `send` 加了 `require`），它不参与跨槽位配对，从而不会和旁边
   新增的另一个问题硬合并。

因此，下列**非实质演进不会**让原问题在对比里忽新忽旧，也不会错误产生严重程度变化：

- 在文件/合约里插入无关函数或另一个合约，使问题整体上移/下移；
- 调整函数先后顺序、把问题挪到文件不同位置；
- 纯标识符重命名（变量/函数/合约名）与注释、空白改动；
- 同一站点仅更换外部调用操作符（send↔call 等）且命中规则集合不变——这判为
  **严重程度变化**而非新增/已修复。

只有问题本身实质变化（命中规则集合变化、函数体语义变化且不能归位、调用点结构性
增减）时，才会体现为新增 / 已修复。

**已知边界**：

- 站点身份的标识符槽位按"函数体内出现顺序"分配，若在**同一个易受影响的函数体
  内部、问题调用点之前**插入引用了新标识符的语句，可能改变槽位而被视作实质变化；
  函数体之外（文件/合约级别）的插入与整体挪动不受影响；
- 不带 `value` 的低层调用（如 `call("")`）与转账调用（如 `send(x)`）被视为两种
  不同形态；跨形态（且金额表达式也变）的演进会按新增/已修复处理，而不是严重程度
  变化；
- 两个结构槽位、规范化函数体、规则集合**完全一致**的同形站点（例如多个函数体都
  只有一句 `send(1)`）发生互换式重排时，无法从内容上区分谁是谁，按序号最近的
  确定性方式配对（结论条数与分类不受影响）。

### 3.2 四类差异与统计

| 分类 | 含义 |
| --- | --- |
| `NEW` | 新版本多出的问题（基线没有可配对的同一站点、同一规则面问题） |
| `FIXED` | 基线有、新版本已消失（含原站点原地修复后不再产出结论）的问题 |
| `PERSISTING` | 两边都在、命中规则集合相同且严重程度相同 |
| `SEVERITY_CHANGED` | 两边都在（同一站点、同一规则面），仅严重程度不同；结果同时给出基线/新严重程度 |

严重程度变化条目的 `baseline_severity` / `current_severity` 分别给出两侧严重程度
（升高或降低都会判出），并同时携带 `baseline_finding` 与 `current_finding` 两侧
明细（函数名/行号等可能因改名或挪动而不同）。

- 同站点的多个结论按多重集、以「严重程度→文件→行→finding_id」稳定键排序后逐对
  配对，多出的一侧分别记为 FIXED / NEW，几百条结论也确定无歧义；
- entries 固定按 `NEW < FIXED < PERSISTING < SEVERITY_CHANGED`、同类按签名等稳定键
  排序；`counts` 给出各分类条数与 `total`；
- 结果显式携带 `baseline_task_id` 与 `baseline_fingerprint`，可看出是**相对哪份
  基线**比出来的；`diff_id = D- + sha256(新版本指纹, 基线指纹)[:16]`，
  `diff_hash` 覆盖基线/新两侧 report_hash 与全部分类条目，两份对比哈希相同即结论
  完全一致。

### 3.3 与单次审计的语义和兼容范围差别

| 维度 | 单次审计 `/audits` | 版本对比 `/audits/{id}/compare` |
| --- | --- | --- |
| 结论 | `report`（findings + report_hash） | `diff`（四类 entries + counts + diff_hash） |
| 去重键 | 新版本输入指纹 | （新版本指纹, **基线**指纹） |
| 同内容重复/并发 | 同一任务、同一结论 | 同一对基线/版本→同一任务、同一结论 |
| 不同基线 | —— | 各自独立任务与结论，**绝不互相复用** |
| 前置条件 | 无 | 基线必须存在、已 `SUCCEEDED`、与新版本至少共享一个同路径来源文件 |
| 生命周期 | 排队/超时/取消/重试/恢复 | 完全相同（同一张任务表、同一套状态 CAS） |

- 提交对比时若新版本此前未审计，会**自动先建立该版本的普通审计任务**再对比；
  普通审计与对比是两条独立记录，互不串用。
- 对比是**有方向**的：以 A 为基线比 B，与以 B 为基线比 A，`NEW/FIXED` 对调、
  `diff_hash` 不同。

### 3.4 基线不可用时明确拒绝（HTTP 400，不降级）

| error_code | 触发条件 |
| --- | --- |
| `BASELINE_NOT_FOUND` | 基线任务 id 不存在（或不是一次审计任务） |
| `BASELINE_NOT_READY` | 基线存在但还没审计完成（非 SUCCEEDED），或其来源载荷缺失 |
| `BASELINE_UNRELATED` | 基线与当前提交没有任何同路径来源文件，根本对不上 |

任一情况都会在任务创建**之前**拒绝：不会悄悄退化成单版本审计，也不会返回半截
对比结果。新版本自身的来源问题仍返回 `SOURCE_MISSING / INVALID_CONTENT /
IMPORT_UNRESOLVABLE`。

### 3.5 对比任务的可靠性

- 与普通审计同一生命周期：进队列、受 `AUDIT_TASK_TIMEOUT` 超时约束、可取消、
  失败可重试（最多 3 次）；
- 同样用 `(状态, attempts)` CAS 令牌：取消/超时/重试与计算完成的任意交错都不会
  写出过期或重复结论；
- 失败后或取消后**再重试 / 再提交同一对**，复用同一条任务记录，不产生重复对比，
  也不写入旧结果；
- 对比结论持久化在 `diffs` 表（主键为新版本+基线指纹），服务重启后已算好的对比
  直接复用，未完成的对比任务重启后重新入队。

## 4. 任务状态语义

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

**去重**：审计任务以归一来源的 sha256 指纹为主键；对比任务以
（新版本指纹, 基线指纹）为主键。无论重复多少次、什么并发时序，相同输入（对比则是
相同的版本对）永远返回同一 `task_id`；已完成结论分别缓存在 `reports` / `diffs` 表，
再次提交直接复用，零重复计算。不同基线的对比彼此独立、绝不复用。

**重启恢复**：输入载荷存于 `inputs` 表、审计结论存于 `reports` 表、对比结论存于
`diffs` 表、任务存于 `tasks` 表（`kind` 区分 audit/diff）。重启时 `QUEUED/RUNNING`
任务自动重新入队，`SUCCEEDED` 结论直接复用，不丢失任何任务或结论。

## 5. 接入失败原因（彼此可区分，HTTP 400）

| error_code | 触发条件 |
| --- | --- |
| `SOURCE_MISSING` | 提交为空；某个声明文件的内容为空 |
| `INVALID_CONTENT` | 非 UTF-8；空/绝对路径或含 `..` 遍历；重复路径；不含任何 Solidity 结构 |
| `IMPORT_UNRESOLVABLE` | import 目标不在提交的来源集合内；循环导入 |
| `BASELINE_NOT_FOUND` | 对比时基线任务不存在或不是审计任务 |
| `BASELINE_NOT_READY` | 基线尚未审计完成（或来源载荷缺失） |
| `BASELINE_UNRELATED` | 基线与当前提交没有共同路径的来源文件，对不上 |

所有失败在任务创建**之前**拒绝，不产生半成品结果或空壳任务；基线类失败不会降级为
单版本审计。

## 6. HTTP API

```bash
uv run uvicorn main:app --reload
```

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/audits` | multipart 上传文件，返回 202 + 任务；相同内容幂等 |
| GET | `/audits/{id}` | 查询状态、审计结论或对比结论 |
| POST | `/audits/{id}/cancel` | 取消 QUEUED/RUNNING 任务（审计/对比通用） |
| POST | `/audits/{id}/retry` | 重试 FAILED/TIMEOUT/CANCELLED 任务（审计/对比通用） |
| POST | `/audits/{id}/compare` | 以已完成审计 `{id}` 为基线，上传新版本做版本对比 |

提交审计示例：

```bash
curl -s -X POST http://127.0.0.1:8000/audits \
  -F "files=@Vault.sol" | jq
```

版本对比示例（先拿到基线任务 id `$BASE`，再上传新版本）：

```bash
BASE=$(curl -s -X POST http://127.0.0.1:8000/audits -F "files=@Vault_v1.sol" \
  | jq -r .task_id)
# 等基线 SUCCEEDED 后：
curl -s -X POST "http://127.0.0.1:8000/audits/$BASE/compare" \
  -F "files=@Vault_v2.sol" | jq
```

返回任务的 `kind=diff`，完成后 `diff` 字段包含 `counts`（NEW/FIXED/PERSISTING/
SEVERITY_CHANGED/total）、`baseline_task_id`、`baseline_fingerprint` 与按分类稳定
排序的 `entries`（每条含基线侧与新版本侧 finding 及各自严重程度）。

## 7. 可复现性保证

1. **顺序无关**：指纹只依赖 `{规范路径, 内容}` 的排序拼接；
2. **并发无关**：指纹去重 + 状态 CAS，16 路并发提交同一合约只产生一个任务、
   一份结论；对比同理，16 路并发提交同一（新版本, 基线）对只产生一个对比任务；
3. **结论确定**：规则解析与输出均确定性排序，`finding_id` 与 `report_hash`
   内容寻址；对比的配对、分类、排序只依赖两份报告内容，`diff_id/diff_hash`
   内容寻址——**先跑哪一侧、提交先后、是否重复都不影响结论**；
4. **匹配抗演进**：跨版本站点身份对整体位移、函数/合约重排、纯命名/注释改动
   稳定，非实质改动不会被误判为新增或已修复；同一站点仅切换外部调用操作符
   （send↔call 等）导致的严重程度升降稳定判为 SEVERITY_CHANGED，不会被拆成
   「新增 + 已修复」；
5. **基线隔离**：去重键含基线指纹，同一新版本配不同基线得到独立结论；
6. **跨重启一致**：审计与对比结论分别按指纹、（版本对）持久化，服务重启后复用
   同一份结论。

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
- 版本对比：新增 / 已修复 / 仍然存在 / 严重程度变化四类判定；
  插入无关代码整体下移、函数重排、纯重命名后原问题仍匹配为 PERSISTING；
  **严重程度变化专项**：用真实 Solidity 演进覆盖低危→中危（未检查 `send(amount)`
  →未检查 `call{value:amount}("")`）与反向降低、顶部插入合约/函数整体挪动 +
  重命名 + 重排后仍判 SEVERITY_CHANGED、以及"原地修复（加 require）+ 旁边新增
  delegatecall"不被硬合并而判 FIXED+NEW 的边界；
  同一新版本配不同基线互不干扰；16 路并发重复对比单任务单结论且哈希一致；
  严重程度变化在真实提交链路上的并发重复提交与服务重启后，分类/条数/顺序/
  diff_hash 完全一致；
  对比任务排队取消、失败重试、取消后重试均不产生重复记录；300 条结论下
  分类/顺序/统计稳定；对比结论跨重启复用；
- 基线拒绝：不存在 / 未完成 / 对不上分别得到
  `BASELINE_NOT_FOUND / BASELINE_NOT_READY / BASELINE_UNRELATED`，不降级；
- 端到端 HTTP：提交、查询、幂等并发、版本对比、404/409 处理。

本地手工验证对比可复现性：

```bash
BASE=$(curl -s -X POST localhost:8000/audits -F "files=@v1.sol" | jq -r .task_id)
# 等待 SUCCEEDED
for i in 1 2 3; do
  curl -s -X POST localhost:8000/audits/$BASE/compare -F "files=@v2.sol" \
    | jq -r .task_id
done   # 三次（或并发）打印的 task_id 必须相同；diff.diff_hash 也必须一致
```

`-s` 可看到每条用例打印的**输入标识与判定依据**，例如：

```
[rule] 函数内重入 -> REENTRANCY L6 外部 call 调用之后仍存在状态写（函数内重入风险）...
[rule] 受锁保护 -> 无 REENTRANCY 命中（对照通过）
[task] 16 路并发提交 -> 单任务 7b3a..., findings=1 hash=...
[diff] 整体位移后匹配 -> 全部 PERSISTING {'NEW': 0, ...}
[difftask] 16 路并发重复对比 -> 单任务 a91f..., hash=...
[sev] 严重程度升高 LOW->MEDIUM -> SEVERITY_CHANGED LOW->MEDIUM
[difftask] 严重程度变化并发/重启一致 hash=...
```

严重程度变化专项用例单独运行：

```bash
uv run pytest tests/test_severity_change.py -q -s
```

本地手工复现「严重程度变化」：准备两个版本的同一合约，基线里是返回值未检查的
`send`（低危），新版本里把同一站点改成返回值同样未检查的低层 `call`（应升中危），
其余代码（含函数名、位置）保持不变：

```solidity
// v1.sol（基线）
contract Wallet {
    function withdraw(address payable to, uint amount) public {
        to.send(amount);
    }
}
// v2.sol（新版本：仅把 send 换成 call{value:...}）
contract Wallet {
    function withdraw(address payable to, uint amount) public {
        to.call{value: amount}("");
    }
}
```

```bash
BASE=$(curl -s -X POST localhost:8000/audits -F "files=@v1.sol" | jq -r .task_id)
curl -s -X POST localhost:8000/audits/$BASE/compare -F "files=@v2.sol" \
  | jq '.diff.counts, .diff.entries[] |
        {category, baseline_severity, current_severity}'
# 期望：counts 为 {"NEW":0,"FIXED":0,"PERSISTING":0,"SEVERITY_CHANGED":1,...}，
# 条目 baseline_severity="LOW"、current_severity="MEDIUM"。
```
