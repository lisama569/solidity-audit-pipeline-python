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

每个外部调用站点都会生成一个**跨版本稳定签名**，匹配只看问题实质，不看表面位置：

- 规范化函数体：去注释、折叠空白后做词法切分，把**用户自定义标识符**按出现顺序
  槽位化（`$0/$1/...`），Solidity 关键字/类型/全局内建名与调用目标链
  （`msg.sender`、用户地址变量等）保留，数字/字符串字面量归一；
- **抹掉外部调用原语本身**：规范化前把每个 `.call/.delegatecall/.send/.transfer`
  连同 `{value:...}` 选项块与参数列表统一替换成占位符。原语与参数只决定该调用
  的**严重程度**，不属于"问题在哪、周边是什么"的站点实质——因此同一处调用仅由
  `send` 改成 `call`（未检查返回值 LOW→MEDIUM）这类**只改变严重程度**的演进，
  站点签名不变，会被识别成「严重程度变化」而不是一条新增加一条已修复；
- 以「文件 + 合约状态骨架（状态变量声明序列）+ 规范化并抹除原语后的函数体 +
  调用点在该函数内的序号」哈希出站点签名；再叠加该问题命中的**规则集合**得到
  最终匹配键。

因此，下列**非实质演进不会**让原问题在对比里忽新忽旧：

- 在文件/合约里插入无关函数或代码，使问题整体上移/下移；
- 调整函数先后顺序、把问题挪到文件不同位置；
- 纯标识符重命名（变量/函数/合约名）与注释、空白改动；
- **同一处外部调用只更换原语/参数导致的严重程度升降**（send↔call 等）。

问题本身实质变化（命中规则集合变化、所在函数体周边语义变化、调用点结构性增减）
时，才会体现为新增 / 已修复；仅严重程度不同记为严重程度变化。

**配对时的反误并保护**：同一签名下先把严重程度相同的结论配成「仍然存在」；
两侧剩余结论**数量相等**时才逐对判为「严重程度变化」。若数量失衡——例如旧问题
所在函数被整个删除、旁边又新加了一个规范化后同形的调用——无法确定哪条是原
问题时，**保守地全部记为已修复/新增，绝不硬并**出一条严重程度变化。站点周边
实质不同（函数体内还有别的特有语句、调用目标链不同等）的新旧问题签名本来就
不同，天然不会被合并。

**已知边界**：

- 签名的标识符槽位按"函数体内出现顺序"分配，若在**同一个易受影响的函数体内部、
  问题调用点之前**插入引用了新标识符的语句，可能改变槽位而被视作实质变化；
  函数体之外（文件/合约级别）的插入与整体挪动不受影响；
- 若基线与新版本里存在多个**规范化后完全同形**（含调用目标链、周边语句也一致）
  的同签名问题且数量发生变化，如上所述按删除/新增保守处理，不会猜配。

### 3.2 四类差异与统计

| 分类 | 含义 | 与相邻类别的边界 |
| --- | --- | --- |
| `NEW` | 新版本多出的问题（基线无同签名问题，或同签名组数量失衡后保守记新） | 同签名两侧都在时不会是 NEW；只有数量对不上的多余项才算 |
| `FIXED` | 基线有、新版本已消失的问题（同上，保守记修复） | 同签名两侧都在时不会是 FIXED |
| `PERSISTING` | 两边都在、命中规则集合相同且严重程度相同 | 严重程度只要不同即落入 SEVERITY_CHANGED |
| `SEVERITY_CHANGED` | 两边都在（签名相同）、命中规则集合相同，**仅严重程度不同**；结果同时给出 `baseline_severity` 与 `current_severity`（升高/降低都算） | 规则集合变了说明问题实质变了，按 NEW/FIXED 处理；同签名组剩余数量不等时不猜配，保守按 NEW/FIXED 处理 |

典型的严重程度变化（均为真实规则会产出的差异）：

- 未检查返回值的 `.send`（LOW）→ 未检查返回值的低层 `.call`（MEDIUM）：升高；
- `delegatecall` 后的重入（HIGH）→ `send` 后的重入（MEDIUM）：降低；
- 上述变化即使伴随整体位移、函数/合约改名，只要站点实质未变，仍判严重程度变化。

- 同签名问题按多重集、以「严重程度→文件→行→finding_id」稳定键排序，先配严重
  程度相同的 PERSISTING，再在两侧剩余数量相等时逐对配 SEVERITY_CHANGED，多出的
  一侧分别记为 FIXED / NEW，几百条结论也确定无歧义；
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
4. **匹配抗演进**：跨版本签名对整体位移、函数重排、纯命名/注释改动稳定，且抹掉
   了只决定严重程度的外部调用原语与参数，非实质改动（含仅严重程度升降）不会被
   误判为新增或已修复；同签名组数量失衡时保守按新增/修复处理，不硬并；
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
  **真实 Solidity 演进**下未检查 `.send`(LOW)→未检查 `.call`(MEDIUM) 判严重程度
  升高、`delegatecall` 重入(HIGH)→`send` 重入(MEDIUM) 判严重程度降低，且结果同时
  给出两侧严重程度；严重程度变化叠加顶部插合约/函数重排/纯改名后仍能匹配；
  旧问题删除+旁边新增异质问题（及同形同签名多重集失衡）不被硬并成严重程度变化；
  插入无关代码整体下移、函数重排、纯重命名后原问题仍匹配为 PERSISTING；
  同一新版本配不同基线互不干扰；16 路并发重复对比单任务单结论且哈希一致；
  对比任务排队取消、失败重试、取消后重试均不产生重复记录；300 条结论下
  分类/顺序/统计稳定；对比结论跨重启复用；
- 基线拒绝：不存在 / 未完成 / 对不上分别得到
  `BASELINE_NOT_FOUND / BASELINE_NOT_READY / BASELINE_UNRELATED`，不降级；
- 端到端 HTTP：提交、查询、幂等并发、版本对比（含严重程度变化 LOW→MEDIUM 的
  JSON 序列化）、404/409 处理。

本地手工复现「严重程度变化」（完整提交+审计链路，而不是手工构造结论）：

```bash
cat > v1.sol <<'EOF'
contract Vault {
    function leak() public { msg.sender.send(1); }
}
EOF
cat > v2.sol <<'EOF'
contract Vault {
    function leak() public { msg.sender.call(""); }
}
EOF
BASE=$(curl -s -X POST localhost:8000/audits -F "files=@v1.sol" | jq -r .task_id)
# 等待 SUCCEEDED 后：
curl -s -X POST localhost:8000/audits/$BASE/compare -F "files=@v2.sol" \
  | jq -r .task_id | xargs -I{} curl -s localhost:8000/audits/{} \
  | jq '.diff.counts, .diff.entries[]
        | {category, baseline_severity, current_severity}'
# 期望：SEVERITY_CHANGED=1、NEW=0、FIXED=0，
#       条目 baseline_severity="LOW" current_severity="MEDIUM"
```

同一份 v2 重复/并发提交、或重启服务后再查，任务 id、分类条数、entries 顺序与
`diff_hash` 都必须完全一致。

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
```
