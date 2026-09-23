# 可复现性保证与验证方法

## 为什么结论可复现

本流水线把“接入 → 归一 → 解析 → 规则求值 → 结论归并”全部设计为
**确定性、无外部依赖的纯函数链路**：

1. **路径归一化**：所有提交路径经 `posixpath.normpath` 折叠 `./`、`//`
   与路径书写差异；拒绝绝对路径、盘符、反斜杠与 `..` 越界。
2. **内容哈希做身份**：对归一化后的 `{路径: 内容}` + 入口做 SHA-256。
   序列化时按路径排序，因此：
   - 同一批文件顺序不同 → 哈希相同；
   - 路径书写不同（`A.sol` / `./A.sol` / `dir/../A.sol`）→ 哈希相同；
   - 任何一个字节不同（含空白字符）→ 哈希不同。
3. **纯函数式引擎**：解析与规则求值不访问时间、随机数、文件系统、网络或
   环境变量；遍历顺序（文件拓扑序、合约定义序、语句源码序、规则注册序）
   全部固定。
4. **结论归并与编号确定**：同一问题按 (文件, 合约, 函数, 行, 列) 合并，
   排序键全序（严重程度 → 定位 → 类别 → 标题 → key），编号随排序分配。
5. **去重落在存储唯一键**：SQLite 对 `content_hash` 加 UNIQUE 约束，加上
   服务锁，保证重复/乱序/并发提交都只有一个任务、一份报告。

对于相同输入，`AuditReport.to_dict()` 序列化结果逐字节一致。

## 失效模式与行为

| 情况 | 行为 |
|---|---|
| 重复提交相同合约 | HTTP 200 `deduplicated=true`，复用已有结论，不重算 |
| 以不同顺序提交 | 哈希相同，去重命中 |
| 路径书写不同但等价 | normpath 后相同，去重命中 |
| 多线程同时提交相同内容 | 恰有一个线程创建任务（created=true），其余复用 |
| 服务崩溃后重启 | COMPLETED 结论保留；RUNNING 回滚 QUEUED；QUEUED 续跑 |
| 执行失败/超时 | 在 max_attempts 内自动回队重试，结论不因瞬时故障而不同 |

## 如何验证（测试地图）

全部验证用例位于 `tests/`，使用 pytest，且测试输出通过 `-s` 打印
**输入标识（fixture 路径）与判定依据（规则 ID、证据、定位、严重度）**：

| 测试文件 | 覆盖的保证 |
|---|---|
| `test_reproducibility.py` | 哈希与顺序无关、5 次引擎求值逐字节一致、重复提交去重、乱序去重、路径书写去重、8 线程并发提交恰好 1 个任务、不同输入不被误去重 |
| `test_malformed_sources.py` | SOURCE_MISSING / UNRESOLVED_IMPORT / INVALID_CONTENT / INVALID_SUBMISSION 四类失败彼此可区分、畸形输入不留任务、多文件中一个非法则整体拒绝 |
| `test_reentrancy_contrast.py` | 跨函数重入 CRITICAL（证据含未加锁兄弟函数）、同函数 HIGH、受锁保护与干净合约 no_findings、多规则合并 rule_ids、编号/排序稳定、多结论严重度降序 |
| `test_lifecycle.py` | 排队取消、终态取消冲突、失败自动重试、持续失败终态、显式 retry、超时标记与重试、未知任务、重启恢复、并发取消状态自洽 |
| `test_api.py` | 202/200 幂等状态码、422 错误码区分、404/409、无风险明确结论 |

### 一键验证

```bash
uv sync                       # 安装依赖
uv run pytest                 # 运行全部 44 个用例（安静输出）
uv run pytest -s              # 同时打印每个用例的输入标识与判定依据
```

期望结果：`all passed`，并且在对照用例中看到：

- `cross_function_reentrancy.sol` → `F-0001 CRITICAL`，证据含
  `unguarded_sibling_writers: ['deposit', 'setBalance']`；
- `same_function_reentrancy.sol` → `F-0001 HIGH`；
- `guarded_reentrancy.sol` 与 `clean_contract.sol` → `no_findings=True`
  与明确的“未命中任何审计规则”结论文本。

### 手工验证（HTTP）

```bash
uv run uvicorn main:app --port 8000 &
curl -s -X POST localhost:8000/audit/tasks -H 'Content-Type: application/json' -d '{
  "entry_point": "Wallet.sol",
  "sources": [{"path": "Wallet.sol", "content": "contract W{ ... }"}]
}'
# 第一次 202，再发一次同样请求得到 200 且 id 相同
```

## 复现性范围说明

- 报告内容（findings、编号、严重度、定位、证据、rules_evaluated）逐字节稳定；
- 任务 `id` 为 UUID，仅用于内部寻址，**故意不作为复现性的一部分**——相同
  内容重复提交会复用首个 UUID；
- 时间戳（created_at/updated_at）是元数据，不参与审计结论；
- 若要跨数据库实例对账，请对比 `content_hash` 与报告内容，而非任务 UUID。
