# 任务状态语义与并发模型

## 状态机

```
            提交(去重未命中)
                  │
                  ▼
              ┌────────┐  worker 领取   ┌─────────┐  成功   ┌───────────┐
              │ QUEUED │ ─────────────► │ RUNNING │ ──────► │ COMPLETED │
              └────────┘                 └─────────┘         └───────────┘
                  │  ▲                      │  │  │                ▲
        取消(排队)│  │ 失败/超时且           │  │  │ 失败/超时       │ 终态
                  ▼  │ 仍有重试额度          │  │  └──► FAILED/TIMEOUT
            ┌───────────┐  ◄────────────────┘  │           (额度耗尽)
            │ CANCELLED │      自动回队          │
            └───────────┘                       │ 取消信号
                  ▲                             ▼
                  └──────────────────── CANCELLED(执行中协作取消)

   FAILED/TIMEOUT ──显式 retry──► QUEUED
   FAILED/TIMEOUT ──cancel──────► CANCELLED
```

| 状态 | 语义 | 是否终态 | 重启后行为 |
|---|---|---|---|
| `QUEUED` | 已落盘、等待 worker 领取（含自动重试回队） | 否 | 重新灌入内存队列继续执行 |
| `RUNNING` | 已被某个 worker 领取、正在执行，`attempts` 已 +1 | 否 | 视为上次崩溃，**回滚为 QUEUED** 重新执行 |
| `COMPLETED` | 审计成功，`report` 字段为可复现结论 | 是 | 结论直接可读，永不重算 |
| `FAILED` | 执行报错且 `attempts == max_attempts` | 是* | 保留，可显式 retry |
| `TIMEOUT` | 执行超过时限且重试额度耗尽 | 是* | 保留，可显式 retry |
| `CANCELLED` | 被用户取消（排队中取消或执行中协作取消） | 是 | 保留，不再执行 |

\* `FAILED`/`TIMEOUT` 对自动处理而言是终态，但允许人工 `retry` 或 `cancel`。

合法流转表在代码中由 `service._ALLOWED` 强约束，任何不在表内的流转
（例如对 COMPLETED 再次取消、对 RUNNING 直接 retry）都会抛出
`TASK_STATE_CONFLICT`，服务不会写入非法状态。

## 幂等与去重

- 任务的身份是**归一化内容哈希**（SHA-256，覆盖 normpath 后的全部文件内容
  与入口路径），与提交顺序、路径书写形式（`A.sol` 与 `./A.sol`）无关；
- `content_hash` 在 SQLite 中有唯一约束；提交路径在一把服务级 RLock 内完成
  “查哈希 → 建任务 → 入队”，因此多线程并发提交相同内容时**恰好创建一个任务**；
- 重复提交返回同一个任务对象，响应中 `deduplicated=true`（HTTP 200），
  新任务返回 202。去重命中不会重新排队、不会重新计算。

## 并发控制

- 一个 FIFO 的线程安全内存队列（`queue.TaskQueue`）负责任务领取顺序；
- `AuditService` 用一把可重入锁串行化所有状态校验与落盘，worker 数量
  （默认 2）可配置；
- 每次执行持有一个**运行代号（epoch）**。任务超时回队后，旧执行线程不会
  被强杀（Python 限制），但旧回合在结束时发现代号已过期便不再触碰任务状态，
  从而避免“旧结果覆盖新回合”的竞态；
- 取消正在运行的任务会设置协作取消事件，worker 在解析完成、写结论前检查；
  排队中的取消则把任务直接置为 CANCELLED 并从队列摘除。

## 超时与重试

- `task_timeout`（默认 30s）为单次执行时限，在单独的执行线程中 join；
- 执行失败或超时且 `attempts < max_attempts`（默认 3）时，任务自动
  `RUNNING -> QUEUED` 回队重试；
- 额度耗尽后分别落为 `FAILED`（携带 `INTERNAL_ERROR` 或具体规则错误）与
  `TIMEOUT`（携带 `TASK_TIMEOUT`），错误信息持久化在任务的 `error` 字段。

## 来源失败 vs 执行失败（错误码可区分）

| 阶段 | 错误码 | 时机 | 是否产生任务 |
|---|---|---|---|
| 提交 | `SOURCE_MISSING` | 入口或被 import 的文件未提交 | 否（整体拒绝） |
| 提交 | `UNRESOLVED_IMPORT` | 裸包名、路径越界等无法映射的 import | 否 |
| 提交 | `INVALID_CONTENT` | 空内容、非法字符、未闭合、结构损坏 | 否 |
| 提交 | `INVALID_SUBMISSION` | 空来源、非法路径、归一化后重复 | 否 |
| 运行 | `TASK_NOT_FOUND` / `TASK_STATE_CONFLICT` / `TASK_TIMEOUT` / `INTERNAL_ERROR` | 查询/取消/重试/执行期 | 是（状态可查） |

所有来源错误都发生在任何状态写入之前，因此**不会留下半成品任务**。
