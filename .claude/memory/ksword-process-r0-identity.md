---
name: ksword-process-r0-identity
description: R0-only 进程危险动作的创建时间来源、驱动对象身份校验与旧协议兼容约束
metadata:
  type: project
---

# R0-only 进程身份校验

进程表的“仅内核枚举可见”记录可能无法通过 `OpenProcess` 得到同一对象。Rootkit 还可能篡改
`UniqueProcessId`、活动链表或用户态查询路径，因此不能用 R3 `OpenProcess + GetProcessTimes`
替代驱动对目标 `EPROCESS` 的身份判断。

## 当前链路

- `KSWORD_ARK_PROCESS_ENTRY` v3 返回 `creationTime100ns`，值来自枚举时已引用对象的
  `PsGetProcessCreateTimeQuadPart`。无法引用的 CID 弱证据行返回 0。
- `ProcessDock` 对有真实 R0 创建时间的 kernel-only 行直接使用该时间建立 identity；旧驱动或
  弱证据行才使用 `KernelOnlyCreationTimeSeed + PID` 维持稳定显示键。
- R0 结束进程与 `BreakOnTermination/APC` 特殊标志请求携带
  `expectedCreateTime100ns`。驱动先按 CID/ActiveProcessLinks/PID 解析并引用 `EPROCESS`，再比较
  `PsGetProcessCreateTimeQuadPart`，不匹配返回 `STATUS_INVALID_CID` 且不执行写操作。
- 普通 R3 可见进程继续持有经 `GetProcessTimes` 验证的 Win32 查询句柄，并同时接受驱动侧校验。
  kernel-only 目标跳过 Win32 句柄校验，只使用驱动侧对象校验。
- 新驱动按请求字段偏移接受旧版终止/特殊标志固定前缀。旧请求缺失的创建时间按 0 处理。

## 约束

- 新增按 PID/CID 定位的 R0 危险动作时，优先把期望创建时间放入 `shared/driver/` 请求结构，
  并在驱动解析出的对象上校验。
- 不要把 kernel-only 行的合成 identity 时间传给驱动。合成值只用于 UI 缓存键。
- 不要全局关闭 `ProcessDock::dispatchProcessActionTargetsInParallel` 的 R3 identity hold。
  只对明确标记为 `isKernelOnly` 的目标跳过。
