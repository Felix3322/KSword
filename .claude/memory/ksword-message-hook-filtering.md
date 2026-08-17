---
name: ksword-message-hook-filtering
description: Win32k 消息 Hook 所有者/目标筛选语义、默认预算和进程右键入口约束
metadata:
  type: project
---

# Win32k 消息 Hook 筛选

- R0/R3 共享协议仍使用 `shared/driver/KswordArkWin32kIoctl.h` 中的
  `KSWORD_ARK_WIN32K_QUERY_REQUEST` 和
  `IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB`；所有者/目标的区别通过
  `KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER` 与
  `KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET` 表达，不需要复制 IOCTL。
- 两个选择位都未设置时保留旧版“所有者或目标匹配”的 ABI 行为；只设置其中一个时，
  Session/PID/TID 过滤只能匹配对应一侧。两个位同时设置表示显式恢复两侧匹配。请求中
  所有有效字段必须在同一侧组成完整谓词，禁止按字段分别在 owner/target 两侧 OR，
  否则会产生 Session 命中 owner、PID 命中 target 的跨侧假阳性。
- 进程右键菜单“转到 -> 消息 Hook”默认表达“作用于该进程线程的 Hook”；范围选择器可
  显式切到“由该进程安装”或“两侧相关”。调用 `queryWin32kHooksPdb` 时必须携带对应的
  `MATCH_TARGET`/`MATCH_OWNER` 位；R3 按相同语义防御性复核，但不能代替 R0 定点筛选，
  否则无关记录会提前耗尽返回预算。异步查询期间范围发生变化时必须丢弃旧范围结果并
  重新查询，避免旧结果短暂覆盖当前选择。
- 消息 Hook 的默认预算是独立的
  `KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES`（4096），不要为了扩大 Hook
  结果而修改其它 Win32k 枚举共用的 1024 默认值。硬上限仍由
  `KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES` 和实际输出缓冲容量共同约束；CLI 的 Hook 专用
  响应缓冲必须覆盖响应头加 8192 个完整条目，并用编译期断言防止协议结构增长后静默
  截断。
- UI/CLI 都应展示驱动返回的链数、访问节点数、读取失败、损坏链接和重复节点统计。
  IOCTL 成功只代表传输完成；`PARTIAL`/`TRUNCATED` 等总体状态必须使用警示色，不能按
  完全成功显示。
- Win32k IOCTL 使用 `METHOD_BUFFERED`；公共适配器必须在初始化输出头前复制请求。
  无输入的旧调用由公共适配器按操作注入默认预算，Hook 查询使用 4096，其它查询仍用
  通用默认值。
