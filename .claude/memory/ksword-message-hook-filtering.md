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
  Session/PID/TID 过滤只能匹配对应一侧。两个位同时设置表示显式恢复两侧匹配。
- 进程右键菜单“转到 -> 消息 Hook”表达的是“作用于该进程线程的 Hook”，调用
  `queryWin32kHooksPdb` 时必须带 `MATCH_TARGET`；R3 的结果过滤只作为防御性复核，
  不能代替 R0 定点筛选，否则无关所有者记录会提前耗尽返回预算。
- 消息 Hook 的默认预算是独立的
  `KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES`（4096），不要为了扩大 Hook
  结果而修改其它 Win32k 枚举共用的 1024 默认值。硬上限仍由
  `KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES` 和实际输出缓冲容量共同约束。
- Win32k IOCTL 使用 `METHOD_BUFFERED`；公共适配器必须在初始化输出头前复制请求。
  无输入的旧调用由公共适配器按操作注入默认预算，Hook 查询使用 4096，其它查询仍用
  通用默认值。
