# Memory Index

- [KSword UI/主题架构](ksword-ui-architecture.md) — theme.h token 体系、全局样式块链路、WindowChrome 标题栏染色、better-ui 分支改动
- [标题栏全局搜索/双模式输入](ksword-global-ui-search.md) — GlobalUiSearch 架构、页面路径/高亮跳转链路、i18n 审计恒等词条与语言包定点插入约定
- [MSVC/WDK 构建恢复](ksword-build-recovery.md) — `LNK1000 IMAGE::BuildImage` 的一次性 WPO 禁用重建，以及驱动 x64 `ApiValidator` 后置校验边界
- [驱动候选地址安全读取](ksword-driver-safe-read.md) — 不可信内核地址统一使用 `KswordARKRuntimeReadMemory`，以及 Release 同构函数符号归因注意事项
- [蓝屏 BGP 准备与 BPP 哨兵](ksword-bugcheck-bgp.md) — 未取得显示所有权时的 `BPP=1`、24/32 BPP 双资源预生成、崩溃阶段诊断日志与 fail-closed 边界
- [FileDock 文件元数据编辑](ksword-file-metadata-editor.md) — FILE_BASIC_INFO 零值写入、重解析点句柄、文件身份复核、结构性属性保留与异步回读
