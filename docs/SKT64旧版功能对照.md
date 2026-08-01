# SKT64 旧版功能对照

> 参考边界：仅使用公开仓库 `PspExitThread/SKT64` 的旧版内容，对照提交为 `461e41a278d93b8fb0f1f6cc4ea36453a0c783e7`。  
> 未访问、未反编译、未推断非公开 NextGen 仓库或二进制。  
> 判定方法：公开源码阅读 + 公开旧版 Release 二进制的静态菜单/字符串清单；不执行参考二进制。

## 结论

KSword 现有代码已覆盖公开 SKT64 旧版中绝大多数可合理用于系统诊断、取证与管理的功能面。本次实际确认并补齐的两个缺口是：

1. `IoTimer` 枚举，并超越旧版增加受控的启动/停止。
2. “结束进程并删除映像文件”，且使用 PID 创建时间与文件 ID 防止路径/PID 竞态。

## 功能面对照

| SKT64 旧版功能面 | KSword 对应实现 | 状态 |
|---|---|---|
| 进程枚举、树、结束/强制结束、挂起/恢复、关键进程、PPL、隐藏 | `ProcessDock/`、`ArkDriverClient/`、`KswordARKDriver/src/features/process/` | 已覆盖并扩展 |
| 结束进程后删除映像 | `ProcessDock/ProcessDock.cpp`、`ksword/process/ProcessImageDeleteGuard.*` | 本次补齐；精确文件句柄删除 |
| 线程、Token、句柄、模块、内存、注入 | `ProcessDock/`、`HandleDock/`、`MemoryDock/`、R0 thread/process features | 已覆盖并扩展 |
| 窗口、热键、KCT/窗口扩展信息 | `WindowDock/`、`KernelDock` 的 win32k 枚举页 | 已覆盖并扩展 |
| 驱动枚举/卸载、DriverObject、DeviceObject、MajorFunction、FastIo、完整性 | `DriverDock/`、`KernelDeviceDriverObjectsTab`、driver integrity/unload/blind features | 已覆盖并扩展 |
| `IoTimer` | `KernelIoTimerTab.*`、`driver_object_query.c`、`io_timer_ioctl.c` | 本次补齐并超越 |
| SSDT / Shadow SSDT / Inline / IAT / EAT | `KernelDock/`、kernel hook/SSDT features | 已覆盖并扩展 |
| Timer/DPC、IDT/GDT、MSR/HAL/CPU 完整性 | `KernelTimerDpcTab`、`KernelDescriptorTableTab`、CPU/platform audit | 已覆盖并扩展 |
| 进程/线程/镜像/注册表/Ob/ExCallback/文件系统回调 | `KernelDock` callback enumeration/interception 与 R0 callback features | 已覆盖并扩展 |
| Minifilter、标准过滤、WFP function/callout | callback/filter/network audit pages 与 R0 filter/network features | 已覆盖并扩展 |
| MmUnloadedDrivers、PiDDB、内核对象类型、系统线程 | unloaded-driver/PiDDB/object-type/thread audit pages | 已覆盖并扩展 |
| 内核/物理内存读写、页表、反汇编诊断 | `MemoryDock/`、R0 memory features、kernel executable-memory scan | 已覆盖并扩展 |
| 物理磁盘查看/镜像/恢复/编辑 | `HardwareDock/`、`FileDock/`、storage forensics 协议 | 诊断/取证/可回滚路径已覆盖 |
| 文件删除、强制解锁、占用查找、恢复 | `FileDock/`、R0 file feature | 已覆盖并扩展 |
| 服务、网络、注册表、启动项、PE/签名分析 | `ServerDock/`、`NetworkDock/`、`RegistryDock/`、`AutoStartDock/`、文件详情 | 已覆盖并扩展 |

## IoTimer 超越项

旧版公开 SKT64 的 IoTimer 菜单只能看到地址/对象并复制。KSword 的新实现增加了：

- 枚举全部公开 DriverObject 命名空间，通过 `DEVICE_OBJECT.Timer` 公开字段组建清单。
- 通过带引用的 `IoEnumerateDeviceObjectList` 快照核验设备，不直接解引用 R3 地址。
- 操作前同时比较 DriverObject、DeviceObject 和 PIO_TIMER 三重身份；任一变化都拒绝并要求刷新。
- 只调用 WDM 公开 `IoStartTimer` / `IoStopTimer`，不读写未公开 `_IO_TIMER` 布局。
- IOCTL 要求 `FILE_WRITE_ACCESS` 和 UI 确认令牌，但不因高级模式或风险等级拒绝修改。
- UI 有不可跳过的风险确认，以及包含精确 PIO_TIMER 地址的输入短语二次确认。
- 明确告知 WDM API 返回 `VOID`；成功仅表示 API 已调用，不伪造不存在的“已验证运行态”。

## 修改能力与风险准则

KSword 对修改能力采用“告知风险、用户决定”的准则：风险等级本身不构成功能封锁条件。用户确认后，操作不会再被高级模式或产品策略拒绝。

协议版本、缓冲区长度、调用方访问权限、目标存在性、对象归属、PID 创建时间、文件 ID 和修改前快照等校验仍然保留。这些校验用于确保修改落在用户实际选择的对象上，防止 PID/地址复用或竞态误伤，不属于基于风险的功能限制。

## 验证

- 共享协议和 dispatch 静态审计：149 个 IOCTL 定义均已注册；`IOCTL_KSWORD_ARK_CONTROL_IO_TIMER` 是 `METHOD_BUFFERED + FILE_WRITE_ACCESS`。
- 中英语言包审计通过。
- `KswordARKDriver` `Release|x64` 编译/链接通过。
- `Ksword5.1` `Release|x64` 编译/链接与 Qt 部署通过。
