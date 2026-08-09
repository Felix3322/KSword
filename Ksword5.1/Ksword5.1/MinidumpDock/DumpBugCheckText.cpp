// ============================================================
// DumpBugCheckText.cpp
// 作用：
// - 实现 DumpBugCheckText.h 声明的全部内核蓝屏释义能力；
// - 结构分三层：
//   1) kBugCheckCodes：停止码 → 名称 / 中文含义 / 故障归类；
//   2) kParameterSpecs：停止码 → 四个参数各自的中文名与语义角色；
//   3) 各 ParameterRole 的渲染函数：把参数数值真正翻译出来
//      （地址归属到驱动、IRQL 给级别名、访问类型给读写执行、
//        NTSTATUS 给异常名、子类型查各自的专表）。
// - 表内容全部为静态常量，无可变状态，可在解析线程内自由调用。
// ============================================================

#include "DumpBugCheckText.h"

#include "MinidumpCodeText.h"

namespace ks::minidump
{
    namespace
    {
        // BugCheckInfo：一条停止码释义。
        struct BugCheckInfo
        {
            std::uint32_t code;        // code：停止码数值。
            const char* name;          // name：官方大写常量名。
            const char* meaning;       // meaning：中文含义（UTF-8）。
            BugCheckCategory category; // category：故障归类。
        };

        // kBugCheckCodes：内核停止码表。
        // 收录范围以“真实世界里能见到”为准：启动期初始化失败类只保留代表项，
        // 驱动/内存/硬件/文件系统/电源/图形这几类尽量收全。
        constexpr BugCheckInfo kBugCheckCodes[] = {
            { 0x00000001u, "APC_INDEX_MISMATCH", "APC 状态索引不匹配：内核 APC 禁用/启用调用未配对，多见于文件系统过滤驱动。", BugCheckCategory::Driver },
            { 0x00000002u, "DEVICE_QUEUE_NOT_BUSY", "设备队列状态与预期不符（设备队列本应处于忙状态）。", BugCheckCategory::Driver },
            { 0x00000003u, "INVALID_AFFINITY_SET", "线程的处理器亲和性集合非法。", BugCheckCategory::Driver },
            { 0x00000004u, "INVALID_DATA_ACCESS_TRAP", "非法的数据访问陷阱。", BugCheckCategory::Driver },
            { 0x00000005u, "INVALID_PROCESS_ATTACH_ATTEMPT", "在已附加到其它进程时再次尝试附加进程上下文。", BugCheckCategory::Driver },
            { 0x00000006u, "INVALID_PROCESS_DETACH_ATTEMPT", "在没有附加进程上下文时执行了分离操作。", BugCheckCategory::Driver },
            { 0x00000007u, "INVALID_SOFTWARE_INTERRUPT", "非法的软件中断。", BugCheckCategory::Driver },
            { 0x00000008u, "IRQL_NOT_DISPATCH_LEVEL", "当前 IRQL 不是 DISPATCH_LEVEL，但代码要求处于该级别。", BugCheckCategory::Driver },
            { 0x00000009u, "IRQL_NOT_GREATER_OR_EQUAL", "当前 IRQL 低于操作所要求的级别。", BugCheckCategory::Driver },
            { 0x0000000Au, "IRQL_NOT_LESS_OR_EQUAL", "在过高的 IRQL 上访问了分页内存或非法地址；绝大多数情况是驱动缺陷。", BugCheckCategory::Driver },
            { 0x0000000Bu, "NO_EXCEPTION_HANDLING_SUPPORT", "系统缺少异常处理支持。", BugCheckCategory::Software },
            { 0x0000000Cu, "MAXIMUM_WAIT_OBJECTS_EXCEEDED", "等待对象数量超过内核允许的上限。", BugCheckCategory::Driver },
            { 0x0000000Du, "MUTEX_LEVEL_NUMBER_VIOLATION", "互斥体获取顺序违反了层级约定（潜在死锁）。", BugCheckCategory::Driver },
            { 0x0000000Eu, "NO_USER_MODE_CONTEXT", "缺少用户态上下文。", BugCheckCategory::Software },
            { 0x0000000Fu, "SPIN_LOCK_ALREADY_OWNED", "重复获取已经持有的自旋锁（自死锁）。", BugCheckCategory::Driver },
            { 0x00000010u, "SPIN_LOCK_NOT_OWNED", "释放了并未持有的自旋锁。", BugCheckCategory::Driver },
            { 0x00000011u, "THREAD_NOT_MUTEX_OWNER", "释放互斥体的线程并不是它的持有者。", BugCheckCategory::Driver },
            { 0x00000012u, "TRAP_CAUSE_UNKNOWN", "发生了内核无法归类的陷阱。", BugCheckCategory::Hardware },
            { 0x00000018u, "REFERENCE_BY_POINTER", "对象引用计数出错（多为多减一次引用导致对象提前销毁）。", BugCheckCategory::Driver },
            { 0x00000019u, "BAD_POOL_HEADER", "池块头部被破坏：池分配的元数据被越界写覆盖。", BugCheckCategory::Memory },
            { 0x0000001Au, "MEMORY_MANAGEMENT", "内存管理器发现内部结构不一致；可能是驱动越界破坏，也可能是物理内存故障。", BugCheckCategory::Memory },
            { 0x0000001Bu, "PFN_SHARE_COUNT", "页帧号数据库的共享计数出错。", BugCheckCategory::Memory },
            { 0x0000001Cu, "PFN_REFERENCE_COUNT", "页帧号数据库的引用计数出错。", BugCheckCategory::Memory },
            { 0x0000001Du, "NO_SPIN_LOCK_AVAILABLE", "无可用自旋锁。", BugCheckCategory::Driver },
            { 0x0000001Eu, "KMODE_EXCEPTION_NOT_HANDLED", "内核模式代码抛出了没有人处理的异常；参数 1 才是真正的异常码。", BugCheckCategory::Driver },
            { 0x00000020u, "KERNEL_APC_PENDING_DURING_EXIT", "线程退出时仍有挂起的内核 APC，通常是 APC 禁用计数没配平。", BugCheckCategory::Driver },
            { 0x00000021u, "QUOTA_UNDERFLOW", "配额记账下溢：进程释放的配额比申请的多。", BugCheckCategory::Driver },
            { 0x00000022u, "FILE_SYSTEM", "文件系统组件内部错误。", BugCheckCategory::FileSystem },
            { 0x00000023u, "FAT_FILE_SYSTEM", "FAT 文件系统驱动内部错误，常伴随磁盘损坏。", BugCheckCategory::FileSystem },
            { 0x00000024u, "NTFS_FILE_SYSTEM", "NTFS 驱动内部错误：磁盘损坏、存储驱动故障或文件系统过滤驱动缺陷。", BugCheckCategory::FileSystem },
            { 0x00000025u, "NPFS_FILE_SYSTEM", "命名管道文件系统内部错误。", BugCheckCategory::FileSystem },
            { 0x00000026u, "CDFS_FILE_SYSTEM", "CDFS（光盘文件系统）内部错误。", BugCheckCategory::FileSystem },
            { 0x00000027u, "RDR_FILE_SYSTEM", "SMB 重定向器（网络文件系统客户端）内部错误。", BugCheckCategory::FileSystem },
            { 0x00000028u, "CORRUPT_ACCESS_TOKEN", "访问令牌被破坏。", BugCheckCategory::Security },
            { 0x00000029u, "SECURITY_SYSTEM", "安全子系统内部错误。", BugCheckCategory::Security },
            { 0x0000002Au, "INCONSISTENT_IRP", "IRP 状态与预期不符（驱动重复完成或改写了已完成的 IRP）。", BugCheckCategory::Driver },
            { 0x0000002Bu, "PANIC_STACK_SWITCH", "内核栈溢出导致的栈切换失败：驱动递归过深或在栈上分配过大。", BugCheckCategory::Driver },
            { 0x0000002Eu, "DATA_BUS_ERROR", "数据总线奇偶错误：内存或总线硬件故障的强信号。", BugCheckCategory::Hardware },
            { 0x0000002Fu, "INSTRUCTION_BUS_ERROR", "指令总线错误。", BugCheckCategory::Hardware },
            { 0x00000031u, "PHASE0_INITIALIZATION_FAILED", "系统初始化第 0 阶段失败。", BugCheckCategory::Boot },
            { 0x00000032u, "PHASE1_INITIALIZATION_FAILED", "系统初始化第 1 阶段失败。", BugCheckCategory::Boot },
            { 0x00000033u, "UNEXPECTED_INITIALIZATION_CALL", "初始化例程被意外重复调用。", BugCheckCategory::Boot },
            { 0x00000034u, "CACHE_MANAGER", "缓存管理器内部错误，多见于内存不足或文件系统故障。", BugCheckCategory::FileSystem },
            { 0x00000035u, "NO_MORE_IRP_STACK_LOCATIONS", "IRP 栈位置耗尽：驱动把 IRP 往下层转发时没有正确设置栈层数。", BugCheckCategory::Driver },
            { 0x00000036u, "DEVICE_REFERENCE_COUNT_NOT_ZERO", "设备对象引用计数在删除时仍不为零。", BugCheckCategory::Driver },
            { 0x0000003Bu, "SYSTEM_SERVICE_EXCEPTION", "执行系统服务例程时发生异常；参数 1 是异常码，参数 2 是出错指令地址。", BugCheckCategory::Driver },
            { 0x0000003Du, "INTERRUPT_EXCEPTION_NOT_HANDLED", "中断服务例程中的异常未被处理。", BugCheckCategory::Driver },
            { 0x0000003Fu, "NO_MORE_SYSTEM_PTES", "系统页表项耗尽：某个驱动大量映射内存后没有释放。", BugCheckCategory::Memory },
            { 0x00000040u, "TARGET_MDL_TOO_SMALL", "目标 MDL 太小，无法容纳要映射的数据。", BugCheckCategory::Driver },
            { 0x00000041u, "MUST_SUCCEED_POOL_EMPTY", "必成功池已耗尽。", BugCheckCategory::Memory },
            { 0x00000044u, "MULTIPLE_IRP_COMPLETE_REQUESTS", "同一个 IRP 被完成了两次：典型的驱动栈协作缺陷。", BugCheckCategory::Driver },
            { 0x00000048u, "CANCEL_STATE_IN_COMPLETED_IRP", "已完成的 IRP 仍带有取消例程。", BugCheckCategory::Driver },
            { 0x00000049u, "PAGE_FAULT_WITH_INTERRUPTS_OFF", "中断关闭状态下发生了页错误。", BugCheckCategory::Driver },
            { 0x0000004Au, "IRQL_GT_ZERO_AT_SYSTEM_SERVICE", "返回用户态时 IRQL 仍高于 PASSIVE_LEVEL：驱动升了 IRQL 没有降回来。", BugCheckCategory::Driver },
            { 0x0000004Cu, "FATAL_UNHANDLED_HARD_ERROR", "致命的未处理硬错误。", BugCheckCategory::Software },
            { 0x0000004Du, "NO_PAGES_AVAILABLE", "没有可用的物理页：内存耗尽或页面文件不可用。", BugCheckCategory::Memory },
            { 0x0000004Eu, "PFN_LIST_CORRUPT", "页帧号列表损坏：多为驱动传入了错误的 MDL 或越界写。", BugCheckCategory::Memory },
            { 0x00000050u, "PAGE_FAULT_IN_NONPAGED_AREA", "访问了无效的系统内存地址；常见于驱动缺陷、内存故障或杀软过滤驱动。", BugCheckCategory::Memory },
            { 0x00000051u, "REGISTRY_ERROR", "注册表（配置管理器）错误，可能是配置单元文件损坏或 I/O 失败。", BugCheckCategory::FileSystem },
            { 0x00000053u, "NO_BOOT_DEVICE", "找不到启动设备。", BugCheckCategory::Boot },
            { 0x00000058u, "FTDISK_INTERNAL_ERROR", "容错磁盘（卷管理）内部错误。", BugCheckCategory::FileSystem },
            { 0x0000005Au, "CRITICAL_SERVICE_FAILED", "关键系统服务启动失败。", BugCheckCategory::Boot },
            { 0x0000005Cu, "HAL_INITIALIZATION_FAILED", "HAL 初始化失败。", BugCheckCategory::Boot },
            { 0x0000005Du, "UNSUPPORTED_PROCESSOR", "当前处理器不受该 Windows 版本支持。", BugCheckCategory::Hardware },
            { 0x0000006Bu, "PROCESS1_INITIALIZATION_FAILED", "会话管理器初始化失败（常因系统文件缺失或损坏）。", BugCheckCategory::Boot },
            { 0x00000074u, "BAD_SYSTEM_CONFIG_INFO", "系统配置信息损坏（注册表 SYSTEM 单元有问题）。", BugCheckCategory::Boot },
            { 0x00000076u, "PROCESS_HAS_LOCKED_PAGES", "进程退出时仍有被驱动锁定的页面未解锁。", BugCheckCategory::Driver },
            { 0x00000077u, "KERNEL_STACK_INPAGE_ERROR", "内核栈页面无法从页面文件读入：磁盘或存储驱动故障。", BugCheckCategory::Hardware },
            { 0x00000079u, "MISMATCHED_HAL", "HAL 与内核版本不匹配。", BugCheckCategory::Boot },
            { 0x0000007Au, "KERNEL_DATA_INPAGE_ERROR", "内核数据页无法读入：参数 2 的 NTSTATUS 指明了具体 I/O 错误，多为磁盘/存储驱动故障。", BugCheckCategory::Hardware },
            { 0x0000007Bu, "INACCESSIBLE_BOOT_DEVICE", "无法访问启动设备：多因存储控制器驱动缺失或磁盘模式变更。", BugCheckCategory::Boot },
            { 0x0000007Cu, "BUGCODE_NDIS_DRIVER", "网络驱动（NDIS）内部错误。", BugCheckCategory::Driver },
            { 0x0000007Eu, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "系统线程抛出了未处理异常；参数 1 是异常码，参数 2 是出错地址。", BugCheckCategory::Driver },
            { 0x0000007Fu, "UNEXPECTED_KERNEL_MODE_TRAP", "CPU 产生了内核无法处理的陷阱；参数 1 是陷阱号（0x8 双重错误常由内核栈溢出引起）。", BugCheckCategory::Driver },
            { 0x00000080u, "NMI_HARDWARE_FAILURE", "不可屏蔽中断报告的硬件故障。", BugCheckCategory::Hardware },
            { 0x0000008Eu, "KERNEL_MODE_EXCEPTION_NOT_HANDLED", "内核模式未处理异常（32 位系统上 0x1E 的对应码）。", BugCheckCategory::Driver },
            { 0x00000092u, "UP_DRIVER_ON_MP_SYSTEM", "单处理器驱动被加载到多处理器系统上。", BugCheckCategory::Driver },
            { 0x00000093u, "INVALID_KERNEL_HANDLE", "对内核句柄执行了非法操作（关闭了受保护句柄或使用了无效句柄）。", BugCheckCategory::Driver },
            { 0x00000094u, "KERNEL_STACK_LOCKED_AT_EXIT", "线程退出时内核栈仍处于锁定状态。", BugCheckCategory::Driver },
            { 0x00000095u, "PNP_INTERNAL_ERROR", "即插即用管理器内部错误。", BugCheckCategory::Driver },
            { 0x00000096u, "INVALID_WORK_QUEUE_ITEM", "工作队列项非法：多为工作项被重复排队或已释放后仍在队列中。", BugCheckCategory::Driver },
            { 0x0000009Cu, "MACHINE_CHECK_EXCEPTION", "处理器机器检查异常：CPU/内存/总线硬件故障，超频与供电不稳是常见诱因。", BugCheckCategory::Hardware },
            { 0x0000009Eu, "USER_MODE_HEALTH_MONITOR", "用户态关键进程健康检查超时（多见于群集/服务器）。", BugCheckCategory::Software },
            { 0x0000009Fu, "DRIVER_POWER_STATE_FAILURE", "驱动在电源状态切换（睡眠/唤醒/关机）时超时或状态不一致。", BugCheckCategory::Power },
            { 0x000000A0u, "INTERNAL_POWER_ERROR", "电源管理器内部错误。", BugCheckCategory::Power },
            { 0x000000A1u, "PCI_BUS_DRIVER_INTERNAL", "PCI 总线驱动内部错误。", BugCheckCategory::Driver },
            { 0x000000A3u, "ACPI_DRIVER_INTERNAL", "ACPI 驱动内部错误，多与固件（BIOS/UEFI）表有关。", BugCheckCategory::Hardware },
            { 0x000000A5u, "ACPI_BIOS_ERROR", "ACPI 固件不符合规范：优先更新 BIOS/UEFI。", BugCheckCategory::Hardware },
            { 0x000000A7u, "BAD_EXHANDLE", "内核句柄表项被破坏。", BugCheckCategory::Driver },
            { 0x000000ABu, "SESSION_HAS_VALID_POOL_ON_EXIT", "会话退出时仍有未释放的会话池（多为图形/打印驱动泄漏）。", BugCheckCategory::Driver },
            { 0x000000ACu, "HAL_MEMORY_ALLOCATION", "HAL 无法分配所需内存。", BugCheckCategory::Memory },
            { 0x000000B4u, "VIDEO_DRIVER_INIT_FAILURE", "显示驱动初始化失败，系统无法进入图形模式。", BugCheckCategory::Graphics },
            { 0x000000B8u, "ATTEMPTED_SWITCH_FROM_DPC", "在 DPC 例程里执行了非法的线程切换（等待/挂起）。", BugCheckCategory::Driver },
            { 0x000000B9u, "CHIPSET_DETECTED_ERROR", "芯片组报告了错误。", BugCheckCategory::Hardware },
            { 0x000000BEu, "ATTEMPTED_WRITE_TO_READONLY_MEMORY", "驱动向只读内存页写入；参数 1 是目标地址。", BugCheckCategory::Driver },
            { 0x000000BFu, "MUTEX_ALREADY_OWNED", "重复获取已持有的互斥体。", BugCheckCategory::Driver },
            { 0x000000C1u, "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION", "特殊池检测到越界写：驱动写出了分配范围。仅在开启驱动验证器时出现。", BugCheckCategory::Driver },
            { 0x000000C2u, "BAD_POOL_CALLER", "非法的池操作（重复释放、释放非池地址、标记不匹配等）；参数 1 是违规类型。", BugCheckCategory::Driver },
            { 0x000000C4u, "DRIVER_VERIFIER_DETECTED_VIOLATION", "驱动验证器捕获到违规；参数 1 是违规子类型，直接指明了违反了哪条规则。", BugCheckCategory::Driver },
            { 0x000000C5u, "DRIVER_CORRUPTED_EXPOOL", "驱动破坏了内核池结构，随后在高 IRQL 上访问到了坏数据。", BugCheckCategory::Driver },
            { 0x000000C6u, "DRIVER_CAUGHT_MODIFYING_FREED_POOL", "驱动在池块释放之后又改写了它（释放后使用）。", BugCheckCategory::Driver },
            { 0x000000C7u, "TIMER_OR_DPC_INVALID", "定时器或 DPC 对象位于已释放/可分页的内存中：驱动卸载时没有取消它们。", BugCheckCategory::Driver },
            { 0x000000C8u, "IRQL_UNEXPECTED_VALUE", "IRQL 出现了不该出现的值：驱动升降 IRQL 没有配平。", BugCheckCategory::Driver },
            { 0x000000C9u, "DRIVER_VERIFIER_IOMANAGER_VIOLATION", "驱动验证器的 I/O 管理器检查捕获到违规；参数 1 是子类型。", BugCheckCategory::Driver },
            { 0x000000CAu, "PNP_DETECTED_FATAL_ERROR", "即插即用管理器检测到致命错误；参数 1 是子类型。", BugCheckCategory::Driver },
            { 0x000000CBu, "DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS", "驱动在 I/O 完成后没有解锁页面（MDL 泄漏）。", BugCheckCategory::Driver },
            { 0x000000CCu, "PAGE_FAULT_IN_FREED_SPECIAL_POOL", "访问了已释放的特殊池内存（释放后使用），由驱动验证器捕获。", BugCheckCategory::Driver },
            { 0x000000CDu, "PAGE_FAULT_BEYOND_END_OF_ALLOCATION", "访问越过了分配的末尾（越界读写），由驱动验证器捕获。", BugCheckCategory::Driver },
            { 0x000000CEu, "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS", "驱动卸载时没有取消挂起的定时器/DPC/工作项，卸载后仍被回调。", BugCheckCategory::Driver },
            { 0x000000D0u, "DRIVER_CORRUPTED_MMPOOL", "驱动破坏了内存管理池。", BugCheckCategory::Driver },
            { 0x000000D1u, "DRIVER_IRQL_NOT_LESS_OR_EQUAL", "驱动在 DISPATCH_LEVEL 及以上访问了分页或无效内存；参数 4 是出错指令地址，直接指向肇事驱动。", BugCheckCategory::Driver },
            { 0x000000D3u, "DRIVER_PORTION_MUST_BE_NONPAGED", "本应常驻内存的驱动代码/数据被放在了分页段。", BugCheckCategory::Driver },
            { 0x000000D5u, "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL", "驱动访问了已释放的特殊池内存（释放后使用）。", BugCheckCategory::Driver },
            { 0x000000D6u, "DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION", "驱动越过分配末尾访问内存（缓冲区溢出）。", BugCheckCategory::Driver },
            { 0x000000D8u, "DRIVER_USED_EXCESSIVE_PTES", "驱动占用了过多系统页表项。", BugCheckCategory::Memory },
            { 0x000000DAu, "SYSTEM_PTE_MISUSE", "系统页表项被误用。", BugCheckCategory::Memory },
            { 0x000000DBu, "DRIVER_CORRUPTED_SYSPTES", "驱动破坏了系统页表项。", BugCheckCategory::Driver },
            { 0x000000DCu, "DRIVER_INVALID_STACK_ACCESS", "驱动访问了越过内核栈边界的地址。", BugCheckCategory::Driver },
            { 0x000000DEu, "POOL_CORRUPTION_IN_FILE_AREA", "驱动破坏了文件缓存所在的池区域。", BugCheckCategory::Driver },
            { 0x000000E0u, "ACPI_BIOS_FATAL_ERROR", "ACPI 固件报告了致命错误。", BugCheckCategory::Hardware },
            { 0x000000E1u, "WORKER_THREAD_RETURNED_AT_BAD_IRQL", "工作线程返回时 IRQL 不正确：工作项回调升了 IRQL 没降回来。", BugCheckCategory::Driver },
            { 0x000000E2u, "MANUALLY_INITIATED_CRASH", "人为触发的崩溃（键盘 CrashOnCtrlScroll 或调试工具），不是故障。", BugCheckCategory::UserInitiated },
            { 0x000000E3u, "RESOURCE_NOT_OWNED", "线程释放了并不属于它的 ERESOURCE。", BugCheckCategory::Driver },
            { 0x000000E4u, "WORKER_INVALID", "工作项或执行体工作线程对象非法（位于可分页或已释放内存中）。", BugCheckCategory::Driver },
            { 0x000000E6u, "DRIVER_VERIFIER_DMA_VIOLATION", "驱动验证器捕获到 DMA 违规。", BugCheckCategory::Driver },
            { 0x000000E7u, "INVALID_FLOATING_POINT_STATE", "浮点状态非法。", BugCheckCategory::Driver },
            { 0x000000E9u, "ACTIVE_EX_WORKER_THREAD_TERMINATION", "执行体工作线程被非法终止。", BugCheckCategory::Driver },
            { 0x000000EAu, "THREAD_STUCK_IN_DEVICE_DRIVER", "线程卡死在设备驱动里（多为显卡驱动无限等待硬件）。", BugCheckCategory::Graphics },
            { 0x000000EFu, "CRITICAL_PROCESS_DIED", "关键系统进程（csrss/wininit/services 等）退出，系统无法继续运行。", BugCheckCategory::Software },
            { 0x000000F4u, "CRITICAL_OBJECT_TERMINATION", "关键进程或线程被意外终止；参数 3/4 通常带有进程名与说明。", BugCheckCategory::Software },
            { 0x000000F5u, "FLTMGR_FILE_SYSTEM", "文件系统过滤管理器（FltMgr）遇到不可恢复错误。", BugCheckCategory::FileSystem },
            { 0x000000F7u, "DRIVER_OVERRAN_STACK_BUFFER", "驱动写爆了栈上的缓冲区，栈保护 cookie 校验失败。", BugCheckCategory::Driver },
            { 0x000000FAu, "HTTP_DRIVER_CORRUPTED", "HTTP 内核驱动（http.sys）内部结构损坏。", BugCheckCategory::Driver },
            { 0x000000FCu, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY", "试图执行不可执行的内存（DEP 违规）；参数 1 是目标地址。", BugCheckCategory::Driver },
            { 0x000000FEu, "BUGCODE_USB_DRIVER", "USB 驱动栈内部错误；参数 1 是子类型。", BugCheckCategory::Driver },
            { 0x00000101u, "CLOCK_WATCHDOG_TIMEOUT", "某个逻辑处理器没有响应时钟中断：多核死锁、虚拟化异常或 CPU 硬件问题。", BugCheckCategory::Watchdog },
            { 0x00000109u, "CRITICAL_STRUCTURE_CORRUPTION", "内核补丁保护（PatchGuard）发现关键结构被修改；参数 4 指明被改的区域类型。", BugCheckCategory::Security },
            { 0x0000010Du, "WDF_VIOLATION", "内核模式驱动框架（KMDF）检测到驱动违规。", BugCheckCategory::Driver },
            { 0x0000010Eu, "VIDEO_MEMORY_MANAGEMENT_INTERNAL", "显存管理器内部错误。", BugCheckCategory::Graphics },
            { 0x00000111u, "RECURSIVE_NMI", "递归的不可屏蔽中断。", BugCheckCategory::Hardware },
            { 0x00000113u, "VIDEO_DXGKRNL_FATAL_ERROR", "DirectX 图形内核（dxgkrnl）致命错误。", BugCheckCategory::Graphics },
            { 0x00000116u, "VIDEO_TDR_FAILURE", "显卡驱动超时后恢复（TDR）失败；参数 2 指向出错的显示驱动。", BugCheckCategory::Graphics },
            { 0x00000117u, "VIDEO_TDR_TIMEOUT_DETECTED", "显卡驱动在规定时间内没有响应（TDR 超时）。", BugCheckCategory::Graphics },
            { 0x00000119u, "VIDEO_SCHEDULER_INTERNAL_ERROR", "显示调度器内部错误；参数 1 是子类型。", BugCheckCategory::Graphics },
            { 0x0000011Bu, "DRIVER_RETURNED_HOLDING_CANCEL_LOCK", "驱动持有取消自旋锁就返回了。", BugCheckCategory::Driver },
            { 0x0000011Cu, "ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE", "试图写入配置管理器的只读存储。", BugCheckCategory::Driver },
            { 0x0000011Du, "EVENT_TRACING_FATAL_ERROR", "事件跟踪（ETW）子系统致命错误。", BugCheckCategory::Software },
            { 0x00000124u, "WHEA_UNCORRECTABLE_ERROR", "硬件报告了不可纠正错误（WHEA）：CPU、内存、PCIe 总线或供电异常。", BugCheckCategory::Hardware },
            { 0x00000127u, "PAGE_NOT_ZERO", "本应为全零的页面里出现了非零数据：驱动越界写或物理内存故障。", BugCheckCategory::Memory },
            { 0x0000012Bu, "FAULTY_HARDWARE_CORRUPTED_PAGE", "单比特翻转导致页面损坏：几乎可以确定是内存条硬件故障。", BugCheckCategory::Hardware },
            { 0x00000133u, "DPC_WATCHDOG_VIOLATION", "DPC 或高 IRQL 代码执行超时；参数 1 为 0 表示单个 DPC 超时，为 1 表示系统长时间处于高 IRQL。", BugCheckCategory::Watchdog },
            { 0x00000139u, "KERNEL_SECURITY_CHECK_FAILURE", "内核安全检查失败（链表损坏、栈 cookie、数组越界等）；参数 1 是具体的检查类型。", BugCheckCategory::Security },
            { 0x0000013Au, "KERNEL_MODE_HEAP_CORRUPTION", "内核堆管理器检测到堆结构损坏。", BugCheckCategory::Memory },
            { 0x0000013Cu, "INVALID_IO_BOOST_STATE", "I/O 优先级提升状态非法。", BugCheckCategory::Driver },
            { 0x00000144u, "BUGCODE_USB3_DRIVER", "USB 3.0 驱动栈内部错误；参数 1 是子类型。", BugCheckCategory::Driver },
            { 0x00000149u, "REFS_FILE_SYSTEM", "ReFS 文件系统驱动内部错误。", BugCheckCategory::FileSystem },
            { 0x0000014Cu, "FATAL_ABNORMAL_RESET_ERROR", "系统发生了致命的异常复位。", BugCheckCategory::Hardware },
            { 0x00000152u, "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE", "自动提升机制管理的锁被非法释放（释放者不是持有者）。", BugCheckCategory::Driver },
            { 0x00000154u, "UNEXPECTED_STORE_EXCEPTION", "内存压缩存储组件发生意外异常，常与存储驱动或磁盘故障相关。", BugCheckCategory::Memory },
            { 0x0000015Cu, "PDC_WATCHDOG_TIMEOUT", "电源相关的看门狗超时。", BugCheckCategory::Watchdog },
            { 0x00000162u, "KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL", "在高 IRQL 上获取了受自动提升管理的锁。", BugCheckCategory::Driver },
            { 0x000001C8u, "MANUALLY_INITIATED_POWER_BUTTON_HOLD", "长按电源键触发的手动崩溃转储，不是故障。", BugCheckCategory::UserInitiated },
            { 0x000001CAu, "SYNTHETIC_WATCHDOG_TIMEOUT", "虚拟化环境的合成看门狗超时（宿主机调度或存储卡顿也会触发）。", BugCheckCategory::Watchdog },
            { 0x000001D3u, "WFP_INVALID_OPERATION", "Windows 过滤平台（WFP）遇到非法操作，多为网络过滤驱动缺陷。", BugCheckCategory::Driver },
            { 0x000001D5u, "DRIVER_PNP_WATCHDOG", "驱动没有在规定时间内完成即插即用操作。", BugCheckCategory::Watchdog },
        };

        // ParameterRole：参数的语义角色，决定用哪个渲染函数翻译它的数值。
        enum class ParameterRole
        {
            None,               // None：没有语义（通常是保留位）。
            Raw,                // Raw：仅按原值展示。
            Address,            // Address：内存地址，交给模块索引归属。
            InstructionPointer, // InstructionPointer：出错指令地址，归因的首要依据。
            Irql,               // Irql：IRQL 级别。
            AccessType,         // AccessType：读/写/执行。
            NtStatus,           // NtStatus：嵌套的异常码。
            ProcessObject,      // ProcessObject：EPROCESS 指针。
            ThreadObject,       // ThreadObject：ETHREAD 指针。
            DeviceObject,       // DeviceObject：DEVICE_OBJECT 指针。
            DriverObject,       // DriverObject：驱动映像地址。
            ExceptionRecord,    // ExceptionRecord：EXCEPTION_RECORD 指针。
            ContextRecord,      // ContextRecord：CONTEXT 指针。
            TrapFrame,          // TrapFrame：KTRAP_FRAME 指针。
            Ticks,              // Ticks：以时钟节拍计的时长。
            SubMemoryManager,   // SubMemoryManager：0x1A 的内存管理子码。
            SubPoolCaller,      // SubPoolCaller：0xC2 的池违规类型。
            SubVerifier,        // SubVerifier：0xC4 的驱动验证器子类型。
            SubSecurityCheck,   // SubSecurityCheck：0x139 的安全检查子类型。
            SubTrap,            // SubTrap：0x7F 的陷阱号。
            SubWhea,            // SubWhea：0x124 的错误源类型。
            SubDpcWatchdog,     // SubDpcWatchdog：0x133 的超时子类型。
            SubPowerState,      // SubPowerState：0x9F 的电源失败子类型。
            SubPatchGuard,      // SubPatchGuard：0x109 的被篡改区域类型。
            SubPnp,             // SubPnp：0xCA 的即插即用子码。
        };

        // ParameterSpec：某个参数的中文名与语义角色。
        struct ParameterSpec
        {
            const char* label;   // label：中文参数名，为空表示未知语义。
            ParameterRole role;  // role：语义角色。
        };

        // BugCheckParameterSpec：一个停止码的四个参数说明。
        struct BugCheckParameterSpec
        {
            std::uint32_t code;      // code：停止码。
            ParameterSpec params[4]; // params：参数 1..4 的说明。
        };

        // kParameterSpecs：参数语义表。
        // 只收录“参数确实有稳定语义”的停止码——参数含义随子类型变化的
        // （如 0xC2/0xC4 的参数 2..4），这里只标注参数 1，其余留空由渲染层按原值展示，
        // 硬编一个可能对不上的说明比不写更有害。
        constexpr BugCheckParameterSpec kParameterSpecs[] = {
            { 0x0000000Au, { { "被访问的内存地址", ParameterRole::Address },
                             { "访问发生时的 IRQL", ParameterRole::Irql },
                             { "访问类型", ParameterRole::AccessType },
                             { "发起该访问的指令地址", ParameterRole::InstructionPointer } } },
            { 0x000000D1u, { { "被访问的内存地址", ParameterRole::Address },
                             { "访问发生时的 IRQL", ParameterRole::Irql },
                             { "访问类型", ParameterRole::AccessType },
                             { "发起该访问的指令地址", ParameterRole::InstructionPointer } } },
            { 0x000000C5u, { { "被访问的内存地址", ParameterRole::Address },
                             { "访问发生时的 IRQL", ParameterRole::Irql },
                             { "访问类型", ParameterRole::AccessType },
                             { "发起该访问的指令地址", ParameterRole::InstructionPointer } } },
            { 0x00000050u, { { "被访问的内存地址", ParameterRole::Address },
                             { "访问类型", ParameterRole::AccessType },
                             { "发起该访问的指令地址", ParameterRole::InstructionPointer },
                             { "保留（页错误内部类型）", ParameterRole::Raw } } },
            { 0x000000CEu, { { "被访问的内存地址", ParameterRole::Address },
                             { "访问类型", ParameterRole::AccessType },
                             { "发起该访问的指令地址", ParameterRole::InstructionPointer },
                             { "保留", ParameterRole::None } } },
            { 0x000000D5u, { { "被访问的内存地址", ParameterRole::Address },
                             { "访问类型", ParameterRole::AccessType },
                             { "发起该访问的指令地址", ParameterRole::InstructionPointer },
                             { "保留", ParameterRole::None } } },
            { 0x000000D6u, { { "被访问的内存地址", ParameterRole::Address },
                             { "访问类型", ParameterRole::AccessType },
                             { "发起该访问的指令地址", ParameterRole::InstructionPointer },
                             { "保留", ParameterRole::None } } },
            { 0x000000CCu, { { "被访问的内存地址", ParameterRole::Address },
                             { "访问类型", ParameterRole::AccessType },
                             { "发起该访问的指令地址", ParameterRole::InstructionPointer },
                             { "保留", ParameterRole::None } } },
            { 0x000000CDu, { { "被访问的内存地址", ParameterRole::Address },
                             { "访问类型", ParameterRole::AccessType },
                             { "发起该访问的指令地址", ParameterRole::InstructionPointer },
                             { "保留", ParameterRole::None } } },
            { 0x0000001Eu, { { "未处理的异常码", ParameterRole::NtStatus },
                             { "异常发生的指令地址", ParameterRole::InstructionPointer },
                             { "异常的参数 0", ParameterRole::Raw },
                             { "异常的参数 1", ParameterRole::Raw } } },
            { 0x0000008Eu, { { "未处理的异常码", ParameterRole::NtStatus },
                             { "异常发生的指令地址", ParameterRole::InstructionPointer },
                             { "陷阱帧地址", ParameterRole::TrapFrame },
                             { "保留", ParameterRole::None } } },
            { 0x0000007Eu, { { "未处理的异常码", ParameterRole::NtStatus },
                             { "异常发生的指令地址", ParameterRole::InstructionPointer },
                             { "异常记录（EXCEPTION_RECORD）地址", ParameterRole::ExceptionRecord },
                             { "上下文记录（CONTEXT）地址", ParameterRole::ContextRecord } } },
            { 0x0000003Bu, { { "引发问题的异常码", ParameterRole::NtStatus },
                             { "引发异常的指令地址", ParameterRole::InstructionPointer },
                             { "上下文记录（CONTEXT）地址", ParameterRole::ContextRecord },
                             { "保留", ParameterRole::None } } },
            { 0x0000007Fu, { { "陷阱号", ParameterRole::SubTrap },
                             { "与陷阱类型相关", ParameterRole::Raw },
                             { "与陷阱类型相关", ParameterRole::Raw },
                             { "与陷阱类型相关", ParameterRole::Raw } } },
            { 0x0000001Au, { { "内存管理子码", ParameterRole::SubMemoryManager },
                             { "与子码相关", ParameterRole::Raw },
                             { "与子码相关", ParameterRole::Raw },
                             { "与子码相关", ParameterRole::Raw } } },
            { 0x000000C2u, { { "池违规类型", ParameterRole::SubPoolCaller },
                             { "与违规类型相关", ParameterRole::Raw },
                             { "与违规类型相关", ParameterRole::Raw },
                             { "与违规类型相关", ParameterRole::Raw } } },
            { 0x000000C4u, { { "验证器违规子类型", ParameterRole::SubVerifier },
                             { "与子类型相关", ParameterRole::Raw },
                             { "与子类型相关", ParameterRole::Raw },
                             { "与子类型相关", ParameterRole::Raw } } },
            { 0x000000C9u, { { "I/O 验证器违规子类型", ParameterRole::Raw },
                             { "与子类型相关", ParameterRole::Raw },
                             { "与子类型相关", ParameterRole::Raw },
                             { "与子类型相关", ParameterRole::Raw } } },
            { 0x000000CAu, { { "即插即用子码", ParameterRole::SubPnp },
                             { "与子码相关", ParameterRole::Raw },
                             { "与子码相关", ParameterRole::Raw },
                             { "与子码相关", ParameterRole::Raw } } },
            { 0x00000139u, { { "安全检查失败类型", ParameterRole::SubSecurityCheck },
                             { "陷阱帧（KTRAP_FRAME）地址", ParameterRole::TrapFrame },
                             { "异常记录（EXCEPTION_RECORD）地址", ParameterRole::ExceptionRecord },
                             { "保留", ParameterRole::None } } },
            { 0x00000124u, { { "错误源类型", ParameterRole::SubWhea },
                             { "WHEA_ERROR_RECORD 结构地址", ParameterRole::Address },
                             { "错误状态高 32 位（MCi_STATUS）", ParameterRole::Raw },
                             { "错误状态低 32 位（MCi_STATUS）", ParameterRole::Raw } } },
            { 0x00000133u, { { "超时类型", ParameterRole::SubDpcWatchdog },
                             { "已消耗的时钟节拍数", ParameterRole::Ticks },
                             { "允许的时钟节拍上限", ParameterRole::Ticks },
                             { "看门狗内部数据块地址", ParameterRole::Address } } },
            { 0x0000009Fu, { { "电源状态失败子类型", ParameterRole::SubPowerState },
                             { "与子类型相关（多为物理设备对象）", ParameterRole::DeviceObject },
                             { "与子类型相关", ParameterRole::Raw },
                             { "阻塞的 IRP 或超时的设备栈", ParameterRole::Address } } },
            { 0x00000109u, { { "保留（内部校验值）", ParameterRole::Raw },
                             { "保留（内部校验值）", ParameterRole::Raw },
                             { "保留（内部校验值）", ParameterRole::Raw },
                             { "被篡改的区域类型", ParameterRole::SubPatchGuard } } },
            { 0x000000BEu, { { "试图写入的虚拟地址", ParameterRole::Address },
                             { "该地址的页表项内容", ParameterRole::Raw },
                             { "保留", ParameterRole::None },
                             { "保留", ParameterRole::None } } },
            { 0x000000FCu, { { "试图执行的虚拟地址", ParameterRole::Address },
                             { "该地址的页表项内容", ParameterRole::Raw },
                             { "保留", ParameterRole::None },
                             { "保留", ParameterRole::None } } },
            { 0x000000B8u, { { "原线程对象", ParameterRole::ThreadObject },
                             { "试图切换到的新线程对象", ParameterRole::ThreadObject },
                             { "原线程的栈地址", ParameterRole::Address },
                             { "保留", ParameterRole::None } } },
            { 0x000000E3u, { { "资源（ERESOURCE）地址", ParameterRole::Address },
                             { "执行释放的线程对象", ParameterRole::ThreadObject },
                             { "资源所有者表地址", ParameterRole::Address },
                             { "保留", ParameterRole::None } } },
            { 0x000000EFu, { { "退出的关键进程对象（EPROCESS）", ParameterRole::ProcessObject },
                             { "保留", ParameterRole::None },
                             { "保留", ParameterRole::None },
                             { "保留", ParameterRole::None } } },
            { 0x000000F4u, { { "对象类型（0x3 进程 / 0x6 线程）", ParameterRole::Raw },
                             { "被终止的对象地址", ParameterRole::Address },
                             { "映像文件名字符串地址", ParameterRole::Address },
                             { "说明字符串地址", ParameterRole::Address } } },
            { 0x000000F7u, { { "实际的栈保护 cookie", ParameterRole::Raw },
                             { "期望的栈保护 cookie", ParameterRole::Raw },
                             { "期望 cookie 的按位取反", ParameterRole::Raw },
                             { "保留", ParameterRole::None } } },
            { 0x0000007Au, { { "锁类型或页表项地址", ParameterRole::Raw },
                             { "I/O 操作返回的 NTSTATUS", ParameterRole::NtStatus },
                             { "当前进程或页表项内容", ParameterRole::Raw },
                             { "无法读入的虚拟地址", ParameterRole::Address } } },
            { 0x00000116u, { { "TDR 恢复上下文地址", ParameterRole::Address },
                             { "出错的显示驱动模块地址", ParameterRole::DriverObject },
                             { "错误码（NTSTATUS 或驱动私有）", ParameterRole::Raw },
                             { "内部上下文数据", ParameterRole::Raw } } },
            { 0x00000117u, { { "TDR 恢复上下文地址", ParameterRole::Address },
                             { "无响应的显示驱动模块地址", ParameterRole::DriverObject },
                             { "保留", ParameterRole::None },
                             { "保留", ParameterRole::None } } },
            { 0x00000101u, { { "时钟中断超时的节拍数", ParameterRole::Ticks },
                             { "保留", ParameterRole::None },
                             { "无响应处理器的 KPRCB 地址", ParameterRole::Address },
                             { "保留", ParameterRole::None } } },
            { 0x0000013Au, { { "堆错误子类型", ParameterRole::Raw },
                             { "堆地址", ParameterRole::Address },
                             { "被破坏的地址", ParameterRole::Address },
                             { "保留", ParameterRole::None } } },
            { 0x000000C1u, { { "被访问的地址", ParameterRole::Address },
                             { "实际读到的填充值", ParameterRole::Raw },
                             { "期望的填充值", ParameterRole::Raw },
                             { "损坏类型", ParameterRole::Raw } } },
            { 0x000000C6u, { { "被改写的已释放池地址", ParameterRole::Address },
                             { "实际读到的值", ParameterRole::Raw },
                             { "期望的填充值", ParameterRole::Raw },
                             { "保留", ParameterRole::None } } },
            { 0x000000C7u, { { "定时器或 DPC 对象地址", ParameterRole::Address },
                             { "对象类型", ParameterRole::Raw },
                             { "对象所在的驱动映像基址", ParameterRole::DriverObject },
                             { "调用者地址", ParameterRole::InstructionPointer } } },
            { 0x000000E1u, { { "工作线程回调函数地址", ParameterRole::InstructionPointer },
                             { "返回时的 IRQL", ParameterRole::Irql },
                             { "工作项地址", ParameterRole::Address },
                             { "保留", ParameterRole::None } } },
            { 0x000000E4u, { { "子类型（0 工作项在可分页内存 / 1 工作项已排队）", ParameterRole::Raw },
                             { "工作项地址", ParameterRole::Address },
                             { "工作项回调函数地址", ParameterRole::InstructionPointer },
                             { "保留", ParameterRole::None } } },
            { 0x000000E2u, { { "保留", ParameterRole::None },
                             { "保留", ParameterRole::None },
                             { "保留", ParameterRole::None },
                             { "保留", ParameterRole::None } } },
        };

        // SubcodePair：一条“子码 → 中文含义”映射。
        struct SubcodePair
        {
            std::uint64_t code; // code：子码数值。
            const char* text;   // text：中文含义（UTF-8）。
        };

        // kMemoryManagementSubcodes：0x1A MEMORY_MANAGEMENT 的参数 1 子码。
        // 这张表决定了 0x1A 的排查方向：同一个停止码下，硬件位翻转、
        // 驱动破坏页表、系统资源耗尽是完全不同的三类问题。
        constexpr SubcodePair kMemoryManagementSubcodes[] = {
            { 0x00000031ull,
              "映像重定位修正表或代码流已损坏。微软明确指出这多半是硬件错误，优先跑内存诊断、检查超频与内存时序。" },
            { 0x0000003Full,
              "换页读入操作 CRC 校验失败。参数 2 为页面文件偏移，参数 3 为实际 CRC，参数 4 为期望 CRC。指向页面文件所在磁盘、存储控制器或内存故障，不是驱动逻辑问题。" },
            { 0x00000403ull,
              "页表与 PFN 数据库不同步。若参数 3 与参数 4 只相差一个二进制位，基本可判定为内存位翻转类硬件故障。" },
            { 0x00000404ull,
              "删除系统页面时发现 PFN 与当前 PTE 指针不一致。参数 2 为期望 PTE，参数 3 为实际 PTE 内容，参数 4 为 PFN 记录的 PTE。多为驱动越界写破坏了页表结构。" },
            { 0x00000411ull,
              "一个 PTE 已被破坏，参数 2 是该 PTE 的地址。常见于驱动野指针写入、DMA 写到错误的物理页。" },
            { 0x00000777ull,
              "驱动解锁了一个当前并未锁定的系统缓存地址（从未映射或被解锁两次）。仅出现在旧版 Windows。" },
            { 0x00000778ull,
              "系统用掉了最后一个系统缓存视图地址而未予保留。仅出现在旧版 Windows。" },
            { 0x00000780ull,
              "映射该系统缓存视图的 PTE 已损坏（文档按 0x780-0x781 区间给出）。仅出现在旧版 Windows。" },
            { 0x00000781ull,
              "同 0x780：映射系统缓存视图的 PTE 已损坏。仅出现在旧版 Windows。" },
            { 0x00001000ull,
              "MmGetSystemAddressForMdl* 的调用方想把全缓存物理页映射成非缓存，会造成 TLB 属性冲突而被拒绝；因 MDL 指定了失败即蓝屏故触发。仅出现在旧版 Windows。" },
            { 0x00001010ull,
              "驱动解锁了一个当前未加锁的可分页节（从未加锁或被解锁两次）。典型是 MmLockPagableCodeSection / MmUnlockPagableImageSection 配对失衡。" },
            { 0x00001233ull,
              "驱动试图映射一个未加锁的物理页——该页内容与属性随时可能变化，属于调用方代码缺陷。参数 2 为该物理页的 PFN。" },
            { 0x00001234ull,
              "驱动试图锁定一个并不存在的可分页节。" },
            { 0x00001235ull,
              "驱动试图对一个映射非法的 MDL 修改保护属性。" },
            { 0x00001236ull,
              "驱动传入的 MDL 里含有未加锁（或无效）的物理页。参数 2 为 MDL 指针，参数 3 指向非法 PFN，参数 4 为该 PFN 值。典型是 MDL 被提前 MmUnlockPages、或被释放后复用。" },
            { 0x00001240ull,
              "驱动为一段不在内存中（非驻留）的虚拟地址构建 MDL，这是非法的。参数 2 为 MDL，参数 3 为 PTE 指针。" },
            { 0x00001241ull,
              "构建 MDL 期间该虚拟地址被异步解除映射。参数 2 为 MDL，参数 3 为 PTE 指针。仅出现在旧版 Windows。" },
            { 0x00003300ull,
              "写操作时目标虚拟地址被错误地标记为写时复制。参数 2 为出错地址，参数 3 为 PTE 内容，参数 4 指明虚拟地址空间类型。" },
            { 0x00003451ull,
              "已换出的内核线程栈的 PTE 被破坏，通常是别的组件越界写到了这块换出栈结构。" },
            { 0x00003453ull,
              "进程退出时因残留引用而无法删除全部页表页，通常说明该进程的页表结构已损坏。" },
            { 0x00003470ull,
              "空闲链表上缓存的内核栈被写坏。参数 2 为虚拟地址，参数 3 为该虚拟地址的 cookie。当前调用栈可能只是受害者，建议开 Driver Verifier 特殊池抓真凶。" },
            { 0x00004477ull,
              "驱动向系统进程用户空间中一个未分配的地址写入。参数 2 为写入地址。典型是驱动在错误的进程上下文里用了用户态指针。" },
            { 0x00005003ull,
              "工作集空闲链表损坏，微软判定多为硬件错误。仅出现在旧版 Windows。" },
            { 0x00005100ull,
              "分配位图损坏，内存管理器即将覆盖一段已在使用中的虚拟地址。" },
            { 0x00005200ull,
              "空闲池 SLIST 上的某个页面被写坏。典型是驱动释放后继续写（write-after-free），或上一个页面越界。参数 2 为空闲池块地址，参数 3 为实际值，参数 4 为期望值。仅出现在旧版 Windows。" },
            { 0x00005305ull,
              "释放池时给出了非法地址。参数 2 为被判定的虚拟地址，参数 3 为区域大小。" },
            { 0x00006001ull,
              "内存压缩存储（store）的私有内存区损坏而不可访问。参数 2 为返回状态，参数 3 为该私有区内的虚拟地址，参数 4 为 MDL。" },
            { 0x00008884ull,
              "待机链表上两个本应优先级相同的页面优先级不一致（文档按 0x8884-0x8885 区间给出，归在旧版参数表中）。差异值记录在参数 4。" },
            { 0x00008885ull,
              "同 0x8884：待机链表页面优先级不一致，差异值在参数 4。" },
            { 0x00008886ull,
              "待机链表上两个本应优先级相同的页面优先级不一致（Windows 7 及以后；文档按 0x8886-0x8887 区间给出）。差异值记录在参数 4。" },
            { 0x00008887ull,
              "同 0x8886：待机链表页面优先级不一致，差异值在参数 4。" },
            { 0x00008888ull,
              "内存管理器内部结构损坏（文档按 0x8888-0x8889 区间给出）。属于兜底子码，需用 Driver Verifier 特殊池定位越界写。" },
            { 0x00008889ull,
              "同 0x8888：内存管理器内部结构损坏。" },
            { 0x0000888Aull,
              "内存管理器内部结构损坏，且很可能就是 PTE 或 PFN 本身被写坏。" },
            { 0x00009696ull,
              "某个 PFN（参数 2）的链接已损坏、脱离了其顶层进程，说明 PFN 结构被越界写破坏。" },
            { 0x00015000ull,
              "解除内存保护时找不到目标范围：要么地址传错，要么在错误的进程上下文里调用。参数 2 为被判定的虚拟地址。" },
            { 0x00015001ull,
              "解除先前 secure 的内存时出错，常见于在错误的进程上下文中调用 MmUnsecureVirtualMemory。" },
            { 0x00041201ull,
              "查询虚拟地址时发现 PFN 与当前 PTE 指针不一致。参数 2 为对应 PTE，参数 3 为 PTE 内容，参数 4 为 VAD。仅出现在旧版 Windows。" },
            { 0x00041202ull,
              "判定非零 PTE 的页保护属性时发现该 PTE 已损坏。参数 2 为 PTE 指针，参数 3 为 PTE 内容，参数 4 为 VAD。" },
            { 0x00041283ull,
              "PTE 中编码的工作集索引已损坏。仅出现在旧版 Windows。" },
            { 0x00041284ull,
              "PTE 或工作集链表已损坏。仅出现在旧版 Windows；排查按「驱动越界写」与「内存硬件」两条线并行。" },
            { 0x00041286ull,
              "驱动试图释放一个非法的池地址。" },
            { 0x00041287ull,
              "持有工作集同步锁期间发生了非法缺页。参数 2 为被引用的虚拟地址。典型原因是在持锁或高 IRQL 状态下访问了分页内存。" },
            { 0x00041785ull,
              "工作集链表已损坏。" },
            { 0x00041790ull,
              "一个页表页被破坏。64 位下参数 2 为该页表页 PFN 的地址；32 位下参数 2 指向已用 PTE 计数、参数 3 为该计数值。" },
            { 0x00041792ull,
              "检测到损坏的 PTE。参数 2 为该 PTE 的地址，参数 3 与参数 4 分别为 PTE 的低位与高位。常见于驱动野指针写或内存硬件故障。" },
            { 0x00041793ull,
              "页表页损坏：参数 2 为最后处理的 PTE，参数 3 为实际非零 PTE 数，参数 4 为期望的非零 PTE 数。Windows 10 1803 之后已废弃。" },
            { 0x00061940ull,
              "一个 PDE 被意外置为无效。仅出现在旧版 Windows。" },
            { 0x00061941ull,
              "分页层次结构（页表树）已损坏。参数 2 指向引发缺页的虚拟地址。多为越界写或硬件故障破坏了页表。" },
            { 0x00061946ull,
              "正在创建的 MDL 有缺陷，几乎必然是调用 MmProbeAndLockPages 的驱动的错——典型是处理分页读时却按「写」方向建 MDL。仅出现在旧版 Windows。" },
            { 0x00061948ull,
              "递减 I/O 空间区域引用计数时找不到该区域的记账节点，通常是该范围从未锁定或已被解锁。参数 2 为基 I/O 帧，参数 3 为页数，参数 4 为找不到节点的那个 I/O 帧。" },
            { 0x00061949ull,
              "IoPageFrameNode 为空。参数 2 为 PageFrameIndex。" },
            { 0x0006194Aull,
              "解除 I/O 空间物理页映射时，对一个当前未被引用的项做了解引用。参数 2、参数 3 描述调用方要解除映射的范围，参数 4 是本应被引用却没有的那个 I/O 物理页。" },
            { 0x03030303ull,
              "引导加载器损坏（仅 Intel Itanium 平台，历史遗留值）。仅出现在旧版 Windows。" },
            { 0x03030308ull,
              "要移除或截断的物理内存范围仍被加载器占用，无法安全移除。参数 2 为 HighestPhysicalPage。" },
        };

        // kPoolCallerViolations：0xC2 BAD_POOL_CALLER 的参数 1 池违规类型。
        // 违规类型直接说明是重复释放、标记不符还是释放了非池地址，方向完全不同。
        constexpr SubcodePair kPoolCallerViolations[] = {
            { 0x00000000ull,
              "线程请求了 0 字节的池分配。参数 3 为池类型（0=非分页，1=分页），参数 4 为池 tag。多为长度计算下溢（如 size - header 变成 0）。" },
            { 0x00000001ull,
              "池头已被破坏。参数 2 指向池头，参数 3 为池头前半部分内容。典型是相邻块被越界写（buffer overrun）。" },
            { 0x00000002ull,
              "同 0x01：池头已被破坏。参数 2 指向池头，参数 3 为池头内容。" },
            { 0x00000004ull,
              "同 0x01：池头已被破坏。参数 2 指向池头，参数 3 为池头内容。" },
            { 0x00000006ull,
              "线程释放了一块已经被释放的池内存。参数 3 指向池头，参数 4 为池头内容。典型是引用计数管理错误或错误路径重复清理。" },
            { 0x00000007ull,
              "线程释放了一块已经被释放的池内存。参数 3 为池头内容，参数 4 为被释放块的地址。" },
            { 0x00000008ull,
              "在非法 IRQL 上分配池。参数 2 为当前 IRQL，参数 3 为池类型，参数 4 为分配字节数。分页池要求 IRQL <= APC_LEVEL，非分页池要求 <= DISPATCH_LEVEL。" },
            { 0x00000009ull,
              "在非法 IRQL 上释放池。参数 2 为当前 IRQL，参数 3 为池类型，参数 4 为池地址。常见于在 DPC 里释放分页池。" },
            { 0x0000000Aull,
              "用错误的 tag 释放池内存——这块内存可能根本属于别的组件。参数 2 为池地址，参数 3 为分配时的 tag，参数 4 为释放时使用的 tag。" },
            { 0x0000000Bull,
              "在一块已损坏的池分配上释放配额。参数 2 为池地址，参数 3 为分配 tag，参数 4 为错误的配额进程指针。" },
            { 0x0000000Cull,
              "同 0x0B：在已损坏的池分配上释放配额。" },
            { 0x0000000Dull,
              "同 0x0B：在已损坏的池分配上释放配额。" },
            { 0x00000040ull,
              "试图把一个用户态地址当成内核池释放。参数 2 为起始地址，参数 3 为系统地址空间起点。典型是把用户缓冲区指针误传给了 ExFreePool。" },
            { 0x00000041ull,
              "释放了一个未分配的非分页池地址。参数 2 为起始地址，参数 3 为物理页帧号，参数 4 为系统最高物理页帧号。" },
            { 0x00000042ull,
              "释放的虚拟地址从来不属于任何池。参数 2 为被释放地址。多为指针被覆盖，或对基址做了偏移运算后才释放。" },
            { 0x00000043ull,
              "同 0x42：释放的虚拟地址从来不属于任何池。" },
            { 0x00000044ull,
              "释放了一个未分配的非分页池地址。参数 2 为起始地址。" },
            { 0x00000046ull,
              "释放了一个无效的池地址。参数 2 为起始地址。" },
            { 0x00000047ull,
              "释放了一个未分配的非分页池地址。参数 2 为起始地址，参数 3 为物理页帧号，参数 4 为系统最高物理页帧号。" },
            { 0x00000048ull,
              "释放了一个未分配的分页池地址。参数 2 为起始地址。" },
            { 0x00000050ull,
              "释放了一个未分配的分页池地址。参数 2 为起始地址，参数 3 为距分页池起点的页偏移，参数 4 为分页池大小（字节）。" },
            { 0x00000060ull,
              "释放了一个无效的连续内存地址——MmFreeContiguousMemory 的调用方传了坏指针。参数 2 为起始地址。" },
            { 0x00000099ull,
              "用无效地址释放池；该码也可能表示池头本身已损坏。参数 2 为被释放的地址。" },
            { 0x0000009Aull,
              "分配请求被标记为 MUST_SUCCEED，而该池类型早已不再受支持。参数 2 为池类型，参数 3 为请求字节数，参数 4 为池 tag。" },
            { 0x0000009Bull,
              "以 tag = 0 分配池：无法追踪，且可能破坏现有 tag 表。参数 2 为池类型，参数 3 为请求字节数，参数 4 为调用方地址。" },
            { 0x0000009Cull,
              "以 tag 为 “BIG” 分配池，与内核内部保留 tag 冲突。参数 2 为池类型，参数 3 为请求字节数，参数 4 为调用方地址。" },
            { 0x0000009Dull,
              "池 tag 中不含任何字母或数字，导致池问题无法追踪。参数 2 为该错误 tag，参数 3 为池类型，参数 4 为调用方地址。" },
            { 0x00041286ull,
              "在一次分页池分配的中间位置调用了释放。参数 4 为距分页池起点的页偏移。典型是指针做过偏移运算后才传给 ExFreePool。" },
        };

        // kSecurityCheckSubtypes：0x139 KERNEL_SECURITY_CHECK_FAILURE 的参数 1 类型。
        // 这是 0x139 排查的核心：子类型直接告诉你是哪一类内存破坏。
        constexpr SubcodePair kSecurityCheckSubtypes[] = {
            { 0x00000000ull,
              "栈缓冲区溢出（旧式 /GS 检查）。局部数组越界写覆盖了返回地址所在区域。" },
            { 0x00000001ull,
              "VTGuard 检测到试图使用非法的虚函数表：C++ 对象被写坏后，虚方法调用用了损坏的 this 指针。典型是 use-after-free 或对象越界写。" },
            { 0x00000002ull,
              "栈 cookie 检查检测到栈缓冲区溢出（/GS 违规）。函数内的局部缓冲区被写越界。" },
            { 0x00000003ull,
              "LIST_ENTRY 双向链表损坏（例如同一项被 RemoveEntryList 两次）。常见根因：驱动破坏了 KEVENT/KTIMER 等内核同步对象、释放了仍挂在链表上的结构、或多线程无锁操作链表。用 dl/dlb 正反向遍历找断点。" },
            { 0x00000004ull,
              "保留值，官方未定义具体含义。" },
            { 0x00000005ull,
              "向一个把非法参数视为致命错误的函数传入了非法参数。" },
            { 0x00000006ull,
              "加载器没有正确初始化栈安全 cookie。典型场景：驱动只按 Windows 8 目标构建，却被加载到更早版本的 Windows 上。" },
            { 0x00000007ull,
              "请求了致命程序退出（如 __fastfail 主动终止）。" },
            { 0x00000008ull,
              "编译器插入的数组边界检查发现了非法的数组索引操作。" },
            { 0x00000009ull,
              "调用 RtlQueryRegistryValues 时指定了 RTL_QUERY_REGISTRY_DIRECT 却没有 RTL_QUERY_REGISTRY_TYPECHECK，且目标值不在受信任的系统 hive 中——这是可被注册表数据篡改利用的经典缺陷。" },
            { 0x0000000Aull,
              "间接调用防护（CFG/kCFG）检测到非法的控制转移。函数指针被覆盖或指向了非法目标。" },
            { 0x0000000Bull,
              "写防护检查检测到非法的内存写入。" },
            { 0x0000000Cull,
              "试图切换到非法的纤程上下文。" },
            { 0x0000000Dull,
              "试图设置非法的寄存器上下文。" },
            { 0x0000000Eull,
              "对象的引用计数非法（如已归零后又被解引用）。" },
            { 0x00000012ull,
              "试图切换到非法的 jmp_buf 上下文。" },
            { 0x00000013ull,
              "对只读数据做了不安全的修改。" },
            { 0x00000014ull,
              "加密自检失败。" },
            { 0x00000015ull,
              "检测到非法的异常链（SEH 链被破坏）。" },
            { 0x00000016ull,
              "加密库发生错误。" },
            { 0x00000017ull,
              "在 DllMain 内部发起了非法调用。" },
            { 0x00000018ull,
              "检测到非法的映像基址。" },
            { 0x00000019ull,
              "保护延迟加载导入项时遇到不可恢复的失败。" },
            { 0x0000001Aull,
              "调用了不安全的扩展。" },
            { 0x0000001Bull,
              "调用了已废弃的服务。" },
            { 0x0000001Cull,
              "检测到越界的缓冲区访问。" },
            { 0x0000001Dull,
              "RTL_BALANCED_NODE 红黑树节点损坏，与 LIST_ENTRY 损坏同类，多为 use-after-free 或并发无锁修改。" },
            { 0x00000025ull,
              "调用了超出范围的 switch 跳转表项。" },
            { 0x00000026ull,
              "longjmp 跳向了非法目标。" },
            { 0x00000027ull,
              "导出抑制的调用目标无法被转为合法调用目标（CFG 导出抑制）。" },
        };

        // kKernelTraps：0x7F UNEXPECTED_KERNEL_MODE_TRAP 的参数 1 陷阱号。
        // 取值即处理器异常向量号，0x8（双重错误）绝大多数是内核栈溢出。
        constexpr SubcodePair kKernelTraps[] = {
            { 0x00000000ull,
              "执行 DIV/IDIV 时除数为零。内存损坏、其它硬件问题或软件缺陷都可能导致。" },
            { 0x00000001ull,
              "系统调试器调用/单步调试异常。" },
            { 0x00000002ull,
              "【非微软 0x7F 表，取自 Intel SDM 架构向量 2】不可屏蔽中断。Windows 上 NMI 通常以停止码 0x80 NMI_HARDWARE_FAILURE 报出，出现在 0x7F 里属异常路径。" },
            { 0x00000003ull,
              "调试器断点（INT 3）。常见于代码里残留的 DbgBreakPoint，或未连接调试器时执行了断点指令。" },
            { 0x00000004ull,
              "溢出标志 OF 置位时执行了 INTO，处理器调用了溢出中断处理程序。" },
            { 0x00000005ull,
              "执行 BOUND 指令时发现操作数超出指定范围（BOUND 用于确保带符号数组索引落在范围内）。" },
            { 0x00000006ull,
              "处理器试图执行非法指令。通常是指令指针被破坏后指向了错误位置；最常见的根因是内存硬件损坏。" },
            { 0x00000007ull,
              "执行了协处理器指令但协处理器不可用（设备不可用/FPU 上下文切换异常）。注：官方页面此处印作 NXP_NOT_AVAILABLE，系笔误。" },
            { 0x00000008ull,
              "处理前一个异常的过程中又发生了异常。两大常见原因：一是内核栈溢出（撞到保护页后连陷阱帧都压不进去，多见于多个过滤驱动叠在同一栈上或递归调用）；二是硬件故障。用 !thread 看栈边界，再用 kb 100 打完整栈。" },
            { 0x0000000Aull,
              "任务状态段（TSS）损坏。" },
            { 0x0000000Bull,
              "访问了一个不存在的内存段。" },
            { 0x0000000Cull,
              "访问超出了栈段界限（栈段错误）。" },
            { 0x0000000Dull,
              "一般保护错误：未被其它异常覆盖的保护性违规，例如写只读段、加载非法段选择子、访问非规范地址。" },
            { 0x0000000Eull,
              "【非微软 0x7F 表，取自 Intel SDM 架构向量 14】页错误。实践中内核页错误通常走 0xA/0x50/0xD1 等专用停止码，出现在 0x7F 里说明陷阱在异常派发路径上就失败了。" },
            { 0x0000000Full,
              "保留的陷阱异常。" },
            { 0x00000010ull,
              "x87 浮点协处理器异常。" },
            { 0x00000011ull,
              "对齐检查异常：在启用对齐检查时访问了未对齐的数据。" },
            { 0x00000012ull,
              "【非微软 0x7F 表，取自 Intel SDM 架构向量 18】机器检查异常，CPU 报告的硬件级错误。现代 Windows 通常以 0x124 WHEA_UNCORRECTABLE_ERROR 报出。" },
            { 0x00000013ull,
              "【非微软 0x7F 表，取自 Intel SDM 架构向量 19】SIMD 浮点异常（SSE/AVX）。" },
        };

        // kWheaErrorSources：0x124 WHEA_UNCORRECTABLE_ERROR 的参数 1 错误源类型。
        // 枚举名与 ntddk.h 的 WHEA_ERROR_SOURCE_TYPE 对应。
        constexpr SubcodePair kWheaErrorSources[] = {
            { 0x00000000ull,
              "机器检查异常（MCE）。参数 3/4 为出错 MCA bank 的 MCi_STATUS MSR 高 32 位与低 32 位。绝大多数 0x124 属于此类：CPU/内存/主板供电异常，超频与散热是常见诱因。" },
            { 0x00000001ull,
              "已纠正的机器检查异常（CMC）。" },
            { 0x00000002ull,
              "已纠正的平台错误（CPE）。" },
            { 0x00000003ull,
              "不可屏蔽中断（NMI）错误。" },
            { 0x00000004ull,
              "不可纠正的 PCI Express 错误。常见于显卡/NVMe/扩展卡链路不稳、插槽接触不良或 PCIe 电源管理（ASPM）问题。" },
            { 0x00000005ull,
              "通用硬件错误（不属于其它任何错误源类型，典型为 ACPI GHES 上报）。" },
            { 0x00000006ull,
              "初始化错误（Itanium INIT）。" },
            { 0x00000007ull,
              "引导错误。" },
            { 0x00000008ull,
              "SCI 通用错误。注：微软两处文档对 SCI 的展开不一致——0x124 页写作 scalable coherent interface（可伸缩一致性接口），ntddk.h 枚举页写作 service control interrupt。" },
            { 0x00000009ull,
              "不可纠正的 Itanium 机器检查中止。参数 3 为 SAL 日志长度（字节），参数 4 为 SAL 地址。" },
            { 0x0000000Aull,
              "已纠正的 Itanium 机器检查错误。" },
            { 0x0000000Bull,
              "已纠正的 Itanium 平台错误。" },
            { 0x0000000Cull,
              "其它类型的错误源（v2）。" },
            { 0x0000000Dull,
              "基于 SCI 的 GHESv2（ACPI 通用硬件错误源）。" },
            { 0x0000000Eull,
              "BMC（基板管理控制器）上报的错误信息，多见于服务器平台。" },
            { 0x0000000Full,
              "ARS PMEM（地址范围擦洗，持久性内存）错误源。" },
            { 0x00000010ull,
              "设备驱动错误源——由驱动通过 WHEA 主动上报的硬件错误。" },
            { 0x00000011ull,
              "Arm 同步外部中止（Synchronous External Abort）。" },
            { 0x00000012ull,
              "Arm SError 中断。" },
        };

        // kDpcWatchdogSubtypes：0x133 DPC_WATCHDOG_VIOLATION 的参数 1 子类型。
        constexpr SubcodePair kDpcWatchdogSubtypes[] = {
            { 0x00000000ull,
              "单个 DPC 或 ISR 超出了时间配额。参数 2 为实际 DPC 时间（tick），参数 3 为配额（tick），参数 4 可转为 nt!DPC_WATCHDOG_GLOBAL_TRIAGE_BLOCK。肇事组件一般能直接从调用栈看出来；DPC 建议 <100us，ISR 建议 <25us。" },
            { 0x00000001ull,
              "系统累计在 IRQL >= DISPATCH_LEVEL 上停留过久。参数 2 为看门狗周期，参数 3 可转为 nt!DPC_WATCHDOG_GLOBAL_TRIAGE_BLOCK，参数 4 保留。此时崩溃点常常不在肇事代码上，需要用 ETW 跟踪找出执行时间异常的驱动。" },
        };

        // kPowerStateSubtypes：0x9F DRIVER_POWER_STATE_FAILURE 的参数 1 子类型。
        constexpr SubcodePair kPowerStateSubtypes[] = {
            { 0x00000001ull,
              "被释放的设备对象上还有未完成的电源请求。参数 2 为该设备对象。" },
            { 0x00000002ull,
              "设备对象完成了系统电源状态请求的 IRP，却没有调用 PoStartNextPowerIrp。参数 2 为目标设备对象，参数 3 为设备对象，参数 4 为驱动对象。" },
            { 0x00000003ull,
              "设备对象阻塞 IRP 时间过长（最常见的一种）。参数 2 为设备栈的 PDO，参数 3 可转为 nt!_TRIAGE_9F_POWER，参数 4 为被阻塞的 IRP。用 !irp 参数4 / !devstack 参数2 定位卡住的驱动。" },
            { 0x00000004ull,
              "电源状态切换在等待与即插即用子系统同步时超时。参数 2 为超时秒数，参数 3 为当前持有 PnP 锁的线程，参数 4 可转为 nt!_TRIAGE_9F_PNP。" },
            { 0x00000005ull,
              "设备未能在规定时间内完成定向电源切换（DFx）。参数 2 为设备栈 PDO，参数 3 为 POP_FX_DEVICE 对象。" },
            { 0x00000006ull,
              "设备未能成功完成其定向电源切换回调。参数 2 为 POP_FX_DEVICE 对象，参数 3 为 1 表示定向下电、0 表示定向上电。" },
            { 0x00000500ull,
              "设备对象完成了系统电源状态请求的 IRP，却没有调用 PoStartNextPowerIrp。参数 3 为目标设备对象，参数 4 为设备对象。" },
        };

        // kPatchGuardRegions：0x109 CRITICAL_STRUCTURE_CORRUPTION 的参数 4 区域类型，
        // 说明 PatchGuard 发现哪一类内核结构被改动了。
        constexpr SubcodePair kPatchGuardRegions[] = {
            { 0x00000000ull,
              "通用数据区。" },
            { 0x00000001ull,
              "函数体被修改（内核函数被内联挂钩）。" },
            { 0x00000002ull,
              "处理器中断描述符表（IDT）被修改。" },
            { 0x00000003ull,
              "处理器全局描述符表（GDT）被修改。" },
            { 0x00000004ull,
              "类型 1 进程链表损坏（常见于隐藏进程的 Rootkit）。" },
            { 0x00000005ull,
              "类型 2 进程链表损坏。" },
            { 0x00000006ull,
              "调试例程被修改。" },
            { 0x00000007ull,
              "关键 MSR 被修改（如 LSTAR/SYSENTER，典型的系统调用挂钩）。" },
            { 0x00000008ull,
              "对象类型结构被修改。" },
            { 0x00000009ull,
              "处理器 IVT 被修改。" },
            { 0x0000000Aull,
              "系统服务函数被修改（SSDT 挂钩）。" },
            { 0x0000000Bull,
              "通用会话数据区被修改。" },
            { 0x0000000Cull,
              "会话函数或其 .pdata 被修改。" },
            { 0x0000000Dull,
              "导入表被修改（IAT 挂钩）。" },
            { 0x0000000Eull,
              "会话导入表被修改。" },
            { 0x0000000Full,
              "Ps Win32 callout 被修改。" },
            { 0x00000010ull,
              "调试切换例程被修改。" },
            { 0x00000011ull,
              "IRP 分配器被修改。" },
            { 0x00000012ull,
              "驱动调用分发器被修改（IoCallDriver 路径被挂钩）。" },
            { 0x00000013ull,
              "IRP 完成分发器被修改。" },
            { 0x00000014ull,
              "IRP 释放器被修改。" },
            { 0x00000015ull,
              "处理器控制寄存器被修改（如 CR0/CR4 的 WP、SMEP 位被清）。" },
            { 0x00000016ull,
              "关键浮点控制寄存器被修改。" },
            { 0x00000017ull,
              "本地 APIC 被修改。" },
            { 0x00000018ull,
              "内核通知 callout 被修改。" },
            { 0x00000019ull,
              "已加载模块链表被修改（典型的隐藏驱动手法）。" },
            { 0x0000001Aull,
              "类型 3 进程链表损坏。" },
            { 0x0000001Bull,
              "类型 4 进程链表损坏。" },
            { 0x0000001Cull,
              "驱动对象损坏（分发例程表被改写）。" },
            { 0x0000001Dull,
              "执行体回调对象被修改。" },
            { 0x0000001Eull,
              "模块填充区被修改（常被用来藏 shellcode）。" },
            { 0x0000001Full,
              "受保护进程被修改。" },
            { 0x00000020ull,
              "通用数据区（与 0x0 同名，非笔误，官方表两处都是该描述）。" },
            { 0x00000021ull,
              "页哈希不匹配——内核页面内容与签名哈希对不上，可能是代码被改或内存位翻转。" },
            { 0x00000022ull,
              "会话页哈希不匹配。" },
            { 0x00000023ull,
              "加载配置目录被修改（含 CFG 相关数据）。" },
            { 0x00000024ull,
              "倒排函数表被修改（异常展开表挂钩）。" },
            { 0x00000025ull,
              "会话配置被修改。" },
            { 0x00000026ull,
              "扩展处理器控制寄存器被修改（如 XCR0）。" },
            { 0x00000027ull,
              "类型 1 池损坏。" },
            { 0x00000028ull,
              "类型 2 池损坏。" },
            { 0x00000029ull,
              "类型 3 池损坏。" },
            { 0x00000101ull,
              "通用池损坏。" },
            { 0x00000102ull,
              "win32k.sys 被修改。" },
        };

        // kVerifierViolations：0xC4 DRIVER_VERIFIER_DETECTED_VIOLATION 的参数 1 子类型。
        // 驱动验证器是主动抓包：命中即说明目标驱动确实违反了某条规则，
        // 子类型直接对应违反的检查项，是可信度最高的一类线索。
        constexpr SubcodePair kVerifierViolations[] = {
            { 0x00000000ull,
              "驱动请求了 0 字节的池分配。参数 2 为当前 IRQL，参数 3 为池类型，参数 4 为字节数。" },
            { 0x00000001ull,
              "驱动在 IRQL > APC_LEVEL 时分配分页内存。参数 2 为当前 IRQL，参数 3 为池类型，参数 4 为分配字节数。" },
            { 0x00000002ull,
              "驱动在 IRQL > DISPATCH_LEVEL 时分配非分页内存。参数 2 为当前 IRQL，参数 3 为池类型，参数 4 为分配字节数。" },
            { 0x00000003ull,
              "调用方申请超过一页的 must-succeed 池，而该 API 最多允许一页。" },
            { 0x00000010ull,
              "驱动释放了一个并非由分配调用返回的地址。参数 2 为该错误地址。" },
            { 0x00000011ull,
              "驱动在 IRQL > APC_LEVEL 时释放分页池。参数 2 为当前 IRQL，参数 3 为池类型，参数 4 为池地址。" },
            { 0x00000012ull,
              "驱动在 IRQL > DISPATCH_LEVEL 时释放非分页池。参数 2 为当前 IRQL，参数 3 为池类型，参数 4 为池地址。" },
            { 0x00000013ull,
              "驱动释放了一块已经被释放的池内存。参数 3 指向池头，参数 4 为池头内容。" },
            { 0x00000014ull,
              "同 0x13：驱动释放了一块已经被释放的池内存。" },
            { 0x00000015ull,
              "被释放的池块中含有仍然活动的定时器。参数 2 为定时器项，参数 3 为池类型，参数 4 为被释放的池地址。释放前必须 KeCancelTimer。" },
            { 0x00000016ull,
              "驱动在错误的地址上释放池，或给内存例程传了非法参数。参数 3 为池地址。" },
            { 0x00000017ull,
              "被释放的池块中含有仍然活动的 ERESOURCE。参数 2 为该 ERESOURCE 项，参数 3 为池类型，参数 4 为被释放的池地址。释放前必须 ExDeleteResourceLite（与 0xD2 同类，只是检出点不同）。" },
            { 0x00000030ull,
              "驱动给 KeRaiseIrql 传了非法参数（低于当前 IRQL 或高于 HIGH_LEVEL），常见于使用了未初始化的 IRQL 变量。参数 2 为当前 IRQL，参数 3 为请求 IRQL。" },
            { 0x00000031ull,
              "驱动给 KeLowerIrql 传了非法参数（高于当前 IRQL 或高于 HIGH_LEVEL）。参数 2 为当前 IRQL，参数 3 为请求 IRQL；参数 4 为 0 表示新 IRQL 非法，为 1 表示在 DPC 例程中该 IRQL 非法。" },
            { 0x00000032ull,
              "驱动在非 DISPATCH_LEVEL 的 IRQL 上调用 KeReleaseSpinLock，常见于自旋锁被重复释放。参数 2 为当前 IRQL，参数 3 为自旋锁地址。" },
            { 0x00000033ull,
              "驱动在 IRQL > APC_LEVEL 时获取快速互斥体。参数 2 为当前 IRQL，参数 3 为快速互斥体地址。" },
            { 0x00000034ull,
              "驱动在非 APC_LEVEL 的 IRQL 上释放快速互斥体。参数 3 为线程 APC 禁用计数，参数 4 为互斥体地址。" },
            { 0x00000035ull,
              "内核在非 DISPATCH_LEVEL 的 IRQL 上释放了自旋锁。参数 3 为自旋锁地址，参数 4 为旧 IRQL。" },
            { 0x00000036ull,
              "内核在非 DISPATCH_LEVEL 的 IRQL 上释放了排队自旋锁。参数 3 为自旋锁编号，参数 4 为旧 IRQL。" },
            { 0x00000037ull,
              "驱动获取 ERESOURCE 时未禁用 APC。获取前应调用 KeEnterCriticalRegion。参数 3 为 APC 禁用计数，参数 4 为资源地址。" },
            { 0x00000038ull,
              "驱动释放 ERESOURCE 时未禁用 APC。参数 3 为 APC 禁用计数，参数 4 为资源地址。" },
            { 0x00000039ull,
              "驱动以 unsafe 方式获取互斥体时 IRQL 不等于 APC_LEVEL。参数 3 为 APC 禁用计数，参数 4 为互斥体地址。" },
            { 0x0000003Aull,
              "驱动以 unsafe 方式释放互斥体时 IRQL 不等于 APC_LEVEL。参数 3 为 APC 禁用计数，参数 4 为互斥体地址。" },
            { 0x0000003Bull,
              "在 IRQL >= DISPATCH_LEVEL 时调用了 KeWaitXxx 例程。参数 3 为等待对象，参数 4 为超时参数。" },
            { 0x0000003Cull,
              "驱动用无效句柄调用了 ObReferenceObjectByHandle。参数 2 为传入的句柄，参数 3 为对象类型。" },
            { 0x0000003Dull,
              "驱动把一个未对齐的 ERESOURCE 传给 ExAcquireResourceExclusive。参数 4 为该资源地址。" },
            { 0x0000003Eull,
              "驱动对一个并不处于临界区的线程调用了 KeLeaveCriticalRegion，即 Enter/Leave 未配对。" },
            { 0x0000003Full,
              "驱动对引用计数为 0 的对象调用了 ObReferenceObject 或 ObDereferenceObject。参数 2 为对象地址，参数 3 为 -1 表示解引用、1 表示引用。" },
            { 0x00000040ull,
              "驱动在 IRQL < DISPATCH_LEVEL 时调用 KeAcquireSpinLockAtDpcLevel。参数 2 为当前 IRQL，参数 3 为自旋锁地址。" },
            { 0x00000041ull,
              "驱动在 IRQL < DISPATCH_LEVEL 时调用 KeReleaseSpinLockFromDpcLevel。参数 2 为当前 IRQL，参数 3 为自旋锁地址。" },
            { 0x00000042ull,
              "驱动在 IRQL > DISPATCH_LEVEL 时调用 KeAcquireSpinLock。参数 2 为当前 IRQL，参数 3 为自旋锁地址。" },
            { 0x00000051ull,
              "驱动写越过分配末尾后再释放该内存（仅在开启池跟踪时报出）。参数 2 为分配基址，参数 3 为越界引用地址，参数 4 为计费字节数。" },
            { 0x00000052ull,
              "同 0x51：驱动越界写后再释放（池跟踪）。参数 2 为分配基址，参数 3 为哈希项，参数 4 为计费字节数。" },
            { 0x00000053ull,
              "同 0x51：驱动越界写后再释放（池跟踪）。参数 2 为分配基址，参数 3 为池头。" },
            { 0x00000054ull,
              "同 0x51：驱动越界写后再释放（池跟踪）。参数 2 为分配基址，参数 4 为池哈希表大小。" },
            { 0x00000059ull,
              "同 0x51：驱动越界写后再释放（池跟踪）。参数 2 为分配基址，参数 3 为链表索引。" },
            { 0x00000060ull,
              "驱动在卸载前没有释放全部池分配（池泄漏）。参数 2/3 为分页与非分页已分配字节数，参数 4 为未释放的分配数。" },
            { 0x00000061ull,
              "驱动正在卸载，其线程却仍在分配池内存。参数含义同 0x60。" },
            { 0x00000062ull,
              "驱动卸载时仍有未释放的池分配。参数 2 为驱动名，参数 4 为未释放分配总数（含分页与非分页）。用 !verifier 3 驱动名.sys 可列出泄漏点。" },
            { 0x0000006Full,
              "对不在 PFN 数据库中的页面调用 MmProbeAndLockPages，典型是驱动想锁自己的双端口 RAM。这不但没必要，在物理内存不连续的机器上还会破坏内存。参数 2 为 MDL 地址，参数 3 为被锁定的物理页，参数 4 为系统最高物理页。" },
            { 0x00000070ull,
              "驱动在 IRQL > DISPATCH_LEVEL 时调用 MmProbeAndLockPages。参数 2 为当前 IRQL，参数 3 为 MDL 地址，参数 4 为访问模式。" },
            { 0x00000071ull,
              "驱动在 IRQL > DISPATCH_LEVEL 时调用 MmProbeAndLockProcessPages。参数 3 为 MDL 地址，参数 4 为进程地址。" },
            { 0x00000072ull,
              "驱动在 IRQL > DISPATCH_LEVEL 时调用 MmProbeAndLockSelectedPages。参数 3 为 MDL 地址，参数 4 为进程地址。" },
            { 0x00000073ull,
              "驱动在 IRQL > DISPATCH_LEVEL 时调用 MmMapIoSpace。参数 3 为物理地址（32 位系统上为低 32 位），参数 4 为字节数。" },
            { 0x00000074ull,
              "驱动在内核模式下以 IRQL > DISPATCH_LEVEL 调用 MmMapLockedPages。参数 3 为 MDL 地址，参数 4 为访问模式。" },
            { 0x00000075ull,
              "驱动在用户模式下以 IRQL > APC_LEVEL 调用 MmMapLockedPages。参数 3 为 MDL 地址，参数 4 为访问模式。" },
            { 0x00000076ull,
              "驱动在内核模式下以 IRQL > DISPATCH_LEVEL 调用 MmMapLockedPagesSpecifyCache。参数 3 为 MDL 地址。" },
            { 0x00000077ull,
              "驱动在用户模式下以 IRQL > APC_LEVEL 调用 MmMapLockedPagesSpecifyCache。参数 3 为 MDL 地址。" },
            { 0x00000078ull,
              "驱动在 IRQL > DISPATCH_LEVEL 时调用 MmUnlockPages。参数 3 为 MDL 地址。" },
            { 0x00000079ull,
              "驱动在内核模式下以 IRQL > DISPATCH_LEVEL 调用 MmUnmapLockedPages。参数 3 为被解除映射的虚拟地址，参数 4 为 MDL 地址。" },
            { 0x0000007Aull,
              "驱动在用户模式下以 IRQL > APC_LEVEL 调用 MmUnmapLockedPages。参数 3 为被解除映射的虚拟地址，参数 4 为 MDL 地址。" },
            { 0x0000007Bull,
              "驱动在 IRQL > APC_LEVEL 时调用 MmUnmapIoSpace。参数 3 为虚拟地址，参数 4 为字节数。" },
            { 0x0000007Cull,
              "驱动对一个从未成功加锁的 MDL 调用 MmUnlockPages。参数 2 为 MDL 地址，参数 3 为 MDL 标志。" },
            { 0x0000007Dull,
              "驱动对页面来自非分页池的 MDL 调用 MmUnlockPages——这类页面本就不该解锁。参数 2 为 MDL 地址，参数 3 为 MDL 标志。" },
            { 0x0000007Eull,
              "驱动在 IRQL > DISPATCH_LEVEL 时调用 MmAllocatePagesForMdl(Ex) 或 MmFreePagesFromMdl。参数 2 为当前 IRQL，参数 3 为 DISPATCH_LEVEL。" },
            { 0x0000007Full,
              "驱动把页面来自分页池的 MDL 传给了 MmBuildMdlForNonPagedPool。参数 3 为 MDL 地址，参数 4 为 MDL 标志。" },
            { 0x00000080ull,
              "驱动在 IRQL > DISPATCH_LEVEL 时调用 KeSetEvent。参数 2 为当前 IRQL，参数 3 为事件对象地址。" },
            { 0x00000081ull,
              "驱动调用了 MmMapLockedPages；应改用 MmMapLockedPagesSpecifyCache 并把 BugCheckOnFailure 设为 FALSE。参数 2 为 MDL 地址，参数 3 为 MDL 标志。" },
            { 0x00000082ull,
              "驱动调用 MmMapLockedPagesSpecifyCache 时把 BugCheckOnFailure 设成了 TRUE，应设为 FALSE 并自行处理失败。参数 2 为 MDL 地址，参数 3 为 MDL 标志。" },
            { 0x00000083ull,
              "驱动调用 MmMapIoSpace 前没有锁定 MDL 页面。参数 2 为物理地址范围起点，参数 3 为映射字节数，参数 4 为第一个未锁定的页帧号。" },
            { 0x00000085ull,
              "驱动调用 MmMapLockedPages 前没有锁定 MDL 页面。参数 2 为 MDL 地址，参数 3 为待映射页数，参数 4 为第一个未锁定的页帧号。" },
            { 0x00000089ull,
              "MDL 未标记为 I/O，却包含非内存页地址。参数 2 为 MDL 地址，参数 3 指向 MDL 中的该非内存页，参数 4 为其页号。" },
            { 0x00000091ull,
              "驱动用了操作系统不支持的方式切换内核栈。扩展内核栈的唯一受支持方式是 KeExpandKernelStackAndCallout。" },
            { 0x000000A0ull,
              "在硬盘上检测到 CRC 错误（仅在开启 Driver Verifier 磁盘完整性检查时报出）。参数 2 为读写 IRP，参数 3 为下层设备对象，参数 4 为出错扇区号。" },
            { 0x000000A1ull,
              "异步检测到扇区 CRC 错误（磁盘完整性检查）。参数 2 为 IRP 副本（原 IRP 已完成），参数 3 为下层设备对象，参数 4 为出错扇区号。" },
            { 0x000000A2ull,
              "CRCDISK 的校验和副本不匹配，可能是分页 I/O 错误（磁盘完整性检查）。参数 2 为该 IRP 或其副本，参数 3 为下层设备对象，参数 4 为出错扇区号。" },
            { 0x000000B0ull,
              "驱动对标志不正确的 MDL 调用 MmProbeAndLockPages，例如把 MmBuildMdlForNonPagedPool 建的 MDL 传了进去。参数 2 为 MDL 地址，参数 3 为 MDL 标志，参数 4 为错误标志位。" },
            { 0x000000B1ull,
              "驱动对标志不正确的 MDL 调用 MmProbeAndLockProcessPages。参数 3 为 MDL 标志，参数 4 为错误标志位。" },
            { 0x000000B2ull,
              "驱动对标志不正确的 MDL 调用 MmMapLockedPages，例如该 MDL 已映射到系统地址或根本未加锁。参数 3 为 MDL 标志，参数 4 为错误标志位。" },
            { 0x000000B3ull,
              "驱动对缺少必要标志的 MDL 调用 MmMapLockedPages（例如 MDL 未加锁）。参数 3 为 MDL 标志，参数 4 为期望但缺失的标志。" },
            { 0x000000B4ull,
              "驱动对由 IoBuildPartialMdl 创建的部分 MDL 调用了 MmUnlockPages。参数 3 为 MDL 标志，参数 4 为意外出现的部分 MDL 标志。" },
            { 0x000000B5ull,
              "驱动对部分 MDL（IoBuildPartialMdl 创建）调用了 MmUnmapLockedPages。参数 3 为 MDL 标志，参数 4 为意外出现的部分 MDL 标志。" },
            { 0x000000B6ull,
              "对一个并未映射到系统地址的 MDL 调用了 MmUnmapLockedPages。参数 3 为 MDL 标志，参数 4 为缺失的 MDL 标志。" },
            { 0x000000B7ull,
              "系统 BIOS 在睡眠状态切换过程中破坏了低端物理内存。参数 2 为被破坏的物理页数，参数 3/4 为首尾物理页。属于固件问题，先升级 BIOS。" },
            { 0x000000B8ull,
              "MDL 描述的页面仍处于映射状态；驱动必须先解除映射再调用 IoFreeMdl。参数 2 为 MDL 地址，参数 3 为 MDL 标志。" },
            { 0x000000B9ull,
              "以错误的用户空间地址调用了 MmUnmapLockedPages。参数 2 为被解除映射的地址，参数 3 为 MDL 地址。" },
            { 0x000000C0ull,
              "驱动在中断被禁用的状态下调用了 IoCallDriver。参数 2 为 IRP 地址。" },
            { 0x000000C1ull,
              "驱动的分发例程返回时中断仍处于禁用状态。参数 2 为分发例程地址。" },
            { 0x000000C2ull,
              "驱动在中断被禁用后调用了 Fast I/O 分发例程。" },
            { 0x000000C3ull,
              "驱动的 Fast I/O 分发例程返回时中断仍处于禁用状态。参数 2 为该例程地址。" },
            { 0x000000C5ull,
              "驱动分发例程改变了线程的 APC 禁用计数，即 KeEnterCriticalRegion / KeLeaveCriticalRegion（或互斥体获取/释放、FsRtlEnterFileSystem / FsRtlExitFileSystem）没有配对。参数 2 为分发例程地址，参数 3/4 为调用后与调用前的计数。" },
            { 0x000000C6ull,
              "驱动 Fast I/O 分发例程改变了线程的 APC 禁用计数，同样是临界区进出未配对。参数 2 为该例程地址，参数 3/4 为调用后与调用前的计数。" },
            { 0x000000CAull,
              "驱动试图重复初始化一个 lookaside 链表。参数 2 为该链表地址。" },
            { 0x000000CBull,
              "驱动试图删除一个未初始化的 lookaside 链表。参数 2 为该链表地址。" },
            { 0x000000CCull,
              "驱动释放的池块中含有仍然活动的 lookaside 链表。参数 2 为该链表地址，参数 3/4 为该池分配的起址与大小。" },
            { 0x000000CDull,
              "驱动创建 lookaside 链表时指定的块大小小于最小支持值。参数 2 为该链表地址，参数 3 为指定值，参数 4 为最小值。" },
            { 0x000000D0ull,
              "驱动试图重复初始化一个 ERESOURCE。参数 2 为该结构地址。" },
            { 0x000000D1ull,
              "驱动试图删除一个未初始化的 ERESOURCE。参数 2 为该结构地址。" },
            { 0x000000D2ull,
              "驱动释放的池块中含有仍然活动的 ERESOURCE。参数 2 为该结构地址，参数 3/4 为该池分配的起址与大小。" },
            { 0x000000D5ull,
              "IoReleaseRemoveLock 的 tag 与此前 IoAcquireRemoveLock 的 tag 不匹配（I/O 验证选项）。参数 2 为 IO_REMOVE_LOCK 结构地址（非 checked build 时为 Driver Verifier 代建的影子结构），参数 3 为本次释放使用的 tag。" },
            { 0x000000D6ull,
              "IoReleaseRemoveLockAndWait 的 tag 与此前 IoAcquireRemoveLock 的 tag 不匹配（I/O 验证选项）。参数 3/4 为不匹配的 tag 与此前的 tag。" },
            { 0x000000D7ull,
              "RemoveLock 即使在 IoReleaseRemoveLockAndWait 之后也不能重新初始化，因为可能仍有线程在用。RemoveLock 应放在设备扩展里且只初始化一次。参数 2 为 Driver Verifier 内部结构，参数 3 为驱动指定的结构。" },
            { 0x000000DAull,
              "驱动卸载时没有注销其 WMI 回调函数。参数 2 为驱动起始地址，参数 3 为回调地址。" },
            { 0x000000DBull,
              "删除了一个尚未从 WMI 注销的设备对象。参数 2 为设备对象地址。" },
            { 0x000000DCull,
              "EtwUnregister 收到了无效的 RegHandle。" },
            { 0x000000DDull,
              "驱动卸载前没有调用 EtwUnregister。参数 2 为 EtwRegister 调用点，参数 3 为卸载中的驱动起始地址；Windows 8 及以后参数 4 为 ETW RegHandle。" },
            { 0x000000DFull,
              "同步对象位于会话地址空间中。会话空间里的对象可能被其它会话或无会话空间的系统线程操作，因而被禁止。参数 2 为对象地址。" },
            { 0x000000E0ull,
              "调用内核函数时把用户态地址当作参数传入。参数 2 为该用户态地址，参数 3 为范围字节数。" },
            { 0x000000E1ull,
              "同步对象的地址无效或位于可分页内存中。参数 2 为该对象地址。" },
            { 0x000000E2ull,
              "Irp->RequestorMode 为 KernelMode 的 IRP 里却含有用户态地址。参数 2 为 IRP 地址，参数 3 为该用户态地址。" },
            { 0x000000E3ull,
              "驱动以用户态地址为参数调用了内核模式的 ZwXxx 例程。参数 2 为调用点，参数 3 为该用户态地址。" },
            { 0x000000E4ull,
              "驱动以格式错误的 UNICODE_STRING 为参数调用了内核模式 ZwXxx 例程。参数 2 为调用点，参数 3 为该结构地址。" },
            { 0x000000E5ull,
              "在不正确的 IRQL 上调用了内核 API。参数 2 为当前 IRQL。" },
            { 0x000000E6ull,
              "内核 Zw API 未在 IRQL = PASSIVE_LEVEL 且启用特殊内核 APC 的条件下调用。参数 2 为调用点，参数 3 为当前 IRQL，参数 4 为特殊内核 APC 状态。" },
            { 0x000000EAull,
              "驱动在 APC 未禁用时获取 pushlock。参数 2 为当前 IRQL，参数 3 为 APC 禁用计数，参数 4 为 pushlock 地址。" },
            { 0x000000EBull,
              "驱动在 APC 未禁用时释放 pushlock。参数 2 为当前 IRQL，参数 3 为 APC 禁用计数，参数 4 为 pushlock 地址。" },
            { 0x000000F0ull,
              "驱动用重叠的源/目标缓冲区调用了 memcpy，应改用 memmove。参数 2/3/4 为目标、源与字节数。" },
            { 0x000000F5ull,
              "驱动向 ObReferenceObjectByHandle 传了 NULL 句柄。参数 2 为该 NULL 句柄地址，参数 3 为对象类型。" },
            { 0x000000F6ull,
              "驱动把用户态句柄当作内核模式句柄引用。参数 2 为句柄值，参数 3 为当前进程地址，参数 4 为发起错误引用的驱动代码地址。" },
            { 0x000000F7ull,
              "驱动在系统进程上下文中对内核句柄发起用户态引用。参数 2 为句柄，参数 3 为对象类型，参数 4 为 AccessMode。" },
            { 0x000000FAull,
              "IRP 完成例程返回时的 IRQL 与被调用时不同。参数 2 为完成例程地址，参数 3 为调用前 IRQL，参数 4 为调用后 IRQL。" },
            { 0x000000FBull,
              "IRP 完成例程改变了线程的 APC 禁用计数，即临界区进出未配对。参数 2 为完成例程地址，参数 3/4 为调用后与调用前的计数。" },
            { 0x000000FCull,
              "从内核模式调用 ZwNotifyChangeKey 时使用了不受支持的 ApcContext。参数 2 为调用点，参数 3 为传入的 ApcContext。" },
            { 0x00000105ull,
              "驱动用 ExFreePool 而不是 IoFreeIrp 释放 IRP。参数 2 为 IRP 地址。" },
            { 0x0000010Aull,
              "驱动试图向 Idle 进程计入池配额。" },
            { 0x0000010Bull,
              "驱动在 DPC 例程中计入池配额，而 DPC 中当前进程上下文是不确定的。" },
            { 0x00000110ull,
              "驱动的中断服务例程破坏了扩展线程上下文（如 XMM/AVX 寄存器状态）。参数 2 为 ISR 地址，参数 3/4 为执行前后保存的扩展上下文地址。" },
            { 0x00000111ull,
              "中断服务例程返回时改变了 IRQL。参数 2 为 ISR 地址，参数 3/4 为执行前后的 IRQL。" },
            { 0x00000115ull,
              "Driver Verifier 检测到系统关机超过 20 分钟仍未完成。参数 2 为可能死锁的负责关机的线程地址。" },
            { 0x0000011Aull,
              "驱动在 IRQL > APC_LEVEL 时调用 KeEnterCriticalRegion。参数 2 为当前 IRQL。" },
            { 0x0000011Bull,
              "驱动在 IRQL > APC_LEVEL 时调用 KeLeaveCriticalRegion。参数 2 为当前 IRQL。" },
            { 0x00000120ull,
              "线程在 IRQL > DISPATCH_LEVEL 时等待。KeWaitForSingleObject/MultipleObjects 要求 IRQL <= DISPATCH_LEVEL。参数 2 指向 IRQL 值，参数 3 指向等待对象，参数 4 指向超时值。" },
            { 0x00000121ull,
              "线程在 IRQL = DISPATCH_LEVEL 且 Timeout 为 NULL 时等待——这会让 CPU 永久卡在 DISPATCH_LEVEL 上。参数 2 指向 IRQL 值，参数 3 指向等待对象，参数 4 指向超时值。" },
            { 0x00000122ull,
              "线程在 DISPATCH_LEVEL 上等待且 Timeout 非 0。Timeout != 0 时要求 IRQL <= APC_LEVEL。参数 2 指向 IRQL 值，参数 3 指向等待对象，参数 4 指向超时值。" },
            { 0x00000123ull,
              "调用方把等待模式指定为 UserMode，但等待对象位于内核栈上——栈可被换出，会导致对象失效。参数 2 为该对象地址。" },
            { 0x00000130ull,
              "工作项位于会话地址空间中，禁止如此。参数 2 为工作项地址。" },
            { 0x00000131ull,
              "工作项位于可分页内存中，而内核会在 DISPATCH_LEVEL 使用它，必须放在非分页内存。参数 2 为工作项地址。" },
            { 0x00000135ull,
              "被取消的 IRP 未在预期时间内完成——驱动完成取消 IRP 太慢。参数 2 为 IRP 地址，参数 3 为自 IoCancelIrp 起允许的毫秒数。" },
            { 0x0000013Aull,
              "ExFreePool 时 Driver Verifier 发现内部池跟踪值有误。参数 2 为被释放的池块地址，参数 3 为错误值，参数 4 为该错误值的地址。" },
            { 0x0000013Bull,
              "同 0x13A：ExFreePool 时池跟踪内部值有误。参数 3 为错误值的地址，参数 4 指向出错内存页的指针。" },
            { 0x0000013Cull,
              "同 0x13A：ExFreePool 时池跟踪内部值有误。参数 3 为错误值，参数 4 为该错误值的地址。" },
            { 0x0000013Dull,
              "同 0x13A：ExFreePool 时池跟踪内部值有误。参数 3 为错误值的地址，参数 4 为期望的正确值。" },
            { 0x0000013Eull,
              "ExFreePool 调用方给出的池块地址与 Driver Verifier 记录的地址不同。参数 2 为调用方给出的池块地址，参数 3 为 Driver Verifier 记录的池块地址。" },
            { 0x0000013Full,
              "ExFreePool 释放的字节数与 Driver Verifier 记录的不同。参数 2 为池块地址，参数 3 为释放字节数，参数 4 指向 Driver Verifier 记录的字节数。" },
            { 0x00000140ull,
              "从可分页或可交易内存构建了未加锁的 MDL。参数 2 为当前 IRQL，参数 3 为 MDL 地址，参数 4 为其虚拟地址。" },
            { 0x00000141ull,
              "驱动显式要求 4GB 以下的物理内存。参数 2 为请求的最高物理地址，参数 3 为字节数。" },
            { 0x00001000ull,
              "自死锁：当前线程只以共享方式持有该资源，却又递归地要求独占获取（死锁检测选项）。参数 2 为资源地址。" },
            { 0x00001001ull,
              "死锁：检测到锁层次违规（死锁检测选项）。参数 2 为最终引发死锁的资源地址，可用 !deadlock 查看详情。" },
            { 0x00001002ull,
              "获取了一个未初始化的资源（死锁检测选项）。参数 2 为资源地址。" },
            { 0x00001003ull,
              "资源释放顺序不正确（死锁检测选项）。参数 2 为被释放的资源，参数 3 为本应先释放的资源。" },
            { 0x00001004ull,
              "由错误的线程释放资源（死锁检测选项）。参数 2 为资源地址，参数 3 为获取该资源的线程，参数 4 为当前线程。" },
            { 0x00001005ull,
              "资源被多次初始化（死锁检测选项）。参数 2 为资源地址。" },
            { 0x00001007ull,
              "资源在获取之前就被释放（死锁检测选项）。参数 2 为资源地址。" },
            { 0x00001008ull,
              "驱动用与该锁类型不匹配的 API 获取锁。参数 2 为锁地址。" },
            { 0x00001009ull,
              "驱动用与该锁类型不匹配的 API 释放锁。参数 2 为锁地址。" },
            { 0x0000100Aull,
              "已终止的线程仍持有该锁。参数 2 为持有者线程地址。" },
            { 0x0000100Bull,
              "被删除的锁仍被某个线程持有。参数 2 为锁地址，参数 3 为持有者线程地址。" },
            { 0x00001010ull,
              "写 IRP 的不变量 MDL 缓冲区内容在传输期间被修改（I/O 验证）。参数 2 为设备对象，参数 3 为 IRP，参数 4 为该 MDL 的系统空间映射地址。" },
            { 0x00001011ull,
              "读 IRP 的不变量 MDL 缓冲区在分发期间被修改，或缓冲区由 dummy 页支撑（I/O 验证）。参数 2 为设备对象，参数 3 为 IRP，参数 4 为该 MDL 的系统空间映射地址。" },
            { 0x00001012ull,
              "Driver Verifier 扩展状态存储检测到损坏。参数 2 指向描述该违规的字符串，参数 3/4 为相关数据（未使用时为 0）。" },
            { 0x00001013ull,
              "Driver Verifier 发现其捕获的原始 I/O 回调表被破坏——典型是有组件在挂钩驱动对象。参数 2 为驱动对象指针，参数 3 指向捕获的原始 I/O 回调。" },
            { 0x00002000ull,
              "代码完整性问题：调用方指定了可执行的池类型，应使用 NonPagedPoolNx。参数 2 为出错的驱动代码地址，参数 3 为池类型，参数 4 为池 tag（若提供）。" },
            { 0x00002001ull,
              "代码完整性问题：调用方指定了可执行的页保护，应清除 PAGE_EXECUTE* 位。参数 2 为出错的驱动代码地址，参数 3 为 WIN32_PROTECTION_MASK。" },
            { 0x00002002ull,
              "代码完整性问题：调用方指定了可执行的 MDL 映射，应使用 MdlMappingNoExecute。参数 2 为出错的驱动代码地址，参数 3 为页面优先级与 MdlMapping* 标志。" },
            { 0x00002003ull,
              "代码完整性问题：映像中存在同时可写又可执行的节。参数 2 为映像文件名，参数 3 为节头地址，参数 4 为节名。" },
            { 0x00002004ull,
              "代码完整性问题：映像中存在未按页对齐的节。参数 2 为映像文件名，参数 3 为节头地址，参数 4 为节名。" },
            { 0x00002005ull,
              "代码完整性问题：映像的导入地址表位于可执行节中。参数 2 为映像文件名，参数 3 为 IAT 目录，参数 4 为节名。" },
        };

        // kPnpFatalSubcodes：0xCA PNP_DETECTED_FATAL_ERROR 的参数 1 子码。
        constexpr SubcodePair kPnpFatalSubcodes[] = {
            { 0x00000001ull,
              "重复 PDO：同一个驱动实例枚举出了多个设备 ID 与唯一 ID 完全相同的 PDO。参数 2 为新上报的 PDO，参数 3 为被重复的旧 PDO。多为总线驱动枚举逻辑缺陷。" },
            { 0x00000002ull,
              "非法 PDO：需要 PDO 的 API 收到了随机内存、FDO、或尚未通过 QueryDeviceRelations/QueryBusRelations 返回给 PnP 的未初始化 PDO。参数 2 为该「PDO」，参数 3 为驱动对象。" },
            { 0x00000003ull,
              "非法 ID：枚举器返回的 ID 含非法字符或未正确以空字符结尾（ID 只能用 0x20-0x2B 与 0x2D-0x7F 范围内的字符）。参数 2 为被查询 ID 的 PDO，参数 3 为 ID 缓冲区，参数 4 表示 ID 种类（1=DeviceID，2=UniqueID，3=HardwareIDs，4=CompatibleIDs）。" },
            { 0x00000004ull,
              "枚举了已删除的 PDO：枚举器返回了一个此前已用 IoDeleteDevice 删除的 PDO。参数 2 为设置了 DOE_DELETE_PENDING 的 PDO。" },
            { 0x00000005ull,
              "PDO 在仍挂在 devnode 树上时被释放：其对象管理器引用计数降到 0。通常是驱动在查询 IRP 中返回 PDO 时忘了加引用。参数 2 为该 PDO。" },
            { 0x00000008ull,
              "总线关系中出现 NULL PDO：总线上有一个或多个设备返回了空 PDO。参数 2 为返回非法总线关系的那个设备栈的 PDO，参数 3 为返回的 PDO 总数，参数 4 为第一个 NULL PDO 的下标（从 0 开始）。" },
            { 0x00000009ull,
              "传给 IoDisconnectInterruptEx 的连接类型非法：必须与此前成功的 IoConnectInterruptEx 返回的类型一致。参数 2 为传入的连接类型。" },
            { 0x0000000Aull,
              "通知回调行为不正确：驱动在处理 PnP 通知时没能保持 IRQL 或 APC 禁用计数不变。参数 2 为驱动对象，参数 3 为回调返回后的 IRQL，参数 4 为返回后的 APC 禁用计数。" },
            { 0x0000000Bull,
              "已删除的 PDO 被当作关系上报：被移除设备的某个移除关系已经被删除。参数 2 为相关 PDO，参数 3 为移除关系。" },
        };

        // FindSubcode 作用：在子码表内线性查找；表都很小，线性查找足够快。
        // 传入表指针、表长与目标 code；命中返回中文文本，否则返回空串。
        QString FindSubcode(
            const SubcodePair* const table,
            const std::size_t count,
            const std::uint64_t code)
        {
            for (std::size_t index = 0; index < count; ++index)
            {
                if (table[index].code == code)
                {
                    return QString::fromUtf8(table[index].text);
                }
            }
            return QString();
        }

        // FindBugCheck 作用：在停止码表内查找一条释义。
        const BugCheckInfo* FindBugCheck(const std::uint32_t code)
        {
            for (const BugCheckInfo& info : kBugCheckCodes)
            {
                if (info.code == code)
                {
                    return &info;
                }
            }
            return nullptr;
        }

        // FindParameterSpec 作用：查找某个停止码的参数语义表。
        const BugCheckParameterSpec* FindParameterSpec(const std::uint32_t code)
        {
            for (const BugCheckParameterSpec& spec : kParameterSpecs)
            {
                if (spec.code == code)
                {
                    return &spec;
                }
            }
            return nullptr;
        }

        // Hex 作用：把数值格式化成 0x 大写十六进制文本。
        QString Hex(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
        }

        // RenderParameterDetail 作用：按语义角色把参数数值翻译成中文解读。
        // 传入 role 角色、value 参数值、modules 模块索引与 pointerSize 指针宽度；
        // 返回解读文本，没有可说的内容时返回空串。
        QString RenderParameterDetail(
            const ParameterRole role,
            const std::uint64_t value,
            const ModuleIndex& modules,
            const std::uint32_t pointerSize)
        {
            switch (role)
            {
            case ParameterRole::Address:
            case ParameterRole::ProcessObject:
            case ParameterRole::ThreadObject:
            case ParameterRole::DeviceObject:
            case ParameterRole::ExceptionRecord:
            case ParameterRole::ContextRecord:
            case ParameterRole::TrapFrame:
            {
                // 这些参数都是地址：先看是否落在模块内，再看是否为哨兵值。
                const QString annotation = modules.annotate(value);
                return annotation;
            }
            case ParameterRole::InstructionPointer:
            case ParameterRole::DriverObject:
            {
                // 指令地址是归因的关键：命中模块时直接点名。
                const AddressNote note = modules.resolve(value);
                if (!note.symbolText.isEmpty())
                {
                    return note.unloadedModule
                        ? QStringLiteral("%1（已卸载模块，高度可疑）").arg(note.symbolText)
                        : QStringLiteral("%1 ← 该地址所属模块是首要嫌疑对象").arg(note.symbolText);
                }
                return note.description;
            }
            case ParameterRole::Irql:
                return IrqlText(value);
            case ParameterRole::AccessType:
                return MemoryAccessTypeText(value);
            case ParameterRole::NtStatus:
            {
                // 嵌套的 NTSTATUS 才是真正的故障原因，名称与含义都要给出。
                const std::uint32_t status = static_cast<std::uint32_t>(value);
                const QString name = ExceptionCodeName(status);
                const QString meaning = ExceptionCodeMeaning(status);
                if (name.isEmpty() && meaning.isEmpty())
                {
                    return QStringLiteral("未收录的 NTSTATUS");
                }
                if (meaning.isEmpty())
                {
                    return name;
                }
                return name.isEmpty() ? meaning : QStringLiteral("%1 —— %2").arg(name, meaning);
            }
            case ParameterRole::Ticks:
                return QStringLiteral("%1 个时钟节拍").arg(value);
            case ParameterRole::SubMemoryManager:
                return MemoryManagementSubcodeText(value);
            case ParameterRole::SubPoolCaller:
                return BadPoolCallerText(value);
            case ParameterRole::SubVerifier:
                return DriverVerifierViolationText(value);
            case ParameterRole::SubSecurityCheck:
                return KernelSecurityCheckText(value);
            case ParameterRole::SubTrap:
                return KernelTrapText(value);
            case ParameterRole::SubWhea:
                return WheaErrorSourceText(value);
            case ParameterRole::SubDpcWatchdog:
                return DpcWatchdogText(value);
            case ParameterRole::SubPowerState:
                return PowerStateFailureText(value);
            case ParameterRole::SubPatchGuard:
                return PatchGuardRegionText(value);
            case ParameterRole::SubPnp:
                return PnpFatalErrorText(value);
            case ParameterRole::Raw:
            {
                // 无固定语义的参数也过一遍哨兵值与模块归属：
                // 很多“与子类型相关”的参数实际上就是地址。
                const QString poison = PoisonValueText(value, pointerSize);
                if (!poison.isEmpty())
                {
                    return poison;
                }
                return modules.symbolText(value);
            }
            default:
                return QString();
            }
        }
    }

    QString BugCheckCodeNameEx(const std::uint32_t code)
    {
        const BugCheckInfo* const info = FindBugCheck(code);
        return info != nullptr ? QString::fromUtf8(info->name) : QString();
    }

    QString BugCheckMeaning(const std::uint32_t code)
    {
        const BugCheckInfo* const info = FindBugCheck(code);
        return info != nullptr ? QString::fromUtf8(info->meaning) : QString();
    }

    BugCheckCategory BugCheckCategoryOf(const std::uint32_t code)
    {
        const BugCheckInfo* const info = FindBugCheck(code);
        return info != nullptr ? info->category : BugCheckCategory::Unknown;
    }

    QString BugCheckCategoryText(const BugCheckCategory category)
    {
        switch (category)
        {
        case BugCheckCategory::Driver:        return QStringLiteral("驱动缺陷");
        case BugCheckCategory::Memory:        return QStringLiteral("内存管理 / 内存故障");
        case BugCheckCategory::Hardware:      return QStringLiteral("硬件故障");
        case BugCheckCategory::FileSystem:    return QStringLiteral("文件系统 / 存储");
        case BugCheckCategory::Power:         return QStringLiteral("电源管理");
        case BugCheckCategory::Graphics:      return QStringLiteral("显示驱动 / 图形栈");
        case BugCheckCategory::Watchdog:      return QStringLiteral("看门狗超时");
        case BugCheckCategory::Security:      return QStringLiteral("安全检查 / 内存破坏防护");
        case BugCheckCategory::Software:      return QStringLiteral("系统组件 / 软件");
        case BugCheckCategory::Boot:          return QStringLiteral("启动 / 初始化");
        case BugCheckCategory::UserInitiated: return QStringLiteral("人为触发");
        default:                              return QStringLiteral("未归类");
        }
    }

    QString IrqlText(const std::uint64_t irql)
    {
        // 0/1/2 三级在所有架构上都一致，也是排查中真正关心的分界；
        // 更高的级别在 x86 与 x64 上编号不同，这里只做范围描述不硬编名字。
        switch (irql)
        {
        case 0:
            return QStringLiteral("0 (PASSIVE_LEVEL) —— 可以访问分页内存");
        case 1:
            return QStringLiteral("1 (APC_LEVEL) —— 可以访问分页内存");
        case 2:
            return QStringLiteral("2 (DISPATCH_LEVEL) —— 此级别及以上禁止访问分页内存，也禁止等待");
        default:
            break;
        }
        if (irql <= 15)
        {
            return QStringLiteral("%1 —— 设备中断级别（DIRQL），禁止访问分页内存").arg(irql);
        }
        return QStringLiteral("%1 —— 高于设备中断级别（32 位系统的时钟/IPI/电源级别）").arg(irql);
    }

    QString MemoryAccessTypeText(const std::uint64_t accessType)
    {
        // 不同停止码用的编码略有差异，但读=0、写=1、执行=8 是通用约定；
        // 0x50 一族还会用 2/10 表示取指令。
        switch (accessType)
        {
        case 0:  return QStringLiteral("读取");
        case 1:  return QStringLiteral("写入");
        case 2:  return QStringLiteral("执行（取指令）");
        case 8:  return QStringLiteral("执行（DEP 保护触发）");
        case 10: return QStringLiteral("执行（取指令，DEP 保护触发）");
        default: return QStringLiteral("访问类型编码 %1").arg(accessType);
        }
    }

    QString MemoryManagementSubcodeText(const std::uint64_t subcode)
    {
        const QString text = FindSubcode(
            kMemoryManagementSubcodes,
            sizeof(kMemoryManagementSubcodes) / sizeof(kMemoryManagementSubcodes[0]),
            subcode);
        if (!text.isEmpty())
        {
            return text;
        }
        return QStringLiteral("未收录的内存管理子码；该停止码整体指向内存管理结构不一致。");
    }

    QString BadPoolCallerText(const std::uint64_t violationType)
    {
        const QString text = FindSubcode(
            kPoolCallerViolations,
            sizeof(kPoolCallerViolations) / sizeof(kPoolCallerViolations[0]),
            violationType);
        return text.isEmpty() ? QStringLiteral("未收录的池违规类型。") : text;
    }

    QString KernelSecurityCheckText(const std::uint64_t subtype)
    {
        const QString text = FindSubcode(
            kSecurityCheckSubtypes,
            sizeof(kSecurityCheckSubtypes) / sizeof(kSecurityCheckSubtypes[0]),
            subtype);
        return text.isEmpty() ? QStringLiteral("未收录的安全检查类型。") : text;
    }

    QString KernelTrapText(const std::uint64_t trapNumber)
    {
        const QString text = FindSubcode(
            kKernelTraps,
            sizeof(kKernelTraps) / sizeof(kKernelTraps[0]),
            trapNumber);
        return text.isEmpty() ? QStringLiteral("未收录的陷阱号。") : text;
    }

    QString WheaErrorSourceText(const std::uint64_t sourceType)
    {
        const QString text = FindSubcode(
            kWheaErrorSources,
            sizeof(kWheaErrorSources) / sizeof(kWheaErrorSources[0]),
            sourceType);
        return text.isEmpty() ? QStringLiteral("未收录的 WHEA 错误源类型。") : text;
    }

    QString DpcWatchdogText(const std::uint64_t subtype)
    {
        const QString text = FindSubcode(
            kDpcWatchdogSubtypes,
            sizeof(kDpcWatchdogSubtypes) / sizeof(kDpcWatchdogSubtypes[0]),
            subtype);
        return text.isEmpty() ? QStringLiteral("未收录的超时类型。") : text;
    }

    QString PowerStateFailureText(const std::uint64_t subtype)
    {
        const QString text = FindSubcode(
            kPowerStateSubtypes,
            sizeof(kPowerStateSubtypes) / sizeof(kPowerStateSubtypes[0]),
            subtype);
        return text.isEmpty() ? QStringLiteral("未收录的电源失败子类型。") : text;
    }

    QString PatchGuardRegionText(const std::uint64_t region)
    {
        const QString text = FindSubcode(
            kPatchGuardRegions,
            sizeof(kPatchGuardRegions) / sizeof(kPatchGuardRegions[0]),
            region);
        return text.isEmpty() ? QStringLiteral("未收录的受保护区域类型。") : text;
    }

    QString DriverVerifierViolationText(const std::uint64_t subtype)
    {
        const QString text = FindSubcode(
            kVerifierViolations,
            sizeof(kVerifierViolations) / sizeof(kVerifierViolations[0]),
            subtype);
        if (!text.isEmpty())
        {
            return text;
        }
        // 未收录时按检查项分组给出方向性说明：子类型编号是按检查类别成段分配的，
        // 落在哪一段就说明启用的是哪一类验证选项。
        if (subtype <= 0x17ull)
        {
            return QStringLiteral("池分配 / 释放与 IRQL 类检查失败；具体子类型未收录。");
        }
        if (subtype >= 0x18ull && subtype <= 0x3Full)
        {
            return QStringLiteral("IRQL、自旋锁与同步对象类检查失败；具体子类型未收录。");
        }
        if (subtype >= 0x60ull && subtype <= 0x91ull)
        {
            return QStringLiteral("MDL、内存映射与 DMA 类检查失败；具体子类型未收录。");
        }
        if (subtype >= 0xE0ull && subtype <= 0xEBull)
        {
            return QStringLiteral("用户态地址访问与 Zw 调用类检查失败；具体子类型未收录。");
        }
        return QStringLiteral("驱动验证器捕获到违规；具体子类型未收录，请以启用的验证选项为线索。");
    }

    QString PnpFatalErrorText(const std::uint64_t subcode)
    {
        const QString text = FindSubcode(
            kPnpFatalSubcodes,
            sizeof(kPnpFatalSubcodes) / sizeof(kPnpFatalSubcodes[0]),
            subcode);
        return text.isEmpty()
            ? QStringLiteral("即插即用管理器检测到致命错误；具体子码未收录。")
            : text;
    }

    std::uint64_t FaultingAddressFromBugCheck(
        const std::uint32_t code,
        const std::uint64_t parameters[4])
    {
        // 借助参数语义表定位“出错指令地址”那一项，避免在两处维护同一份知识。
        const BugCheckParameterSpec* const spec = FindParameterSpec(code);
        if (spec == nullptr)
        {
            return 0;
        }
        for (int index = 0; index < 4; ++index)
        {
            if (spec->params[index].role == ParameterRole::InstructionPointer &&
                parameters[index] != 0)
            {
                return parameters[index];
            }
        }
        return 0;
    }

    std::uint32_t NestedStatusFromBugCheck(
        const std::uint32_t code,
        const std::uint64_t parameters[4])
    {
        const BugCheckParameterSpec* const spec = FindParameterSpec(code);
        if (spec == nullptr)
        {
            return 0;
        }
        for (int index = 0; index < 4; ++index)
        {
            if (spec->params[index].role == ParameterRole::NtStatus &&
                parameters[index] != 0)
            {
                return static_cast<std::uint32_t>(parameters[index]);
            }
        }
        return 0;
    }

    std::vector<BugCheckParameterInfo> DescribeBugCheckParameters(
        const std::uint32_t code,
        const std::uint64_t parameters[4],
        const ModuleIndex& modules,
        const std::uint32_t pointerSize)
    {
        // infos：恒为 4 项，UI 与报告都按固定四行渲染。
        std::vector<BugCheckParameterInfo> infos;
        infos.reserve(4);
        const BugCheckParameterSpec* const spec = FindParameterSpec(code);
        for (int index = 0; index < 4; ++index)
        {
            BugCheckParameterInfo info{};
            info.value = Hex(parameters[index]);
            if (spec != nullptr)
            {
                const ParameterSpec& parameterSpec = spec->params[index];
                info.label = parameterSpec.label != nullptr
                    ? QString::fromUtf8(parameterSpec.label)
                    : QString();
                info.detail = RenderParameterDetail(
                    parameterSpec.role, parameters[index], modules, pointerSize);
            }
            else
            {
                // 没有参数语义表时也别浪费信息：仍然尝试模块归属与哨兵值识别。
                info.detail = parameters[index] != 0
                    ? modules.annotate(parameters[index])
                    : QString();
            }
            infos.push_back(std::move(info));
        }
        return infos;
    }

    QStringList BugCheckSuggestions(const std::uint32_t code)
    {
        // 先给停止码专属建议，再兜底给归类级建议；两者不重复。
        switch (code)
        {
        case 0x0000000Au:
        case 0x000000D1u:
        case 0x000000C5u:
            return {
                QStringLiteral("参数 4 是出错指令地址：把它归属到的驱动作为首要嫌疑，优先更新或回滚该驱动。"),
                QStringLiteral("参数 1 是被访问的地址；若它接近 0 说明是空指针解引用，若是 0xFFFF… 之类说明取到了失效指针。"),
                QStringLiteral("怀疑对象明确后，用驱动验证器（verifier /standard /driver 该驱动.sys）复现，能在越界的第一现场断下。"),
                QStringLiteral("同一驱动反复出现在多份转储里，基本可以定案；只出现一次时先排除内存故障。"),
            };
        case 0x00000050u:
            return {
                QStringLiteral("参数 3 是发起访问的指令地址，据此定位肇事驱动。"),
                QStringLiteral("如果多份转储的出错地址毫无规律，优先跑 MemTest86 排查物理内存。"),
                QStringLiteral("常见诱因还包括杀软/加密/虚拟磁盘等文件系统过滤驱动，可临时卸载验证。"),
            };
        case 0x0000001Eu:
        case 0x0000007Eu:
        case 0x0000003Bu:
        case 0x0000008Eu:
            return {
                QStringLiteral("这几个停止码本身只说明“异常没人处理”，参数 1 的 NTSTATUS 才是真正的原因，先看它。"),
                QStringLiteral("参数 2 是出错指令地址，把它归属到的模块作为嫌疑对象。"),
                QStringLiteral("参数 1 若是 0xC0000005，按访问违例排查；若是 0x80000003，说明有代码执行到了断点指令。"),
            };
        case 0x00000133u:
            return {
                QStringLiteral("参数 1 为 0 时是单个 DPC 超时：看调用栈里的第三方驱动，常见于存储、网络与虚拟化驱动。"),
                QStringLiteral("参数 1 为 1 时是系统整体长时间处于高 IRQL：多为大量中断/DPC 堆积，检查磁盘或网卡驱动。"),
                QStringLiteral("虚拟机里出现该码时，先排除宿主机的磁盘卡顿与 CPU 超配。"),
            };
        case 0x00000124u:
        case 0x0000009Cu:
        case 0x0000012Bu:
            return {
                QStringLiteral("这是硬件报告的错误，换驱动通常无效：先取消一切超频（CPU/内存/XMP-EXPO）恢复默认。"),
                QStringLiteral("跑 MemTest86 至少一轮完整测试，多条内存时逐条排查。"),
                QStringLiteral("检查供电与温度：电源功率不足与散热不良都会导致不可纠正错误。"),
                QStringLiteral("更新主板 BIOS/UEFI 与芯片组微码；系统事件日志里的 WHEA-Logger 记录能补充更多细节。"),
            };
        case 0x000000EFu:
        case 0x000000F4u:
            return {
                QStringLiteral("关键进程退出通常是被外力终止或自身初始化失败：先看系统事件日志中同一时刻的应用程序错误。"),
                QStringLiteral("运行 sfc /scannow 与 DISM /Online /Cleanup-Image /RestoreHealth 修复系统文件。"),
                QStringLiteral("排查安全软件与第三方 LSA/凭据提供程序，它们注入关键进程后崩溃会直接导致本停止码。"),
            };
        case 0x000000C4u:
            return {
                QStringLiteral("这是驱动验证器主动抓到的违规，说明目标驱动确实违反了规则，可信度很高。"),
                QStringLiteral("参数 1 的子类型直接对应违反的检查项，据此定位代码位置。"),
                QStringLiteral("排查完毕后记得关闭验证器：verifier /reset，否则系统会持续处于低性能状态。"),
            };
        case 0x000000C2u:
        case 0x00000019u:
            return {
                QStringLiteral("池损坏的崩溃点离真正的越界写很远：开启驱动验证器的特殊池能把现场提前到越界那一刻。"),
                QStringLiteral("参数 1 的违规类型说明了是重复释放、标记不符还是释放了非池地址，方向完全不同。"),
            };
        case 0x00000109u:
            return {
                QStringLiteral("PatchGuard 报错说明内核关键结构被修改：优先排查带内核驱动的安全软件、外挂与虚拟化工具。"),
                QStringLiteral("该停止码也可能由内存故障导致的随机比特翻转触发，排除软件后再测内存。"),
            };
        case 0x000000E2u:
        case 0x000001C8u:
            return {
                QStringLiteral("这是人为触发的转储，不是系统故障，无需排查稳定性问题。"),
            };
        case 0x00000116u:
        case 0x00000117u:
        case 0x000000EAu:
            return {
                QStringLiteral("参数 2 指向出错的显示驱动模块：先干净安装显卡驱动（用 DDU 彻底卸载后再装）。"),
                QStringLiteral("取消显卡超频与降压曲线，恢复默认频率再观察。"),
                QStringLiteral("检查供电与显卡温度；多屏、高刷新率与自定义分辨率也会诱发 TDR。"),
            };
        case 0x0000007Au:
        case 0x00000077u:
            return {
                QStringLiteral("参数 2 的 NTSTATUS 指明了具体的 I/O 失败原因，先看它。"),
                QStringLiteral("用 chkdsk 与厂商工具检查磁盘健康（SMART 的重分配扇区计数是关键指标）。"),
                QStringLiteral("更新存储控制器驱动；NVMe 固态盘还要检查固件版本。"),
            };
        case 0x0000009Fu:
            return {
                QStringLiteral("参数 1 为 3 时，参数 4 指向被阻塞的电源 IRP，顺着它能找到卡住的设备栈。"),
                QStringLiteral("常见肇事者是网卡、USB 控制器与显卡驱动：先更新这几类驱动。"),
                QStringLiteral("临时禁用快速启动与混合睡眠，可判断是否为休眠路径特有的问题。"),
            };
        case 0x0000007Fu:
            return {
                QStringLiteral("参数 1 为 0x8（双重错误）时最常见的原因是内核栈溢出：查调用栈里是否有深度递归的驱动。"),
                QStringLiteral("参数 1 为 0xD（一般保护错误）时，多为访问了非规范地址，指针被破坏。"),
                QStringLiteral("参数 1 为 0x2（NMI）时按硬件方向排查。"),
            };
        case 0x00000139u:
            return {
                QStringLiteral("参数 1 的子类型直接说明了破坏形式（链表损坏 / 栈 cookie / 数组越界），先看它。"),
                QStringLiteral("子类型为 3（LIST_ENTRY 损坏）时，通常是某个驱动释放对象后没有摘链，用驱动验证器复现。"),
            };
        default:
            break;
        }

        // 归类级通用建议：没有专属条目时至少给出正确的排查方向。
        switch (BugCheckCategoryOf(code))
        {
        case BugCheckCategory::Driver:
            return {
                QStringLiteral("先看“肇事模块候选”：第一名是第三方驱动时，优先更新、回滚或临时卸载它；"
                    "第一名是系统模块或候选为空时，说明证据还不足以定位到某个驱动，别急着动它。"),
                QStringLiteral("对可疑驱动启用驱动验证器（verifier /standard /driver 名称.sys）复现，能大幅提前故障现场。"),
                QStringLiteral("收集多份转储做交叉比对：反复出现同一个第三方驱动才算定案。"),
            };
        case BugCheckCategory::Memory:
            return {
                QStringLiteral("先用 MemTest86 做一轮完整内存测试，排除物理内存故障。"),
                QStringLiteral("取消内存超频与 XMP/EXPO 配置，恢复 JEDEC 默认频率再观察。"),
                QStringLiteral("排除硬件后，用驱动验证器的特殊池定位越界写的驱动。"),
            };
        case BugCheckCategory::Hardware:
            return {
                QStringLiteral("恢复所有默认频率与电压，取消超频。"),
                QStringLiteral("检查内存、电源与散热；查看系统事件日志中的 WHEA-Logger 记录。"),
                QStringLiteral("更新 BIOS/UEFI 与芯片组驱动。"),
            };
        case BugCheckCategory::FileSystem:
            return {
                QStringLiteral("用 chkdsk 检查目标卷，并查看磁盘 SMART 健康状态。"),
                QStringLiteral("排查文件系统过滤驱动（杀软、备份、加密、虚拟磁盘），逐个临时卸载验证。"),
            };
        case BugCheckCategory::Power:
            return {
                QStringLiteral("更新网卡、USB 与显卡驱动，这三类最常在睡眠/唤醒路径出问题。"),
                QStringLiteral("临时关闭快速启动与休眠，判断是否为特定电源路径的问题。"),
            };
        case BugCheckCategory::Graphics:
            return {
                QStringLiteral("用 DDU 彻底卸载后重新安装显卡驱动。"),
                QStringLiteral("取消显卡超频/降压，恢复默认设置。"),
            };
        case BugCheckCategory::Watchdog:
            return {
                QStringLiteral("看调用栈里出现的第三方驱动：存储、网络与虚拟化驱动是常见肇事者。"),
                QStringLiteral("虚拟机环境下先排除宿主机的存储卡顿与 CPU 超配。"),
            };
        case BugCheckCategory::Security:
            return {
                QStringLiteral("排查带内核驱动的安全软件、虚拟化工具与外挂类程序。"),
                QStringLiteral("排除软件后测内存：随机比特翻转同样会触发内核安全检查。"),
            };
        case BugCheckCategory::Boot:
            return {
                QStringLiteral("这是启动阶段的失败：核对最近的驱动/系统更新，必要时用最后一次正确配置或安全模式回退。"),
                QStringLiteral("运行 sfc /scannow 与 DISM 修复系统文件。"),
            };
        case BugCheckCategory::UserInitiated:
            return { QStringLiteral("人为触发的转储，无需排查稳定性问题。") };
        default:
            return {
                QStringLiteral("先看“肇事模块候选”与调用栈里出现的第三方模块。"),
                QStringLiteral("收集多份转储交叉比对，反复出现的模块才是可靠线索。"),
            };
        }
    }
}
