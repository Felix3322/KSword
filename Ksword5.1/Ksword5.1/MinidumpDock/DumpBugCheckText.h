#pragma once

// ============================================================
// DumpBugCheckText.h
// 作用：
// - 内核 BugCheck（蓝屏停止码）的全部释义能力，集中在这一个模块：
//   停止码名称与含义、故障归类、四个参数的逐项带值解读、
//   各停止码专有的参数子类型表，以及面向使用者的排查建议；
// - 与 MinidumpCodeText.h 的分工：那里放用户态异常码与内存/流等
//   通用释义，这里只放内核蓝屏相关的表，避免单文件膨胀到不可维护。
// - “逐项带值解读”是本模块存在的理由：光给一段静态的参数说明
//   （参数 1 是地址、参数 2 是 IRQL…）没有价值，必须把实际数值
//   翻译出来——地址归到哪个驱动、IRQL 是几级、访问类型是读还是写、
//   NTSTATUS 具体是哪个异常，才能直接指向根因。
// 调用方式：
// - KernelDumpParser 解析出停止码与四个参数后，连同 ModuleIndex
//   一起交给 DescribeBugCheckParameters；
// - DumpAnalyzer 用 BugCheckCategoryOf/BugCheckSuggestions 生成结论。
// ============================================================

#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"

namespace ks::minidump
{
    // BugCheckCategory：停止码的故障归类，决定给出哪一类排查建议。
    enum class BugCheckCategory
    {
        Unknown,     // Unknown：未归类。
        Driver,      // Driver：驱动缺陷（越界、释放后使用、IRQL 违规等）。
        Memory,      // Memory：内存管理器/池一致性错误，可能是驱动破坏也可能是物理内存故障。
        Hardware,    // Hardware：硬件报告的错误（WHEA、机器检查、总线错误）。
        FileSystem,  // FileSystem：文件系统或存储栈错误。
        Power,       // Power：电源状态切换相关。
        Graphics,    // Graphics：显示驱动 / TDR。
        Watchdog,    // Watchdog：看门狗超时（DPC、时钟、PDC）。
        Security,    // Security：内核安全检查 / PatchGuard。
        Software,    // Software：关键系统进程或组件异常退出。
        Boot,        // Boot：启动阶段初始化失败。
        UserInitiated, // UserInitiated：人为触发的崩溃转储。
    };

    // BugCheckParameterInfo：某个 BugCheck 参数的完整解读。
    struct BugCheckParameterInfo
    {
        QString label;  // label：中文参数名（如“被访问的内存地址”），未知时为空。
        QString value;  // value：参数的十六进制文本。
        QString detail; // detail：结合数值给出的解读（模块归属、IRQL 名、异常码名…）。
    };

    // BugCheckCodeNameEx 作用：返回停止码的官方名称。
    // 传入 code 停止码；未收录时返回空串。
    QString BugCheckCodeNameEx(std::uint32_t code);

    // BugCheckMeaning 作用：返回停止码的中文含义说明。
    // 传入 code 停止码；未收录时返回空串。
    QString BugCheckMeaning(std::uint32_t code);

    // BugCheckCategoryOf 作用：返回停止码的故障归类。
    // 传入 code 停止码；未收录时返回 Unknown。
    BugCheckCategory BugCheckCategoryOf(std::uint32_t code);

    // BugCheckCategoryText 作用：把故障归类转成中文文本。
    // 传入 category；Unknown 时返回“未归类”。
    QString BugCheckCategoryText(BugCheckCategory category);

    // DescribeBugCheckParameters 作用：把四个参数逐项翻译成可读解读。
    // 传入 code 停止码、parameters 四个参数、modules 模块索引（用于地址归属）、
    // pointerSize 指针宽度；返回恒为 4 项的解读数组，未知语义时 label 为空。
    std::vector<BugCheckParameterInfo> DescribeBugCheckParameters(
        std::uint32_t code,
        const std::uint64_t parameters[4],
        const ModuleIndex& modules,
        std::uint32_t pointerSize);

    // BugCheckSuggestions 作用：给出该停止码对应的排查建议。
    // 传入 code 停止码；返回若干条中文建议，未收录时返回归类级通用建议。
    QStringList BugCheckSuggestions(std::uint32_t code);

    // FaultingAddressFromBugCheck 作用：从参数里挑出“出错指令地址”。
    // 不同停止码把指令地址放在不同参数位（0xD1 在参数 4、0x50 在参数 3、
    // 0x7E 在参数 2…），归因分析要靠它锁定肇事模块。
    // 传入 code 与四个参数；没有该语义的停止码返回 0。
    std::uint64_t FaultingAddressFromBugCheck(
        std::uint32_t code,
        const std::uint64_t parameters[4]);

    // NestedStatusFromBugCheck 作用：从参数里挑出“嵌套的 NTSTATUS 异常码”。
    // 0x1E/0x7E/0x3B/0x8E 这类停止码本身只是“未处理”，真正的原因是参数里
    // 那个 NTSTATUS。传入 code 与四个参数；没有该语义时返回 0。
    std::uint32_t NestedStatusFromBugCheck(
        std::uint32_t code,
        const std::uint64_t parameters[4]);

    // IrqlText 作用：把 IRQL 数值转成级别名。
    // 传入 irql 数值；返回如 “2 (DISPATCH_LEVEL)”。
    QString IrqlText(std::uint64_t irql);

    // MemoryAccessTypeText 作用：把“读/写/执行”类型码转成中文。
    // 传入 accessType（0 读 / 1 写 / 8 或 10 执行）；返回中文描述。
    QString MemoryAccessTypeText(std::uint64_t accessType);

    // ===== 以下为各停止码专有的参数子类型表 =====

    // MemoryManagementSubcodeText 作用：0x1A MEMORY_MANAGEMENT 参数 1 子码。
    QString MemoryManagementSubcodeText(std::uint64_t subcode);

    // BadPoolCallerText 作用：0xC2 BAD_POOL_CALLER 参数 1 池违规类型。
    QString BadPoolCallerText(std::uint64_t violationType);

    // DriverVerifierViolationText 作用：0xC4 驱动验证器违规子类型。
    QString DriverVerifierViolationText(std::uint64_t subtype);

    // KernelSecurityCheckText 作用：0x139 内核安全检查失败子类型。
    QString KernelSecurityCheckText(std::uint64_t subtype);

    // KernelTrapText 作用：0x7F UNEXPECTED_KERNEL_MODE_TRAP 参数 1 陷阱号。
    QString KernelTrapText(std::uint64_t trapNumber);

    // WheaErrorSourceText 作用：0x124 WHEA 参数 1 错误源类型。
    QString WheaErrorSourceText(std::uint64_t sourceType);

    // DpcWatchdogText 作用：0x133 DPC_WATCHDOG_VIOLATION 参数 1 子类型。
    QString DpcWatchdogText(std::uint64_t subtype);

    // PowerStateFailureText 作用：0x9F DRIVER_POWER_STATE_FAILURE 参数 1 子类型。
    QString PowerStateFailureText(std::uint64_t subtype);

    // PatchGuardRegionText 作用：0x109 CRITICAL_STRUCTURE_CORRUPTION 参数 4 区域号。
    QString PatchGuardRegionText(std::uint64_t region);

    // PnpFatalErrorText 作用：0xCA PNP_DETECTED_FATAL_ERROR 参数 1 子码。
    QString PnpFatalErrorText(std::uint64_t subcode);
}
