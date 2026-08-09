#pragma once

// ============================================================
// DumpContextRegisters.h
// 作用：
// - 按 CPU 架构从转储里的 CONTEXT 结构提取完整寄存器快照；
// - 用户态 MDMP 的 CONTEXT 由 MINIDUMP_LOCATION_DESCRIPTOR 指向，
//   内核转储的 CONTEXT 位于 DUMP_HEADER64 固定偏移，两者共用本模块；
// - 每个寄存器值都过一遍 ModuleIndex，命中模块时标注“模块名+偏移”，
//   命中哨兵值时标注“未初始化/已释放”，这是判断崩溃根因的关键线索
//   （例如 Rcx 是 0xFFFFFFFFFFFFFFFF 往往说明取到了失效对象指针）。
// 布局来源：
// - 各架构 CONTEXT 偏移取自官方 winnt.h 公开定义，并在实现文件里
//   用 static_assert 对本机架构自检。
// 调用方式：
// - 解析器拿到 CONTEXT 的文件偏移与长度后调用 ReadContextRegisters。
// ============================================================

#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"

namespace ks::minidump
{
    // ContextArch：本模块支持的 CONTEXT 布局类别。
    enum class ContextArch
    {
        Unknown, // Unknown：不支持的架构，所有读取都会失败。
        X86,     // X86：32 位 x86 CONTEXT（0x2CC 字节）。
        Amd64,   // Amd64：x64 CONTEXT（0x4D0 字节）。
        Arm64,   // Arm64：ARM64 CONTEXT（0x390 字节）。
    };

    // ContextArchFromProcessorArchitecture 作用：把 SYSTEM_INFO 的
    // PROCESSOR_ARCHITECTURE_* 编号映射成本模块的 ContextArch。
    // 传入 architecture 编号；无法识别时返回 Unknown。
    ContextArch ContextArchFromProcessorArchitecture(std::uint16_t architecture);

    // ContextArchFromMachineImageType 作用：把 PE 机器类型（内核转储头
    // 的 MachineImageType 字段）映射成本模块的 ContextArch。
    // 传入 machineType（0x014C/0x8664/0xAA64）；无法识别时返回 Unknown。
    ContextArch ContextArchFromMachineImageType(std::uint32_t machineType);

    // ContextPointerSize 作用：返回该架构的指针宽度（4 或 8）。
    // 传入 arch；Unknown 时返回 8。
    std::uint32_t ContextPointerSize(ContextArch arch);

    // ContextMinimumBytes 作用：返回读取通用寄存器所需的最小 CONTEXT 长度。
    // 传入 arch；Unknown 时返回 0。用于在解析前校验流长度是否够。
    std::uint64_t ContextMinimumBytes(ContextArch arch);

    // ReadContextPointers 作用：只取指令指针、栈指针与帧指针三个关键值。
    // 传入 view、contextOffset CONTEXT 在文件内的偏移、contextBytes 可用长度、
    // arch 架构，以及三个输出指针（允许为 nullptr）；全部读取成功才返回 true。
    bool ReadContextPointers(
        const DumpFileView& view,
        std::uint64_t contextOffset,
        std::uint64_t contextBytes,
        ContextArch arch,
        std::uint64_t* instructionPointerOut,
        std::uint64_t* stackPointerOut,
        std::uint64_t* framePointerOut);

    // ReadContextRegisters 作用：提取完整寄存器快照并逐个加注解。
    // 传入 view、contextOffset、contextBytes、arch、threadId 所属线程、
    // modules 模块索引（用于把寄存器值翻译成“模块名+偏移”）；
    // 返回按架构自然顺序排列的寄存器数组，长度不足时返回空数组。
    std::vector<RegisterEntry> ReadContextRegisters(
        const DumpFileView& view,
        std::uint64_t contextOffset,
        std::uint64_t contextBytes,
        ContextArch arch,
        std::uint32_t threadId,
        const ModuleIndex& modules);

    // EFlagsText 作用：把 x86/x64 的 EFlags 拆成置位标志名列表。
    // 传入 eflags 值；返回如 "0x10246 (PF ZF IF)" 的文本。
    QString EFlagsText(std::uint32_t eflags);
}
