#pragma once

// ============================================================
// MinidumpCodeText.h
// 作用：
// - 集中提供转储解析所需的“数值 → 可读文本”释义表；
// - 覆盖 NTSTATUS 异常码、内核 BugCheck（蓝屏）代码、CPU 架构、
//   内存状态/保护位与 MDMP 流类型名；
// - 返回的均为中文规范文本（或原样英文常量名），渲染层再按语言包翻译。
// 调用方式：
// - MinidumpParser/KernelDumpParser 在拼装模型时调用；
// - 查不到的数值一律返回空串或“未知”，由调用方决定兜底格式。
// ============================================================

#include <QString>

#include <cstdint>

namespace ks::minidump
{
    // ExceptionCodeName 作用：返回 NTSTATUS 异常码的常量名（如 EXCEPTION_ACCESS_VIOLATION）。
    // 传入异常码 code；返回常量名，未知时返回空串。
    QString ExceptionCodeName(std::uint32_t code);

    // ExceptionCodeMeaning 作用：返回异常码的中文含义说明。
    // 传入异常码 code；返回中文说明，未知时返回空串。
    QString ExceptionCodeMeaning(std::uint32_t code);

    // AccessViolationDetailText 作用：把访问违例/页错误的两个参数翻译成
    // “读/写/执行 地址”的中文描述（参数含义见 EXCEPTION_RECORD 文档）。
    // 传入 operationType（0 读/1 写/8 DEP 执行）与 faultAddress 出错地址；返回中文描述。
    QString AccessViolationDetailText(std::uint64_t operationType, std::uint64_t faultAddress);

    // FastFailCodeText 作用：把 __fastfail 子码翻译成中文说明。
    // STATUS_STACK_BUFFER_OVERRUN(0xC0000409) 的参数 1 就是这个子码，
    // 它才是真正说明“触发了哪条安全检查”的信息，异常码本身反而没什么区分度。
    // 传入 code 子码；未收录时返回空串。
    QString FastFailCodeText(std::uint64_t code);

    // CppExceptionMagicText 作用：识别 MSVC C++ 异常（0xE06D7363）的魔数版本。
    // 传入 magic 参数 1 的值；不是已知魔数时返回空串。
    QString CppExceptionMagicText(std::uint64_t magic);

    // IsCppException 作用：判断异常码是否为 MSVC C++ 异常（'msc' + 0xE0000000）。
    bool IsCppException(std::uint32_t code);

    // IsManagedException 作用：判断异常码是否来自 .NET 运行时。
    bool IsManagedException(std::uint32_t code);



    // ProcessorArchitectureText 作用：把 SYSTEM_INFO 的架构编号转成可读文本。
    // 传入 PROCESSOR_ARCHITECTURE_* 编号；返回 x86/x64/ARM64 等文本，未知时返回编号文本。
    QString ProcessorArchitectureText(std::uint16_t architecture);

    // StreamTypeName 作用：返回 MDMP 流类型编号对应的官方枚举名。
    // 传入流类型编号 streamType；返回枚举名，未知时返回空串。
    QString StreamTypeName(std::uint32_t streamType);

    // StreamTypeNote 作用：返回流承载内容的一句中文说明。
    // 传入流类型编号 streamType；返回中文说明，未知时返回空串。
    QString StreamTypeNote(std::uint32_t streamType);

    // MemoryStateText 作用：把 MEM_COMMIT 等状态位转成常量名文本。
    // 传入 state 状态值；返回常量名，未知时返回十六进制文本。
    QString MemoryStateText(std::uint32_t state);

    // MemoryProtectText 作用：把 PAGE_* 保护位组合转成常量名文本（含修饰位）。
    // 传入 protect 保护值；返回组合文本，0 时返回空串。
    QString MemoryProtectText(std::uint32_t protect);

    // MemoryTypeText 作用：把 MEM_IMAGE/MAPPED/PRIVATE 类型位转成常量名文本。
    // 传入 type 类型值；返回常量名，未知时返回十六进制文本。
    QString MemoryTypeText(std::uint32_t type);
}
