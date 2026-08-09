// ============================================================
// DumpContextRegisters.cpp
// 作用：
// - 实现 DumpContextRegisters.h 声明的 CONTEXT 寄存器提取；
// - 每个架构用一张 { 寄存器名, 偏移, 宽度 } 静态表描述布局，
//   读取逻辑与架构无关，新增架构只要加一张表；
// - 偏移取自官方 winnt.h，并在本文件里对编译目标架构做 static_assert
//   自检：本机是 x64 时会真正校验 x64 那张表的关键偏移。
// ============================================================

#include "DumpContextRegisters.h"

#include <windows.h>

#include <cstddef>
#include <cstring>

namespace ks::minidump
{
    namespace
    {
        // RegisterSlot：CONTEXT 里一个寄存器的位置描述。
        struct RegisterSlot
        {
            const char* name;      // name：寄存器名（英文原文，不翻译）。
            std::uint32_t offset;  // offset：在 CONTEXT 结构内的字节偏移。
            std::uint32_t width;   // width：字节宽度（2/4/8）。
        };

        // kAmd64Registers：x64 CONTEXT 的通用寄存器与关键状态字段。
        // 顺序按排查习惯排列：先 Rip/Rsp/Rbp，再通用寄存器，最后状态位。
        constexpr RegisterSlot kAmd64Registers[] = {
            { "Rip", 0xF8, 8 },
            { "Rsp", 0x98, 8 },
            { "Rbp", 0xA0, 8 },
            { "Rax", 0x78, 8 },
            { "Rbx", 0x90, 8 },
            { "Rcx", 0x80, 8 },
            { "Rdx", 0x88, 8 },
            { "Rsi", 0xA8, 8 },
            { "Rdi", 0xB0, 8 },
            { "R8",  0xB8, 8 },
            { "R9",  0xC0, 8 },
            { "R10", 0xC8, 8 },
            { "R11", 0xD0, 8 },
            { "R12", 0xD8, 8 },
            { "R13", 0xE0, 8 },
            { "R14", 0xE8, 8 },
            { "R15", 0xF0, 8 },
            { "EFlags", 0x44, 4 },
            { "SegCs", 0x38, 2 },
            { "SegSs", 0x42, 2 },
            { "SegDs", 0x3A, 2 },
            { "SegEs", 0x3C, 2 },
            { "SegFs", 0x3E, 2 },
            { "SegGs", 0x40, 2 },
            { "MxCsr", 0x34, 4 },
            { "ContextFlags", 0x30, 4 },
        };

        // kX86Registers：32 位 x86 CONTEXT 的通用寄存器与关键状态字段。
        constexpr RegisterSlot kX86Registers[] = {
            { "Eip", 0xB8, 4 },
            { "Esp", 0xC4, 4 },
            { "Ebp", 0xB4, 4 },
            { "Eax", 0xB0, 4 },
            { "Ebx", 0xA4, 4 },
            { "Ecx", 0xAC, 4 },
            { "Edx", 0xA8, 4 },
            { "Esi", 0xA0, 4 },
            { "Edi", 0x9C, 4 },
            { "EFlags", 0xC0, 4 },
            { "SegCs", 0xBC, 4 },
            { "SegSs", 0xC8, 4 },
            { "SegDs", 0x98, 4 },
            { "SegEs", 0x94, 4 },
            { "SegFs", 0x90, 4 },
            { "SegGs", 0x8C, 4 },
            { "ContextFlags", 0x00, 4 },
        };

        // kArm64Registers：ARM64 CONTEXT 的通用寄存器。
        // X0..X28 连续排列，X29/X30 在结构里另有 Fp/Lr 别名。
        constexpr RegisterSlot kArm64Registers[] = {
            { "Pc",  0x108, 8 },
            { "Sp",  0x100, 8 },
            { "Fp",  0x0F0, 8 },
            { "Lr",  0x0F8, 8 },
            { "X0",  0x008, 8 },
            { "X1",  0x010, 8 },
            { "X2",  0x018, 8 },
            { "X3",  0x020, 8 },
            { "X4",  0x028, 8 },
            { "X5",  0x030, 8 },
            { "X6",  0x038, 8 },
            { "X7",  0x040, 8 },
            { "X8",  0x048, 8 },
            { "X9",  0x050, 8 },
            { "X10", 0x058, 8 },
            { "X11", 0x060, 8 },
            { "X12", 0x068, 8 },
            { "X13", 0x070, 8 },
            { "X14", 0x078, 8 },
            { "X15", 0x080, 8 },
            { "X16", 0x088, 8 },
            { "X17", 0x090, 8 },
            { "X18", 0x098, 8 },
            { "X19", 0x0A0, 8 },
            { "X20", 0x0A8, 8 },
            { "X21", 0x0B0, 8 },
            { "X22", 0x0B8, 8 },
            { "X23", 0x0C0, 8 },
            { "X24", 0x0C8, 8 },
            { "X25", 0x0D0, 8 },
            { "X26", 0x0D8, 8 },
            { "X27", 0x0E0, 8 },
            { "X28", 0x0E8, 8 },
            { "Cpsr", 0x004, 4 },
            { "ContextFlags", 0x000, 4 },
        };

#if defined(_M_X64)
        // 本机是 x64：直接用编译器的 CONTEXT 定义校验表里的关键偏移。
        static_assert(offsetof(CONTEXT, Rip) == 0xF8, "x64 CONTEXT.Rip 偏移必须是 0xF8");
        static_assert(offsetof(CONTEXT, Rsp) == 0x98, "x64 CONTEXT.Rsp 偏移必须是 0x98");
        static_assert(offsetof(CONTEXT, Rbp) == 0xA0, "x64 CONTEXT.Rbp 偏移必须是 0xA0");
        static_assert(offsetof(CONTEXT, Rax) == 0x78, "x64 CONTEXT.Rax 偏移必须是 0x78");
        static_assert(offsetof(CONTEXT, R15) == 0xF0, "x64 CONTEXT.R15 偏移必须是 0xF0");
        static_assert(offsetof(CONTEXT, EFlags) == 0x44, "x64 CONTEXT.EFlags 偏移必须是 0x44");
        static_assert(offsetof(CONTEXT, SegCs) == 0x38, "x64 CONTEXT.SegCs 偏移必须是 0x38");
        static_assert(offsetof(CONTEXT, MxCsr) == 0x34, "x64 CONTEXT.MxCsr 偏移必须是 0x34");
#elif defined(_M_IX86)
        // 本机是 x86：校验 x86 那张表。
        static_assert(offsetof(CONTEXT, Eip) == 0xB8, "x86 CONTEXT.Eip 偏移必须是 0xB8");
        static_assert(offsetof(CONTEXT, Esp) == 0xC4, "x86 CONTEXT.Esp 偏移必须是 0xC4");
        static_assert(offsetof(CONTEXT, Ebp) == 0xB4, "x86 CONTEXT.Ebp 偏移必须是 0xB4");
        static_assert(offsetof(CONTEXT, Eax) == 0xB0, "x86 CONTEXT.Eax 偏移必须是 0xB0");
        static_assert(offsetof(CONTEXT, EFlags) == 0xC0, "x86 CONTEXT.EFlags 偏移必须是 0xC0");
#elif defined(_M_ARM64)
        // 本机是 ARM64：校验 ARM64 那张表。
        static_assert(offsetof(CONTEXT, Pc) == 0x108, "ARM64 CONTEXT.Pc 偏移必须是 0x108");
        static_assert(offsetof(CONTEXT, Sp) == 0x100, "ARM64 CONTEXT.Sp 偏移必须是 0x100");
        static_assert(offsetof(CONTEXT, Cpsr) == 0x04, "ARM64 CONTEXT.Cpsr 偏移必须是 0x04");
#endif

        // FlagBit：EFlags 里一个标志位与它的助记符。
        struct FlagBit
        {
            std::uint32_t bit;  // bit：标志位掩码。
            const char* name;   // name：Intel 手册里的助记符。
        };

        // kEFlagsBits：EFlags 常用标志位；只列排查时真正有用的几个。
        constexpr FlagBit kEFlagsBits[] = {
            { 0x00000001u, "CF" }, // 进位
            { 0x00000004u, "PF" }, // 奇偶
            { 0x00000010u, "AF" }, // 辅助进位
            { 0x00000040u, "ZF" }, // 结果为零
            { 0x00000080u, "SF" }, // 符号
            { 0x00000100u, "TF" }, // 单步陷阱
            { 0x00000200u, "IF" }, // 中断使能
            { 0x00000400u, "DF" }, // 方向
            { 0x00000800u, "OF" }, // 溢出
            { 0x00010000u, "RF" }, // 恢复
            { 0x00020000u, "VM" }, // 虚拟 8086
            { 0x00040000u, "AC" }, // 对齐检查
        };

        // ReadSlot 作用：按 RegisterSlot 描述读出一个寄存器的值。
        // 传入 view、contextOffset、slot 与输出指针；越界时返回 false。
        bool ReadSlot(
            const DumpFileView& view,
            const std::uint64_t contextOffset,
            const RegisterSlot& slot,
            std::uint64_t* const valueOut)
        {
            const std::uint64_t offset = contextOffset + slot.offset;
            switch (slot.width)
            {
            case 2:
            {
                std::uint16_t value16 = 0;
                if (!view.readStruct(offset, &value16))
                {
                    return false;
                }
                *valueOut = value16;
                return true;
            }
            case 4:
            {
                std::uint32_t value32 = 0;
                if (!view.readStruct(offset, &value32))
                {
                    return false;
                }
                *valueOut = value32;
                return true;
            }
            default:
                return view.readStruct(offset, valueOut);
            }
        }

        // SlotTable 作用：返回目标架构的寄存器表与表长。
        // 传入 arch 与输出的表长；不支持的架构返回 nullptr。
        // 注意：本文件里接收返回值的局部变量一律不能叫 slots——
        // Qt 在 qobjectdefs.h 里把 slots 定义成了空宏，用作标识符会被直接吃掉。
        const RegisterSlot* SlotTable(const ContextArch arch, std::size_t* const countOut)
        {
            switch (arch)
            {
            case ContextArch::Amd64:
                *countOut = sizeof(kAmd64Registers) / sizeof(kAmd64Registers[0]);
                return kAmd64Registers;
            case ContextArch::X86:
                *countOut = sizeof(kX86Registers) / sizeof(kX86Registers[0]);
                return kX86Registers;
            case ContextArch::Arm64:
                *countOut = sizeof(kArm64Registers) / sizeof(kArm64Registers[0]);
                return kArm64Registers;
            default:
                *countOut = 0;
                return nullptr;
            }
        }

        // PointerSlots 作用：返回目标架构里 IP/SP/FP 三个寄存器的名字。
        // 传入 arch 与三个输出指针；不支持的架构全部置空。
        void PointerSlots(
            const ContextArch arch,
            const char** const ipName,
            const char** const spName,
            const char** const fpName)
        {
            switch (arch)
            {
            case ContextArch::Amd64: *ipName = "Rip"; *spName = "Rsp"; *fpName = "Rbp"; break;
            case ContextArch::X86:   *ipName = "Eip"; *spName = "Esp"; *fpName = "Ebp"; break;
            case ContextArch::Arm64: *ipName = "Pc";  *spName = "Sp";  *fpName = "Fp";  break;
            default:                 *ipName = nullptr; *spName = nullptr; *fpName = nullptr; break;
            }
        }
    }

    ContextArch ContextArchFromProcessorArchitecture(const std::uint16_t architecture)
    {
        // 编号来自 PROCESSOR_ARCHITECTURE_* 常量族。
        switch (architecture)
        {
        case 0:  return ContextArch::X86;   // PROCESSOR_ARCHITECTURE_INTEL
        case 9:  return ContextArch::Amd64; // PROCESSOR_ARCHITECTURE_AMD64
        case 12: return ContextArch::Arm64; // PROCESSOR_ARCHITECTURE_ARM64
        default: return ContextArch::Unknown;
        }
    }

    ContextArch ContextArchFromMachineImageType(const std::uint32_t machineType)
    {
        switch (machineType)
        {
        case 0x014C: return ContextArch::X86;
        case 0x8664: return ContextArch::Amd64;
        case 0xAA64: return ContextArch::Arm64;
        default:     return ContextArch::Unknown;
        }
    }

    std::uint32_t ContextPointerSize(const ContextArch arch)
    {
        return arch == ContextArch::X86 ? 4u : 8u;
    }

    std::uint64_t ContextMinimumBytes(const ContextArch arch)
    {
        // 只要求覆盖到通用寄存器区的末尾，不强求整个 CONTEXT 都在。
        switch (arch)
        {
        case ContextArch::Amd64: return 0x100; // 覆盖到 Rip(0xF8)+8
        case ContextArch::X86:   return 0x0CC; // 覆盖到 SegSs(0xC8)+4
        case ContextArch::Arm64: return 0x110; // 覆盖到 Pc(0x108)+8
        default:                 return 0;
        }
    }

    QString EFlagsText(const std::uint32_t eflags)
    {
        // names：置位的标志助记符，按 Intel 手册顺序排列。
        QStringList names;
        for (const FlagBit& flag : kEFlagsBits)
        {
            if ((eflags & flag.bit) != 0)
            {
                names.append(QString::fromLatin1(flag.name));
            }
        }
        // iopl：I/O 特权级（位 12-13），内核态排查偶尔用得到。
        const std::uint32_t iopl = (eflags >> 12) & 0x3u;
        QString text = QStringLiteral("0x%1").arg(QString::number(eflags, 16).toUpper());
        if (!names.isEmpty())
        {
            text += QStringLiteral(" (%1)").arg(names.join(QLatin1Char(' ')));
        }
        if (iopl != 0)
        {
            text += QStringLiteral(" IOPL=%1").arg(iopl);
        }
        return text;
    }

    bool ReadContextPointers(
        const DumpFileView& view,
        const std::uint64_t contextOffset,
        const std::uint64_t contextBytes,
        const ContextArch arch,
        std::uint64_t* const instructionPointerOut,
        std::uint64_t* const stackPointerOut,
        std::uint64_t* const framePointerOut)
    {
        std::size_t slotCount = 0;
        const RegisterSlot* const slotTable = SlotTable(arch, &slotCount);
        if (slotTable == nullptr || contextBytes < ContextMinimumBytes(arch))
        {
            return false;
        }
        // ipName/spName/fpName：目标架构里三个关键寄存器的名字。
        const char* ipName = nullptr;
        const char* spName = nullptr;
        const char* fpName = nullptr;
        PointerSlots(arch, &ipName, &spName, &fpName);

        bool allRead = true;
        for (std::size_t index = 0; index < slotCount; ++index)
        {
            const RegisterSlot& slot = slotTable[index];
            std::uint64_t* target = nullptr;
            if (ipName != nullptr && std::strcmp(slot.name, ipName) == 0)
            {
                target = instructionPointerOut;
            }
            else if (spName != nullptr && std::strcmp(slot.name, spName) == 0)
            {
                target = stackPointerOut;
            }
            else if (fpName != nullptr && std::strcmp(slot.name, fpName) == 0)
            {
                target = framePointerOut;
            }
            if (target == nullptr)
            {
                continue;
            }
            if (!ReadSlot(view, contextOffset, slot, target))
            {
                allRead = false;
            }
        }
        return allRead;
    }

    std::vector<RegisterEntry> ReadContextRegisters(
        const DumpFileView& view,
        const std::uint64_t contextOffset,
        const std::uint64_t contextBytes,
        const ContextArch arch,
        const std::uint32_t threadId,
        const ModuleIndex& modules)
    {
        // registers：产出的寄存器快照；架构不支持或长度不足时为空。
        std::vector<RegisterEntry> registers;
        std::size_t slotCount = 0;
        const RegisterSlot* const slotTable = SlotTable(arch, &slotCount);
        if (slotTable == nullptr || contextBytes < ContextMinimumBytes(arch))
        {
            return registers;
        }
        registers.reserve(slotCount);
        for (std::size_t index = 0; index < slotCount; ++index)
        {
            const RegisterSlot& slot = slotTable[index];
            std::uint64_t value = 0;
            if (!ReadSlot(view, contextOffset, slot, &value))
            {
                continue;
            }
            RegisterEntry entry{};
            entry.threadId = threadId;
            entry.name = QString::fromLatin1(slot.name);
            entry.value = value;
            // EFlags 用标志助记符展开；其余寄存器按地址解读加注解。
            // 判据必须用「本架构的指针宽度」而不是「槽位宽度是 8」——
            // x86 的通用寄存器全是 4 字节，按后者判会让 32 位转储的寄存器表
            // 一条注解都没有，与头文件里“每个寄存器值都过一遍 ModuleIndex”的承诺不符。
            // 段寄存器（2 或 4 字节且不是通用寄存器）不该被当地址解读，
            // 因此这里要求槽位宽度恰好等于指针宽度。
            const std::uint32_t pointerSize = ContextPointerSize(arch);
            if (entry.name == QLatin1String("EFlags"))
            {
                entry.note = EFlagsText(static_cast<std::uint32_t>(value));
            }
            else if (slot.width == pointerSize && value != 0 &&
                     entry.name != QLatin1String("ContextFlags"))
            {
                entry.note = modules.annotate(value);
            }
            registers.push_back(std::move(entry));
        }
        return registers;
    }
}
