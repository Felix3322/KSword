// ============================================================
// DumpStackWalker.cpp
// 作用：
// - 实现 DumpStackWalker.h 声明的栈扫描式调用栈重建；
// - 过滤策略（按误报代价从高到低）：
//   1) 值必须落在某个模块映像区间内；
//   2) 相对模块基址的偏移必须跳过 PE 头（>= 0x1000），
//      否则大量“指向映像头部的数据指针”会被当成返回地址；
//   3) 若转储里恰好抓到了该地址所在的代码页，则要求它前面
//      2~7 字节能构成一条 call 指令，这条能滤掉绝大多数残留值；
//   4) 相邻重复值合并，避免同一帧被多次列出。
// - 扫描起点优先用 CONTEXT 的 SP：SP 以下是已经弹掉的垃圾数据，
//   扫描它们只会制造误报。
// ============================================================

#include "DumpStackWalker.h"

#include <algorithm>
#include <cstring>

namespace ks::minidump
{
    namespace
    {
        // kPeHeaderBytes：跳过映像头部的偏移下限；代码节永远在这之后。
        constexpr std::uint64_t kPeHeaderBytes = 0x1000;
        // kMaxScanBytes：单个线程最多扫描的栈字节数，防止巨大栈拖垮解析。
        constexpr std::uint64_t kMaxScanBytes = 1024ull * 1024ull;
        // kCallMinBytes/kCallMaxBytes：x86/x64 call 指令的长度范围。
        constexpr int kCallMinBytes = 2;
        constexpr int kCallMaxBytes = 7;
    }

    bool LooksLikeReturnAddress(
        const DumpFileView& view,
        const DumpMemoryReader& memory,
        const std::uint64_t address,
        const std::uint32_t pointerSize)
    {
        if (address <= static_cast<std::uint64_t>(kCallMaxBytes))
        {
            return false;
        }
        // prefix：返回地址之前最多 7 字节，call 指令必然完整落在这里面。
        unsigned char prefix[kCallMaxBytes] = {};
        if (!memory.read(
                view,
                address - static_cast<std::uint64_t>(kCallMaxBytes),
                static_cast<std::uint64_t>(kCallMaxBytes),
                prefix))
        {
            return false;
        }
        for (int length = kCallMinBytes; length <= kCallMaxBytes; ++length)
        {
            // opcodeIndex：长度为 length 的指令，其首字节在 prefix 中的下标。
            const int opcodeIndex = kCallMaxBytes - length;
            const unsigned char opcode = prefix[opcodeIndex];
            // E8 rel32：直接近调用，固定 5 字节。
            if (opcode == 0xE8 && length == 5)
            {
                return true;
            }
            // FF /2、FF /3：间接调用（寄存器/内存操作数），长度可变，
            // 判据是 ModRM 的 reg 字段等于 2（call）或 3（call far）。
            if (opcode == 0xFF && opcodeIndex + 1 < kCallMaxBytes)
            {
                const unsigned char modrm = prefix[opcodeIndex + 1];
                const unsigned char reg = static_cast<unsigned char>((modrm >> 3) & 0x07);
                if (reg == 2 || reg == 3)
                {
                    return true;
                }
            }
            // 9A ptr16:32：远调用，仅存在于 32 位目标。
            if (pointerSize == 4 && opcode == 0x9A && length == 7)
            {
                return true;
            }
        }
        return false;
    }

    std::vector<StackFrameEntry> ScanStackFrames(
        const DumpFileView& view,
        const StackScanInput& input,
        const ModuleIndex& modules,
        const DumpMemoryReader& memory,
        const int maxFrames)
    {
        // frames：产出的疑似调用栈；第 0 帧来自 CONTEXT，其余按栈地址升序追加。
        std::vector<StackFrameEntry> frames;
        if (maxFrames <= 0)
        {
            return frames;
        }
        // pointerSize：扫描步长；非法值一律按 8 字节处理。
        const std::uint32_t pointerSize = input.pointerSize == 4 ? 4u : 8u;

        // 第 0 帧：CONTEXT 的指令指针本身，是整条栈里唯一完全可信的地址。
        if (input.instructionPointer != 0)
        {
            const AddressNote note = modules.resolve(input.instructionPointer);
            StackFrameEntry frame{};
            frame.threadId = input.threadId;
            frame.index = 0;
            frame.stackAddress = input.stackPointer;
            frame.address = input.instructionPointer;
            frame.symbolText = note.symbolText;
            frame.moduleName = note.moduleName;
            frame.unloadedModule = note.unloadedModule;
            frame.fromContext = true;
            frames.push_back(std::move(frame));
        }

        if (input.stackBytes == 0 || !view.contains(input.stackFileOffset, input.stackBytes))
        {
            return frames;
        }

        // scanStart：优先从 SP 开始，SP 以下都是已经弹出的旧数据。
        // SP 不在本段栈内存范围时退化为从段首开始扫。
        std::uint64_t scanStart = 0;
        if (input.stackPointer >= input.stackBaseAddress &&
            input.stackPointer < input.stackBaseAddress + input.stackBytes)
        {
            scanStart = input.stackPointer - input.stackBaseAddress;
        }
        // 对齐到指针宽度：返回地址一定是对齐存放的，跳过未对齐位置能减少一半误报。
        scanStart -= scanStart % pointerSize;
        const std::uint64_t scanEnd =
            std::min<std::uint64_t>(input.stackBytes, scanStart + kMaxScanBytes);

        // lastAddress：上一帧的地址，用于合并相邻重复值（同一帧被写在多个槽位）。
        std::uint64_t lastAddress = 0;
        int frameIndex = static_cast<int>(frames.size());
        for (std::uint64_t offset = scanStart;
             offset + pointerSize <= scanEnd && frameIndex < maxFrames;
             offset += pointerSize)
        {
            // candidate：栈上当前槽位的值，按目标机指针宽度读取。
            std::uint64_t candidate = 0;
            const unsigned char* const slot =
                view.at(input.stackFileOffset + offset, pointerSize);
            if (slot == nullptr)
            {
                break;
            }
            if (pointerSize == 4)
            {
                std::uint32_t value32 = 0;
                std::memcpy(&value32, slot, sizeof(value32));
                candidate = value32;
            }
            else
            {
                std::memcpy(&candidate, slot, sizeof(candidate));
            }
            if (candidate == 0 || candidate == lastAddress)
            {
                continue;
            }

            const AddressNote note = modules.resolve(candidate);
            // 规则 1、2：必须命中模块，且要跳过 PE 头区域。
            if (note.symbolText.isEmpty() || note.offset < kPeHeaderBytes)
            {
                continue;
            }
            // 规则 3：转储里抓到了这段代码时，要求前面确实是一条 call；
            // 抓不到时（小型转储通常没有代码页）无法校验，保留候选。
            if (memory.contains(candidate - kCallMaxBytes, kCallMaxBytes) &&
                !LooksLikeReturnAddress(view, memory, candidate, pointerSize))
            {
                continue;
            }

            StackFrameEntry frame{};
            frame.threadId = input.threadId;
            frame.index = frameIndex;
            frame.stackAddress = input.stackBaseAddress + offset;
            frame.address = candidate;
            frame.symbolText = note.symbolText;
            frame.moduleName = note.moduleName;
            frame.unloadedModule = note.unloadedModule;
            frame.fromContext = false;
            frames.push_back(std::move(frame));
            lastAddress = candidate;
            ++frameIndex;
        }
        return frames;
    }
}
