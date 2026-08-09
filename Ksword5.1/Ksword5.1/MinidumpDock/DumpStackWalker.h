#pragma once

// ============================================================
// DumpStackWalker.h
// 作用：
// - 在没有 PDB 符号、也不做 unwind 的前提下重建“疑似调用栈”：
//   逐指针宽度扫描线程栈内存，把落在某个模块映像区间内的值
//   当作候选返回地址，再用若干规则过滤误报；
// - 用户态 MDMP 与内核小型转储共用同一套扫描器：前者的栈来自
//   MINIDUMP_THREAD.Stack，后者来自 TRIAGE_DUMP64 的 CallStack 块。
// 局限（必须如实告知使用者）：
// - 栈扫描不是真正的栈回溯：残留的旧帧会被当成有效帧（假阳性），
//   内联与 FPO 函数不会出现（假阴性），帧序号只反映栈上的先后位置，
//   不等于精确的调用层级。UI 上一律标注“疑似调用栈（栈扫描）”。
// 调用方式：
// - 解析器准备好 StackScanInput 与 ModuleIndex 后调用 ScanStackFrames。
// ============================================================

#include "DumpMemoryReader.h"
#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"

namespace ks::minidump
{
    // StackScanInput：一次栈扫描所需的全部输入。
    struct StackScanInput
    {
        std::uint64_t stackFileOffset = 0;   // stackFileOffset：栈字节在转储文件里的偏移。
        std::uint64_t stackBytes = 0;        // stackBytes：栈字节数。
        std::uint64_t stackBaseAddress = 0;  // stackBaseAddress：栈首字节对应的目标机虚拟地址。
        std::uint64_t stackPointer = 0;      // stackPointer：崩溃时的 SP，用来确定扫描起点；0 表示从头扫。
        std::uint64_t instructionPointer = 0; // instructionPointer：崩溃时的 IP，作为第 0 帧。
        std::uint32_t pointerSize = 8;       // pointerSize：指针宽度（4 或 8），即扫描步长。
        std::uint32_t threadId = 0;          // threadId：所属线程 ID，写进产出的每一帧。
    };

    // ScanStackFrames 作用：扫描栈内存并产出疑似调用栈。
    // 传入 view 文件视图、input 扫描输入、modules 模块区间索引、
    // memory 已捕获内存索引（用于校验返回地址前是否为 call 指令，可为空索引）、
    // maxFrames 最多产出的帧数；返回按栈地址由低到高排列的帧数组。
    // 第 0 帧固定来自 CONTEXT 的 IP（fromContext=true），其余为扫描所得。
    std::vector<StackFrameEntry> ScanStackFrames(
        const DumpFileView& view,
        const StackScanInput& input,
        const ModuleIndex& modules,
        const DumpMemoryReader& memory,
        int maxFrames);

    // LooksLikeReturnAddress 作用：检查 address 前面若干字节是否构成一条 call 指令。
    // 传入 view、memory 内存索引、address 候选返回地址与 pointerSize 指针宽度；
    // 无法读到目标字节时返回 false（调用方据此降级为“未校验”而非直接丢弃）。
    bool LooksLikeReturnAddress(
        const DumpFileView& view,
        const DumpMemoryReader& memory,
        std::uint64_t address,
        std::uint32_t pointerSize);
}
