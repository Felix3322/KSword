#pragma once

// ============================================================
// DumpKernelModuleList.h
// 作用：
// - 沿转储头给出的 PsLoadedModuleList 遍历 KLDR_DATA_TABLE_ENTRY 双向链表，
//   为完整/内核内存转储重建"已加载驱动列表"；
// - 小型转储（DumpType 4）自带 TRIAGE 驱动表，不需要走这里；完整/内核转储
//   没有那张表，不遍历链表就一个驱动名都拿不到，归因也就无从谈起。
// 为什么不需要 PDB：
// - PsLoadedModuleList 的地址由转储头直接给出（DUMP_HEADER64 偏移 0x20），
//   KLDR_DATA_TABLE_ENTRY 的字段布局在 x64 上自 Vista 起保持稳定，
//   因此整条链路只依赖公开布局，不需要任何符号文件。
// 可靠性策略：
// - 逐项做结构自校验（基址页对齐、落在内核空间、映像大小合理、名字是合法
//   UNICODE_STRING）；校验失败的条目跳过，连续失败或成环即中止并如实报告，
//   宁可少给也不输出看似合理的垃圾条目。
// 调用方式：
// - KernelDumpParser 建好 PageTableWalker 后调用 EnumerateLoadedDrivers。
// ============================================================

#include "DumpPageTable.h"

namespace ks::minidump
{
    // KernelModuleScanResult：一次驱动链表遍历的统计结果。
    struct KernelModuleScanResult
    {
        bool listReadable = false;      // listReadable：链表头是否成功读到。
        int acceptedCount = 0;          // acceptedCount：通过校验并产出的条目数。
        int rejectedCount = 0;          // rejectedCount：因结构校验失败被丢弃的条目数。
        bool truncated = false;         // truncated：是否因上限或成环提前中止。
        QString stopReason;             // stopReason：提前中止的中文原因，正常走完为空。
    };

    // EnumerateLoadedDrivers 作用：遍历 PsLoadedModuleList 产出驱动列表。
    // 传入 walker 虚拟地址翻译器、listHeadAddress 链表头地址（转储头 0x20 字段）、
    // modulesOut 追加输出的模块表（已有条目保留，按基址去重）；
    // 返回遍历统计。函数只读转储，不修改 walker。
    KernelModuleScanResult EnumerateLoadedDrivers(
        const PageTableWalker& walker,
        std::uint64_t listHeadAddress,
        std::vector<ModuleEntry>& modulesOut);
}
