#pragma once

// ============================================================
// DumpPhysicalMemory.h
// 作用：
// - 把完整/内核内存转储里的物理页组织成 物理地址 → 文件偏移 的映射；
// - 覆盖两种截然不同的落盘布局：
//   经典布局（DumpType 1/2/7）：头之后按 PHYSICAL_MEMORY_DESCRIPTOR 的
//   run 顺序连续排列页数据；
//   位图布局（DumpType 5/6，Win8 起的活动内存转储）：文件偏移 0x2000 处是
//   _BMP_DUMP_HEADER，页位图每 bit 表示一页是否落盘，页数据紧凑排列。
// - 小型转储（DumpType 4）不走这里，它没有物理内存区，只有 TRIAGE 块。
// 调用方式：
// - KernelDumpParser 判定 DumpType 后调 build()，随后用 readPhysical()
//   取字节；页表遍历（DumpPageTable）建立在本模块之上。
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    // PhysicalMemoryLayout：转储的物理页落盘布局。
    enum class PhysicalMemoryLayout
    {
        None,    // None：尚未建立或不适用（如小型转储）。
        Classic, // Classic：按物理内存段顺序连续排列。
        Bitmap,  // Bitmap：页位图 + 紧凑页数据。
    };

    // PhysicalMemoryMap 作用：完整/内核转储的物理页索引。
    // build 成功后内部只读，可安全并发查询。
    class PhysicalMemoryMap
    {
    public:
        // buildClassic 作用：按经典布局建立索引。
        // 传入 view 文件视图、descriptorOffset 为 PHYSICAL_MEMORY_DESCRIPTOR 在
        // 转储头内的偏移（DUMP_HEADER64 是 0x88）、dataStartOffset 为首个页数据
        // 的文件偏移（内核转储固定 0x2000）；
        // 返回是否建立出至少一个有效段。
        bool buildClassic(
            const DumpFileView& view,
            std::uint64_t descriptorOffset,
            std::uint64_t dataStartOffset);

        // buildBitmap 作用：按位图布局建立索引。
        // 传入 view 与 headerOffset（_BMP_DUMP_HEADER 的文件偏移，固定 0x2000）；
        // 返回签名与位图是否可信。
        // 说明：头内三元组（FirstPage/TotalPresentPages/Pages）的偏移在公开资料里
        // 有两种说法，实现不赌其一，而是用"位图置位数 == TotalPresentPages"这条
        // 等式在候选布局中自证，两个都不成立时判定为不可解析。
        bool buildBitmap(const DumpFileView& view, std::uint64_t headerOffset);

        // translate 作用：把物理地址换算成文件偏移。
        // 传入 physicalAddress 与输出 fileOffsetOut；
        // 该页未落盘（位图未置位或超出所有段）时返回 false。
        bool translate(std::uint64_t physicalAddress, std::uint64_t* fileOffsetOut) const;

        // readPhysical 作用：按物理地址读取字节，自动跨页拼接。
        // 传入 view、physicalAddress 起始物理地址、bytes 长度与输出缓冲；
        // 任何一页缺失都返回 false，不做部分填充——半截数据比读不到更危险。
        bool readPhysical(
            const DumpFileView& view,
            std::uint64_t physicalAddress,
            std::uint64_t bytes,
            void* buffer) const;

        // layout / valid / pageCount / describedPageCount：状态查询。
        PhysicalMemoryLayout layout() const { return m_layout; }
        bool valid() const { return m_layout != PhysicalMemoryLayout::None; }
        std::uint64_t pageCount() const { return m_pageCount; }

        // layoutText 作用：返回布局的中文说明，用于概览页与诊断信息。
        QString layoutText() const;

        // regionCount 作用：返回索引里的物理段数量（位图布局按连续置位段合并计）。
        std::size_t regionCount() const { return m_runs.size(); }

        // appendRegions 作用：把物理段追加到结果的内存区域表，供 UI 展示。
        // 传入 result（就地修改）；只写 base/size/source 三个字段。
        void appendRegions(DumpParseResult& result) const;

    private:
        // Run：一段连续的物理页，且在文件里也连续存放。
        struct Run
        {
            std::uint64_t basePage = 0;   // basePage：起始物理页号。
            std::uint64_t pageCount = 0;  // pageCount：页数。
            std::uint64_t fileOffset = 0; // fileOffset：首页在文件里的偏移。
        };

        std::vector<Run> m_runs;   // m_runs：按 basePage 升序排列的物理段。
        std::uint64_t m_pageCount = 0; // m_pageCount：索引覆盖的总页数。
        PhysicalMemoryLayout m_layout = PhysicalMemoryLayout::None; // m_layout：实际布局。
    };
}
