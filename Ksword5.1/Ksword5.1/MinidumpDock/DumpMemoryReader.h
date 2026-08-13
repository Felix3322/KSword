#pragma once

// ============================================================
// DumpMemoryReader.h
// 作用：
// - 把转储文件里“被真正抓取下来的内存块”组织成
//   虚拟地址 → 文件偏移 的有序映射，提供按虚拟地址的只读访问；
// - 用户态 MDMP 的来源是 MemoryListStream / Memory64ListStream，
//   内核小型转储的来源是 TRIAGE 数据块与调用栈块；
// - 有了它才能做“返回地址前面是不是一条 call 指令”这种校验，
//   把栈扫描的误报显著压下去。
// - 完整/内核内存转储没有任何按虚拟地址组织的内存流，页数据只按物理地址
//   排列，因此本类支持挂一个页表后端（PageTableWalker）：块索引未命中时
//   改由页表翻译。这样栈扫描的 call 校验等能力对两类转储是同一套代码。
// 调用方式：
// - 解析器边解析内存流边 addRange()，全部加完调用 finalize()；
// - 完整/内核转储另外调用 attachPageTable() 挂上翻译器；
// - 之后用 contains()/read() 按目标机虚拟地址取字节。
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    class PageTableWalker;

    // DumpMemoryReader 作用：转储内已捕获内存的虚拟地址索引。
    // finalize() 之后内部为只读，可安全并发读取。
    class DumpMemoryReader
    {
    public:
        // addRange 作用：登记一段“虚拟地址 ↔ 文件偏移”的映射。
        // 传入 virtualAddress 目标机地址、fileOffset 文件内偏移、bytes 长度与
        // source 捕获来源；
        // 长度为 0 或越界的段会被忽略。
        void addRange(
            std::uint64_t virtualAddress,
            std::uint64_t fileOffset,
            std::uint64_t bytes,
            const QString& source = QString());

        // finalize 作用：剔除文件内越界的段并按虚拟地址排序，供查询使用。
        // 不做重叠合并——真实转储里内存块本就不重叠，find() 已用回溯兜住少量重叠。
        // 传入 view 只读文件视图（用于剔除文件外的非法段）；返回值：无。
        void finalize(const DumpFileView& view);

        // read 作用：按目标机虚拟地址读取字节到调用方缓冲区。
        // 传入 view 文件视图、virtualAddress 起始地址、bytes 长度与输出缓冲；
        // 要求整段落在同一个已捕获块内，跨块请求返回 false。
        bool read(
            const DumpFileView& view,
            std::uint64_t virtualAddress,
            std::uint64_t bytes,
            void* buffer) const;

        // contains 作用：判断某个虚拟地址的字节是否在转储里。
        bool contains(std::uint64_t virtualAddress, std::uint64_t bytes) const;

        // attachPageTable 作用：挂上页表后端，供块索引未命中时回退翻译。
        // 传入 walker 指针；调用方必须保证 walker 的生命周期长于本对象的使用期。
        // 传 nullptr 可解除挂接。
        void attachPageTable(const PageTableWalker* walker) { m_pageTable = walker; }

        // hasPageTable 作用：是否已挂上页表后端。
        bool hasPageTable() const { return m_pageTable != nullptr; }

        // rangeCount 作用：返回已登记的内存块数量。
        std::size_t rangeCount() const { return m_ranges.size(); }

        // appendCapturedRanges 作用：导出已完成文件边界校验的块索引。
        // 只导出真实 addRange() 注册的数据，不导出页表后端翻译的临时结果；
        // 每段保留注册时的来源，供查看器区分线程栈、TRIAGE 块等证据。
        void appendCapturedRanges(std::vector<DumpMemoryRange>* rangesOut) const;

    private:
        // Range：一段被捕获的内存。
        struct Range
        {
            std::uint64_t virtualAddress = 0; // virtualAddress：块在目标机中的起始地址。
            std::uint64_t fileOffset = 0;     // fileOffset：块在转储文件里的偏移。
            std::uint64_t bytes = 0;          // bytes：块长度。
            QString source;                   // source：该内存的捕获来源。
        };

        // find 作用：定位覆盖 [virtualAddress, +bytes) 的块；找不到返回 nullptr。
        const Range* find(std::uint64_t virtualAddress, std::uint64_t bytes) const;

        std::vector<Range> m_ranges; // m_ranges：按 virtualAddress 升序排列的内存块。
        bool m_finalized = false;    // m_finalized：是否已排序，未排序时禁止查询。
        const PageTableWalker* m_pageTable = nullptr; // m_pageTable：可选的页表后端，不持有所有权。
    };
}
