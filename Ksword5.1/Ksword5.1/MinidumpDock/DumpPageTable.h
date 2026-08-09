#pragma once

// ============================================================
// DumpPageTable.h
// 作用：
// - 用转储头里的 DirectoryTableBase（崩溃瞬间的 CR3）遍历 x64 四级页表，
//   把内核虚拟地址翻译成物理地址，再经 PhysicalMemoryMap 落到文件偏移；
// - 这是完整/内核内存转储能"按虚拟地址读内存"的唯一途径：这类转储不带
//   TRIAGE 块，也没有 MDMP 那样的虚拟地址内存流，页数据只按物理地址排列。
// - 有了它才能沿 PsLoadedModuleList 枚举驱动、才能扫描内核栈。
// 局限：
// - 只实现 4 级分页（PML4）。5 级分页（LA57）与 32 位 PAE 未覆盖，
//   遇到时 translate 一律失败而不是给出错误地址；
// - 页表项标记为 present 但该物理页未落盘（内核转储会跳过大量页）时同样
//   失败——这是转储本身的信息缺失，不是翻译错误。
// 调用方式：
// - KernelDumpParser 建好 PhysicalMemoryMap 后构造本类，随后用
//   readVirtual() 按内核虚拟地址取字节。
// ============================================================

#include "DumpPhysicalMemory.h"

namespace ks::minidump
{
    // PageTableWalker 作用：基于转储物理页索引的 x64 虚拟地址翻译器。
    // 构造后内部只读，可安全并发查询。
    class PageTableWalker
    {
    public:
        // 构造函数作用：绑定文件视图、物理页索引与页目录基址。
        // 传入 view 文件视图、physical 物理页索引、directoryTableBase 崩溃时的 CR3。
        PageTableWalker(
            const DumpFileView& view,
            const PhysicalMemoryMap& physical,
            std::uint64_t directoryTableBase);

        // usable 作用：判断翻译器是否具备工作条件（物理索引有效且 CR3 可信）。
        bool usable() const { return m_usable; }

        // translate 作用：把虚拟地址翻译成物理地址。
        // 传入 virtualAddress 与输出 physicalOut；
        // 页表任一级缺页、未落盘或标记为 not-present 时返回 false。
        // largePageOut 可选，返回该地址是否由 1GB/2MB 大页映射。
        bool translate(
            std::uint64_t virtualAddress,
            std::uint64_t* physicalOut,
            bool* largePageOut = nullptr) const;

        // readVirtual 作用：按虚拟地址读取字节，自动跨页翻译与拼接。
        // 传入 virtualAddress 起始地址、bytes 长度与输出缓冲；
        // 任何一页翻译失败都返回 false，不做部分填充。
        bool readVirtual(std::uint64_t virtualAddress, std::uint64_t bytes, void* buffer) const;

        // readPointer 作用：读取一个 64 位指针，失败时不修改输出。
        bool readPointer(std::uint64_t virtualAddress, std::uint64_t* valueOut) const;

        // readUnicodeString 作用：读取目标机 UNICODE_STRING 的内容。
        // 传入 bufferAddress 字符缓冲区地址与 lengthBytes 字节数；
        // 返回读到的文本；长度非法或内存缺失时返回空串。
        QString readUnicodeString(std::uint64_t bufferAddress, std::uint16_t lengthBytes) const;

        // directoryTableBase 作用：返回实际使用的页目录物理基址。
        std::uint64_t directoryTableBase() const { return m_directoryTableBase; }

    private:
        const DumpFileView& m_view;             // m_view：只读文件视图。
        const PhysicalMemoryMap& m_physical;    // m_physical：物理页索引。
        std::uint64_t m_directoryTableBase = 0; // m_directoryTableBase：CR3 的物理页基址。
        bool m_usable = false;                  // m_usable：是否具备翻译条件。
    };
}
