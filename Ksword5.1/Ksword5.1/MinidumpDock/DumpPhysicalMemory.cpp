#include "DumpPhysicalMemory.h"

// ============================================================
// DumpPhysicalMemory.cpp
// 说明：
// - 两种布局的共同点是"物理页在文件里按某种顺序紧凑排列"，因此都能归约成
//   一组 Run（连续物理页 ↔ 连续文件字节），查询时二分定位即可；
// - 位图布局的关键是"第 N 个置位的页排在文件里第 N 个位置"，所以要把
//   位图里每一段连续置位区间转成一个 Run，转换过程中累加文件偏移；
// - 所有长度/偏移换算都先做溢出检查：畸形转储的页数字段可以是任意值，
//   直接乘 0x1000 会绕回小数值，反而绕过后面的边界判断。
// ============================================================

#include <algorithm>
#include <cstring>

namespace ks::minidump
{
    namespace
    {
        // kPageSize：x86/x64 基础页大小，两种布局的页粒度都是它。
        constexpr std::uint64_t kPageSize = 0x1000ull;

        // kMaxClassicRuns：PHYSICAL_MEMORY_DESCRIPTOR 在头内的 union 区约 700 字节，
        // 最多容纳 42 段；超出即说明该字段不是有效描述符。
        constexpr std::uint32_t kMaxClassicRuns = 42;

        // kMaxBitmapPages：位图覆盖页数上限，对应 64 TB 物理地址空间。
        // 再大只可能是字段被当成了别的数据。
        constexpr std::uint64_t kMaxBitmapPages = 1ull << 34;

        // kMaxRuns：合并后允许的最大段数，防止病态位图产生上百万个碎段。
        constexpr std::size_t kMaxRuns = 1u << 20;

        // kBmpSignature/kBmpValidFull/kBmpValidKernel：_BMP_DUMP_HEADER 的签名。
        // 'SDMP' 是固定签名，第二个字段区分完整/内核活动转储。
        constexpr std::uint32_t kBmpSignature = 0x504D4453u;   // 'SDMP'
        constexpr std::uint32_t kBmpValidDump = 0x504D5544u;   // 'DUMP'
        constexpr std::uint32_t kBmpValidFull = 0x4C4C5546u;   // 'FULL'

        // MultiplyOverflows 作用：判断 a*b 是否溢出 64 位。
        bool MultiplyOverflows(const std::uint64_t a, const std::uint64_t b)
        {
            return a != 0 && b > (~0ull) / a;
        }

        // AddOverflows 作用：判断 a+b 是否溢出 64 位。
        bool AddOverflows(const std::uint64_t a, const std::uint64_t b)
        {
            return b > (~0ull) - a;
        }
    }

    bool PhysicalMemoryMap::buildClassic(
        const DumpFileView& view,
        const std::uint64_t descriptorOffset,
        const std::uint64_t dataStartOffset)
    {
        m_runs.clear();
        m_pageCount = 0;
        m_layout = PhysicalMemoryLayout::None;

        // PHYSICAL_MEMORY_DESCRIPTOR64 布局：
        // 0x00 NumberOfRuns / 0x08 NumberOfPages / 0x10 起是 Run[] {BasePage, PageCount}。
        std::uint32_t numberOfRuns = 0;
        std::uint64_t numberOfPages = 0;
        if (!view.readStruct(descriptorOffset, &numberOfRuns) ||
            !view.readStruct(descriptorOffset + 8, &numberOfPages))
        {
            return false;
        }
        if (numberOfRuns == 0 || numberOfRuns > kMaxClassicRuns)
        {
            return false;
        }

        std::uint64_t cumulativePages = 0; // cumulativePages：已排在前面的页数，决定文件偏移。
        for (std::uint32_t index = 0; index < numberOfRuns; ++index)
        {
            const std::uint64_t runOffset = descriptorOffset + 16 + static_cast<std::uint64_t>(index) * 16;
            std::uint64_t basePage = 0;
            std::uint64_t pageCount = 0;
            if (!view.readStruct(runOffset, &basePage) ||
                !view.readStruct(runOffset + 8, &pageCount))
            {
                break;
            }
            if (pageCount == 0)
            {
                continue;
            }
            // 段自身的地址范围和文件范围都必须能算得出来且不越界。
            if (MultiplyOverflows(basePage, kPageSize) ||
                MultiplyOverflows(cumulativePages, kPageSize) ||
                MultiplyOverflows(pageCount, kPageSize))
            {
                break;
            }
            const std::uint64_t runFileOffset = dataStartOffset + cumulativePages * kPageSize;
            if (AddOverflows(dataStartOffset, cumulativePages * kPageSize) ||
                !view.contains(runFileOffset, pageCount * kPageSize))
            {
                // 段声明的数据超出文件：截断转储很常见，保留已成功建立的部分。
                break;
            }

            Run run{};
            run.basePage = basePage;
            run.pageCount = pageCount;
            run.fileOffset = runFileOffset;
            m_runs.push_back(run);

            cumulativePages += pageCount;
            m_pageCount += pageCount;
        }

        if (m_runs.empty())
        {
            return false;
        }
        std::sort(
            m_runs.begin(),
            m_runs.end(),
            [](const Run& left, const Run& right) { return left.basePage < right.basePage; });
        m_layout = PhysicalMemoryLayout::Classic;
        return true;
    }

    bool PhysicalMemoryMap::buildBitmap(
        const DumpFileView& view,
        const std::uint64_t headerOffset)
    {
        m_runs.clear();
        m_pageCount = 0;
        m_layout = PhysicalMemoryLayout::None;

        // _BMP_DUMP_HEADER 的固定部分：
        // 0x00 Signature 'SDMP' / 0x04 ValidDump 'DUMP' 或 'FULL'。
        std::uint32_t signature = 0;
        std::uint32_t validDump = 0;
        if (!view.readStruct(headerOffset, &signature) ||
            !view.readStruct(headerOffset + 4, &validDump))
        {
            return false;
        }
        if (signature != kBmpSignature ||
            (validDump != kBmpValidDump && validDump != kBmpValidFull))
        {
            return false;
        }

        /*
         * 三元组 FirstPage / TotalPresentPages / Pages 的起始偏移在公开资料里
         * 有 0x10 与 0x20 两种说法，本机拿不到权威定义。与其赌一个，不如让数据
         * 自证：位图里的置位数必须恰好等于 TotalPresentPages，且各字段都要通过
         * 范围与文件边界检查。这个等式几乎不可能被错位读出的字段偶然满足，
         * 因此能唯一地选出正确布局；两个候选都不满足时直接判定为不可解析。
         */
        constexpr std::uint64_t kTripletOffsetCandidates[] = { 0x10ull, 0x20ull };
        std::uint64_t firstPageOffset = 0;
        std::uint64_t totalPresentPages = 0;
        std::uint64_t totalPages = 0;
        std::uint64_t bitmapOffset = 0;
        std::uint64_t bitmapBytes = 0;
        const unsigned char* bitmap = nullptr;

        for (const std::uint64_t tripletOffset : kTripletOffsetCandidates)
        {
            std::uint64_t candidateFirstPage = 0;
            std::uint64_t candidatePresent = 0;
            std::uint64_t candidatePages = 0;
            if (!view.readStruct(headerOffset + tripletOffset, &candidateFirstPage) ||
                !view.readStruct(headerOffset + tripletOffset + 8, &candidatePresent) ||
                !view.readStruct(headerOffset + tripletOffset + 16, &candidatePages))
            {
                continue;
            }
            if (candidatePages == 0 || candidatePages > kMaxBitmapPages ||
                candidatePresent == 0 || candidatePresent > candidatePages)
            {
                continue;
            }

            const std::uint64_t candidateBitmapOffset = headerOffset + tripletOffset + 24;
            const std::uint64_t candidateBitmapBytes = (candidatePages + 7) / 8;
            if (!view.contains(candidateBitmapOffset, candidateBitmapBytes))
            {
                continue;
            }
            // 页数据必须排在位图之后，且首页偏移要落在文件内。
            if (candidateFirstPage < candidateBitmapOffset + candidateBitmapBytes ||
                candidateFirstPage >= view.size)
            {
                continue;
            }

            const unsigned char* const candidateBitmap =
                view.at(candidateBitmapOffset, candidateBitmapBytes);
            if (candidateBitmap == nullptr)
            {
                continue;
            }

            // 决定性校验：统计置位数是否等于 TotalPresentPages。
            std::uint64_t setBits = 0;
            for (std::uint64_t byteIndex = 0; byteIndex < candidateBitmapBytes; ++byteIndex)
            {
                unsigned char byteValue = candidateBitmap[byteIndex];
                while (byteValue != 0)
                {
                    setBits += (byteValue & 1u);
                    byteValue = static_cast<unsigned char>(byteValue >> 1);
                }
            }
            if (setBits != candidatePresent)
            {
                continue;
            }

            firstPageOffset = candidateFirstPage;
            totalPresentPages = candidatePresent;
            totalPages = candidatePages;
            bitmapOffset = candidateBitmapOffset;
            bitmapBytes = candidateBitmapBytes;
            bitmap = candidateBitmap;
            break;
        }

        if (bitmap == nullptr)
        {
            return false;
        }
        (void)totalPresentPages;
        (void)bitmapBytes;

        // 把位图里每一段连续置位区间转成一个 Run。文件里页数据的排列顺序
        // 与页号顺序一致，所以累计置位数直接就是该页在文件里的序号。
        std::uint64_t presentIndex = 0; // presentIndex：已跨过的置位页数。
        std::uint64_t pageIndex = 0;
        while (pageIndex < totalPages && m_runs.size() < kMaxRuns)
        {
            const std::uint64_t byteIndex = pageIndex >> 3;
            const unsigned char bitMask = static_cast<unsigned char>(1u << (pageIndex & 7));
            if ((bitmap[byteIndex] & bitMask) == 0)
            {
                ++pageIndex;
                continue;
            }

            const std::uint64_t runStartPage = pageIndex;
            const std::uint64_t runStartPresent = presentIndex;
            while (pageIndex < totalPages)
            {
                const std::uint64_t currentByte = pageIndex >> 3;
                const unsigned char currentMask = static_cast<unsigned char>(1u << (pageIndex & 7));
                if ((bitmap[currentByte] & currentMask) == 0)
                {
                    break;
                }
                ++pageIndex;
                ++presentIndex;
            }

            const std::uint64_t runPages = pageIndex - runStartPage;
            if (MultiplyOverflows(runStartPresent, kPageSize) ||
                MultiplyOverflows(runPages, kPageSize) ||
                AddOverflows(firstPageOffset, runStartPresent * kPageSize))
            {
                break;
            }
            const std::uint64_t runFileOffset = firstPageOffset + runStartPresent * kPageSize;
            if (!view.contains(runFileOffset, runPages * kPageSize))
            {
                // 截断样本：保留已建立的段，后续查询自然落空而不是读到错页。
                break;
            }

            Run run{};
            run.basePage = runStartPage;
            run.pageCount = runPages;
            run.fileOffset = runFileOffset;
            m_runs.push_back(run);
            m_pageCount += runPages;
        }

        if (m_runs.empty())
        {
            return false;
        }
        m_layout = PhysicalMemoryLayout::Bitmap;
        return true;
    }

    bool PhysicalMemoryMap::translate(
        const std::uint64_t physicalAddress,
        std::uint64_t* const fileOffsetOut) const
    {
        if (fileOffsetOut == nullptr || m_runs.empty())
        {
            return false;
        }

        const std::uint64_t page = physicalAddress / kPageSize;
        const std::uint64_t pageOffset = physicalAddress % kPageSize;

        // 二分找到最后一个 basePage <= page 的段。
        std::size_t low = 0;
        std::size_t high = m_runs.size();
        while (low < high)
        {
            const std::size_t middle = low + (high - low) / 2;
            if (m_runs[middle].basePage <= page)
            {
                low = middle + 1;
            }
            else
            {
                high = middle;
            }
        }
        if (low == 0)
        {
            return false;
        }

        const Run& run = m_runs[low - 1];
        if (page - run.basePage >= run.pageCount)
        {
            return false;
        }
        const std::uint64_t pageIndexInRun = page - run.basePage;
        if (MultiplyOverflows(pageIndexInRun, kPageSize))
        {
            return false;
        }
        *fileOffsetOut = run.fileOffset + pageIndexInRun * kPageSize + pageOffset;
        return true;
    }

    bool PhysicalMemoryMap::readPhysical(
        const DumpFileView& view,
        const std::uint64_t physicalAddress,
        const std::uint64_t bytes,
        void* const buffer) const
    {
        if (buffer == nullptr || bytes == 0)
        {
            return false;
        }
        if (AddOverflows(physicalAddress, bytes))
        {
            return false;
        }

        unsigned char* const output = static_cast<unsigned char*>(buffer);
        std::uint64_t copied = 0;
        while (copied < bytes)
        {
            const std::uint64_t currentAddress = physicalAddress + copied;
            std::uint64_t fileOffset = 0;
            if (!translate(currentAddress, &fileOffset))
            {
                return false;
            }
            // 一次最多拷到当前页末尾，跨页要重新翻译——相邻物理页在文件里
            // 未必相邻（位图布局下尤其如此）。
            const std::uint64_t pageRemaining = kPageSize - (currentAddress % kPageSize);
            const std::uint64_t chunk = std::min<std::uint64_t>(pageRemaining, bytes - copied);
            const unsigned char* const source = view.at(fileOffset, chunk);
            if (source == nullptr)
            {
                return false;
            }
            std::memcpy(output + copied, source, static_cast<std::size_t>(chunk));
            copied += chunk;
        }
        return true;
    }

    QString PhysicalMemoryMap::layoutText() const
    {
        switch (m_layout)
        {
        case PhysicalMemoryLayout::Classic:
            return QStringLiteral("经典物理内存布局（按内存段顺序排列）");
        case PhysicalMemoryLayout::Bitmap:
            return QStringLiteral("位图物理内存布局（活动内存转储）");
        case PhysicalMemoryLayout::None:
        default:
            return QStringLiteral("未建立物理内存映射");
        }
    }

    void PhysicalMemoryMap::appendRegions(DumpParseResult& result) const
    {
        const QString sourceText = (m_layout == PhysicalMemoryLayout::Bitmap)
            ? QStringLiteral("物理内存段（位图）")
            : QStringLiteral("物理内存段");
        for (const Run& run : m_runs)
        {
            MemoryRegionEntry entry{};
            entry.base = run.basePage * kPageSize;
            entry.size = run.pageCount * kPageSize;
            entry.source = sourceText;
            ++result.memoryRegionTotal;
            ++result.memoryRegionShown;
            result.memoryRegions.push_back(std::move(entry));
        }
    }
}
