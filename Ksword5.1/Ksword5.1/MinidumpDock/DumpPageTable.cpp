#include "DumpPageTable.h"

// ============================================================
// DumpPageTable.cpp
// 说明：
// - x64 四级分页的地址拆分（每级 9 位索引 + 12 位页内偏移）：
//   [47:39] PML4 索引 / [38:30] PDPT 索引 / [29:21] PD 索引 /
//   [20:12] PT 索引 / [11:0] 页内偏移；
// - 任一级的表项 bit0(P) 为 0 表示未映射；PDPTE/PDE 的 bit7(PS) 为 1 表示
//   该级直接映射 1GB/2MB 大页，不再往下走；
// - 表项里的物理帧号占 [51:12]，高位是 NX 等属性位，必须掩掉再当地址用。
// ============================================================

#include <algorithm>
#include <vector>

namespace ks::minidump
{
    namespace
    {
        // kPageSize：基础页大小。
        constexpr std::uint64_t kPageSize = 0x1000ull;

        // kPhysicalFrameMask：页表项里物理帧号所占的位 [51:12]。
        constexpr std::uint64_t kPhysicalFrameMask = 0x000FFFFFFFFFF000ull;

        // kPresentBit / kLargePageBit：表项的 P 位与 PS 位。
        constexpr std::uint64_t kPresentBit = 1ull << 0;
        constexpr std::uint64_t kLargePageBit = 1ull << 7;

        // kMaxUnicodeBytes：一次 UNICODE_STRING 读取的字节上限。
        // 驱动路径不会超过这个量级，更大的值只可能来自被误读的结构。
        constexpr std::uint16_t kMaxUnicodeBytes = 1024;

        // CanonicalAddressInvalid 作用：判断地址是否违反 x64 规范形式。
        // 4 级分页下 [63:48] 必须是 bit47 的符号扩展，否则硬件本身就会拒绝。
        bool CanonicalAddressInvalid(const std::uint64_t address)
        {
            const std::uint64_t high = address >> 47;
            return high != 0 && high != 0x1FFFFull;
        }
    }

    PageTableWalker::PageTableWalker(
        const DumpFileView& view,
        const PhysicalMemoryMap& physical,
        const std::uint64_t directoryTableBase)
        : m_view(view)
        , m_physical(physical)
    {
        // CR3 的低 12 位是 PCID 等属性，取物理帧部分即可。
        m_directoryTableBase = directoryTableBase & kPhysicalFrameMask;
        // 页目录基址为 0 说明头里这个字段没被填（部分裁剪过的样本会这样），
        // 此时任何翻译都没有意义，直接标记为不可用而不是给出错误结果。
        m_usable = physical.valid() && m_directoryTableBase != 0;
    }

    bool PageTableWalker::translate(
        const std::uint64_t virtualAddress,
        std::uint64_t* const physicalOut,
        bool* const largePageOut) const
    {
        if (largePageOut != nullptr)
        {
            *largePageOut = false;
        }
        if (!m_usable || physicalOut == nullptr)
        {
            return false;
        }
        if (CanonicalAddressInvalid(virtualAddress))
        {
            return false;
        }

        // 逐级索引：每级取 9 位，表项 8 字节。
        const std::uint64_t indices[4] = {
            (virtualAddress >> 39) & 0x1FFull, // PML4
            (virtualAddress >> 30) & 0x1FFull, // PDPT
            (virtualAddress >> 21) & 0x1FFull, // PD
            (virtualAddress >> 12) & 0x1FFull, // PT
        };

        std::uint64_t tableBase = m_directoryTableBase;
        for (int level = 0; level < 4; ++level)
        {
            const std::uint64_t entryAddress = tableBase + indices[level] * 8ull;
            std::uint64_t entry = 0;
            if (!m_physical.readPhysical(m_view, entryAddress, sizeof(entry), &entry))
            {
                // 页表页本身没落盘：内核转储会跳过大量物理页，属于信息缺失。
                return false;
            }
            if ((entry & kPresentBit) == 0)
            {
                return false;
            }

            const std::uint64_t frame = entry & kPhysicalFrameMask;
            if (level == 1 && (entry & kLargePageBit) != 0)
            {
                // 1GB 大页：帧号按 1GB 对齐，页内偏移取低 30 位。
                if (largePageOut != nullptr)
                {
                    *largePageOut = true;
                }
                *physicalOut = (frame & ~0x3FFFFFFFull) | (virtualAddress & 0x3FFFFFFFull);
                return true;
            }
            if (level == 2 && (entry & kLargePageBit) != 0)
            {
                // 2MB 大页：帧号按 2MB 对齐，页内偏移取低 21 位。
                if (largePageOut != nullptr)
                {
                    *largePageOut = true;
                }
                *physicalOut = (frame & ~0x1FFFFFull) | (virtualAddress & 0x1FFFFFull);
                return true;
            }
            if (level == 3)
            {
                *physicalOut = frame | (virtualAddress & 0xFFFull);
                return true;
            }
            tableBase = frame;
        }
        return false;
    }

    bool PageTableWalker::readVirtual(
        const std::uint64_t virtualAddress,
        const std::uint64_t bytes,
        void* const buffer) const
    {
        if (!m_usable || buffer == nullptr || bytes == 0)
        {
            return false;
        }
        if (bytes > (~0ull) - virtualAddress)
        {
            return false;
        }

        unsigned char* const output = static_cast<unsigned char*>(buffer);
        std::uint64_t copied = 0;
        while (copied < bytes)
        {
            const std::uint64_t currentAddress = virtualAddress + copied;
            std::uint64_t physicalAddress = 0;
            if (!translate(currentAddress, &physicalAddress))
            {
                return false;
            }
            // 一次最多读到当前基础页末尾。大页映射下相邻虚拟页的物理地址是连续的，
            // 但按基础页切分同样正确，只是多几次翻译，换来的是逻辑上少一个分支。
            const std::uint64_t pageRemaining = kPageSize - (currentAddress % kPageSize);
            const std::uint64_t chunk = std::min<std::uint64_t>(pageRemaining, bytes - copied);
            if (!m_physical.readPhysical(m_view, physicalAddress, chunk, output + copied))
            {
                return false;
            }
            copied += chunk;
        }
        return true;
    }

    bool PageTableWalker::readPointer(
        const std::uint64_t virtualAddress,
        std::uint64_t* const valueOut) const
    {
        if (valueOut == nullptr)
        {
            return false;
        }
        std::uint64_t value = 0;
        if (!readVirtual(virtualAddress, sizeof(value), &value))
        {
            return false;
        }
        *valueOut = value;
        return true;
    }

    QString PageTableWalker::readUnicodeString(
        const std::uint64_t bufferAddress,
        const std::uint16_t lengthBytes) const
    {
        if (bufferAddress == 0 || lengthBytes == 0 || lengthBytes > kMaxUnicodeBytes)
        {
            return QString();
        }
        if ((lengthBytes % sizeof(char16_t)) != 0)
        {
            // 长度不是宽字符整数倍：多半读到的不是真正的 UNICODE_STRING。
            return QString();
        }

        std::vector<char16_t> characters(lengthBytes / sizeof(char16_t), u'\0');
        if (!readVirtual(bufferAddress, lengthBytes, characters.data()))
        {
            return QString();
        }
        return QString::fromUtf16(
            reinterpret_cast<const char16_t*>(characters.data()),
            static_cast<qsizetype>(characters.size()));
    }
}
