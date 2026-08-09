#include "DumpKernelModuleList.h"

// ============================================================
// DumpKernelModuleList.cpp
// 说明：
// - PsLoadedModuleList 是一个 LIST_ENTRY 头，它的 Flink 指向第一个
//   KLDR_DATA_TABLE_ENTRY 的 InLoadOrderLinks 字段——该字段位于结构偏移 0，
//   所以链表节点地址就是结构地址，不需要额外的 CONTAINING_RECORD 换算；
// - 遍历终止条件是回到链表头。为防止畸形/被篡改的链表把遍历带进死循环，
//   同时设了条目上限和"已访问节点"集合两道保险。
// ============================================================

#include <QDateTime>

#include <algorithm>
#include <unordered_set>

namespace ks::minidump
{
    namespace
    {
        // kMaxModules：单次遍历产出的条目上限。真实系统的驱动数在数百量级，
        // 给到 4096 足够覆盖，再多只可能是链表被破坏。
        constexpr int kMaxModules = 4096;

        // kMaxRejectedInARow：连续校验失败的容忍次数。链表中间偶发一两个
        // 读不到的节点可以跳过，连续失败说明已经走进了非链表数据。
        constexpr int kMaxRejectedInARow = 16;

        // kMinImageSize/kMaxImageSize：映像大小的合理区间。
        // 下界是一个页，上界 512 MB——比最大的合法驱动映像还宽松一个数量级。
        constexpr std::uint32_t kMinImageSize = 0x1000u;
        constexpr std::uint32_t kMaxImageSize = 512u * 1024u * 1024u;

        // kKernelSpaceLowerBound：x64 内核地址下界。驱动基址必须落在高半区。
        constexpr std::uint64_t kKernelSpaceLowerBound = 0xFFFF800000000000ull;

#pragma pack(push, 8)
        // LdrEntry64：KLDR_DATA_TABLE_ENTRY 中本模块需要的前半部分。
        // 与 KernelDumpParser.cpp 里 triage 用的 KldrDataTableEntry64 同源，
        // 这里只声明遍历所需字段，避免为了几个字段拷一份完整结构。
        struct LdrEntry64
        {
            std::uint64_t InLoadOrderFlink;  // 0x00：下一节点。
            std::uint64_t InLoadOrderBlink;  // 0x08：上一节点。
            std::uint64_t Reserved1;         // 0x10。
            std::uint64_t Reserved2;         // 0x18。
            std::uint64_t Reserved3;         // 0x20。
            std::uint64_t NonPagedDebugInfo; // 0x28。
            std::uint64_t DllBase;           // 0x30：映像基址。
            std::uint64_t EntryPoint;        // 0x38：入口点。
            std::uint32_t SizeOfImage;       // 0x40：映像大小。
            std::uint32_t SizePad;           // 0x44。
            std::uint16_t FullDllNameLength;    // 0x48：完整路径字节数。
            std::uint16_t FullDllNameMaximum;   // 0x4A。
            std::uint32_t FullDllNamePad;       // 0x4C。
            std::uint64_t FullDllNameBuffer;    // 0x50：完整路径缓冲区地址。
            std::uint16_t BaseDllNameLength;    // 0x58：基本名字节数。
            std::uint16_t BaseDllNameMaximum;   // 0x5A。
            std::uint32_t BaseDllNamePad;       // 0x5C。
            std::uint64_t BaseDllNameBuffer;    // 0x60：基本名缓冲区地址。
            std::uint32_t Flags;             // 0x68。
            std::uint16_t LoadCount;         // 0x6C。
            std::uint16_t Reserved5;         // 0x6E。
            std::uint64_t Reserved6;         // 0x70。
            std::uint32_t CheckSum;          // 0x78：PE CheckSum。
            std::uint32_t Padding1;          // 0x7C。
            std::uint32_t TimeDateStamp;     // 0x80：PE 时间戳。
            std::uint32_t Padding2;          // 0x84。
        };
        static_assert(sizeof(LdrEntry64) == 0x88,
            "KLDR_DATA_TABLE_ENTRY(64) 必须是 0x88 字节");
        static_assert(offsetof(LdrEntry64, DllBase) == 0x30,
            "DllBase 必须位于 0x30");
        static_assert(offsetof(LdrEntry64, SizeOfImage) == 0x40,
            "SizeOfImage 必须位于 0x40");
        static_assert(offsetof(LdrEntry64, BaseDllNameBuffer) == 0x60,
            "BaseDllName.Buffer 必须位于 0x60");
#pragma pack(pop)

        // TimestampToText 作用：把 PE 时间戳转成本地时间文本，0 时返回空串。
        QString TimestampToText(const std::uint32_t timeDateStamp)
        {
            if (timeDateStamp == 0)
            {
                return QString();
            }
            return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(timeDateStamp))
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        }

        // EntryLooksValid 作用：判断一个读到的 LDR 条目是否像真实驱动记录。
        // 基址必须页对齐且在内核高半区，映像大小必须落在合理区间，
        // 名字长度必须是宽字符整数倍。任何一条不满足都说明读到的不是有效结构。
        bool EntryLooksValid(const LdrEntry64& entry)
        {
            if (entry.DllBase < kKernelSpaceLowerBound)
            {
                return false;
            }
            if ((entry.DllBase % 0x1000ull) != 0)
            {
                return false;
            }
            if (entry.SizeOfImage < kMinImageSize || entry.SizeOfImage > kMaxImageSize)
            {
                return false;
            }
            if ((entry.BaseDllNameLength % sizeof(char16_t)) != 0 ||
                (entry.FullDllNameLength % sizeof(char16_t)) != 0)
            {
                return false;
            }
            if (entry.BaseDllNameLength > entry.BaseDllNameMaximum ||
                entry.FullDllNameLength > entry.FullDllNameMaximum)
            {
                return false;
            }
            return true;
        }
    }

    KernelModuleScanResult EnumerateLoadedDrivers(
        const PageTableWalker& walker,
        const std::uint64_t listHeadAddress,
        std::vector<ModuleEntry>& modulesOut)
    {
        KernelModuleScanResult scan{};
        if (!walker.usable() || listHeadAddress == 0)
        {
            scan.stopReason = QStringLiteral("页表不可用或链表头地址为空");
            return scan;
        }

        // 链表头本身是一个 LIST_ENTRY，Flink 指向第一个条目。
        std::uint64_t firstNode = 0;
        if (!walker.readPointer(listHeadAddress, &firstNode))
        {
            scan.stopReason = QStringLiteral("链表头所在内存页不在转储中");
            return scan;
        }
        scan.listReadable = true;
        if (firstNode == 0 || firstNode == listHeadAddress)
        {
            scan.stopReason = QStringLiteral("驱动链表为空");
            return scan;
        }

        // existingBases：已有条目的基址集合，避免与 triage 表重复登记。
        std::unordered_set<std::uint64_t> existingBases;
        existingBases.reserve(modulesOut.size() * 2 + 16);
        for (const ModuleEntry& moduleEntry : modulesOut)
        {
            existingBases.insert(moduleEntry.base);
        }

        // visited：已走过的链表节点，成环时立刻发现。
        std::unordered_set<std::uint64_t> visited;
        visited.reserve(1024);

        std::uint64_t node = firstNode;
        int rejectedInARow = 0;
        while (node != 0 && node != listHeadAddress)
        {
            if (scan.acceptedCount >= kMaxModules)
            {
                scan.truncated = true;
                scan.stopReason = QStringLiteral("达到条目上限 %1，剩余部分未展开")
                    .arg(kMaxModules);
                break;
            }
            if (!visited.insert(node).second)
            {
                scan.truncated = true;
                scan.stopReason = QStringLiteral("驱动链表出现环，已在重复节点处停止");
                break;
            }

            LdrEntry64 entry{};
            if (!walker.readVirtual(node, sizeof(entry), &entry))
            {
                // 节点所在页没落盘：内核转储会跳过大量分页内存，属正常缺失。
                scan.truncated = true;
                scan.stopReason = QStringLiteral("链表在第 %1 项处进入未落盘内存")
                    .arg(scan.acceptedCount + 1);
                break;
            }

            if (!EntryLooksValid(entry))
            {
                ++scan.rejectedCount;
                ++rejectedInARow;
                if (rejectedInARow >= kMaxRejectedInARow)
                {
                    scan.truncated = true;
                    scan.stopReason = QStringLiteral("连续 %1 项结构校验失败，已停止遍历")
                        .arg(kMaxRejectedInARow);
                    break;
                }
                node = entry.InLoadOrderFlink;
                continue;
            }
            rejectedInARow = 0;

            // 名字优先取 BaseDllName，读不到再退回 FullDllName。
            QString baseName = walker.readUnicodeString(
                entry.BaseDllNameBuffer, entry.BaseDllNameLength);
            QString fullName = walker.readUnicodeString(
                entry.FullDllNameBuffer, entry.FullDllNameLength);
            if (baseName.isEmpty() && fullName.isEmpty())
            {
                // 结构本身合法但名字缓冲区未落盘：仍然登记，用基址占位，
                // 因为地址区间对归因有价值，缺的只是可读名称。
                baseName = QStringLiteral("(未落盘名称) 0x%1")
                    .arg(QString::number(entry.DllBase, 16).toUpper());
            }

            if (existingBases.insert(entry.DllBase).second)
            {
                ModuleEntry moduleEntry{};
                moduleEntry.name = !fullName.isEmpty() ? fullName : baseName;
                moduleEntry.base = entry.DllBase;
                moduleEntry.size = entry.SizeOfImage;
                moduleEntry.checksum = entry.CheckSum;
                moduleEntry.timeDateStamp = entry.TimeDateStamp;
                moduleEntry.timestampText = TimestampToText(entry.TimeDateStamp);
                modulesOut.push_back(std::move(moduleEntry));
                ++scan.acceptedCount;
            }

            node = entry.InLoadOrderFlink;
        }

        return scan;
    }
}
