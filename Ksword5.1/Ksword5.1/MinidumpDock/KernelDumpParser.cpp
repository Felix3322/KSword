// ============================================================
// KernelDumpParser.cpp
// 作用：
// - 解析 Windows 内核转储（蓝屏 DMP）：
//   64 位 PAGEDU64 头（0x2000 字节）与 32 位 PAGEDUMP 头（0x1000 字节）；
// - 64 位小型转储（DumpType=4，即 C:\Windows\Minidump\*.dmp）额外解析
//   TRIAGE_DUMP64：驱动列表、已卸载驱动表、崩溃线程内核栈与 TRIAGE 数据块；
// - 完整/内核转储解析物理内存段描述。
// 解析出原始事实后统一走同一条分析链：
//   建立模块地址索引 → 提取崩溃点寄存器 → 栈扫描重建调用栈 →
//   逐项解读停止码参数 → 生成归因结论（DumpAnalyzer）。
// 布局来源：
// - DUMP_HEADER64/TRIAGE_DUMP64/KLDR_DATA_TABLE_ENTRY64 按 WinDbg SDK
//   （wdbgexts.h）公开布局本地声明，并用 static_assert 锁死关键偏移；
// - 所有偏移访问经 DumpFileView 边界检查，畸形样本安全降级。
// ============================================================

#include "KernelDumpParser.h"

#include "DumpAnalyzer.h"
#include "DumpBugCheckText.h"
#include "DumpContextRegisters.h"
#include "DumpKernelModuleList.h"
#include "DumpMemoryReader.h"
#include "DumpPageTable.h"
#include "DumpPhysicalMemory.h"
#include "DumpStackWalker.h"
#include "DumpSymbolIndex.h"
#include "MinidumpCodeText.h"

#include <QDateTime>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <optional>
#include <vector>

namespace ks::minidump
{
    namespace
    {
        // kKernelHeader64Bytes/kKernelHeader32Bytes：两种内核转储头的固定长度。
        constexpr std::uint64_t kKernelHeader64Bytes = 0x2000;
        constexpr std::uint64_t kKernelHeader32Bytes = 0x1000;
        // kMaxDriverEntries：驱动列表解析上限（正常系统数百个）。
        constexpr std::uint32_t kMaxDriverEntries = 4096;
        // kMaxTriageDataBlocks：TRIAGE 数据块解析上限。
        constexpr std::uint32_t kMaxTriageDataBlocks = 65536;
        // kMaxTriageByteBlockPreviews：原始预览页最多保留的数据块数。目录可能有数百
        // 条，全部复制到结果中会徒增内存与 UI 成本，前若干条已经覆盖核心现场。
        constexpr std::uint32_t kMaxTriageByteBlockPreviews = 128;
        // kTriageByteBlockPreviewBytes：每个数据块的原始预览上限。
        constexpr std::uint32_t kTriageByteBlockPreviewBytes = 512;
        // kMaxDriverNameChars：DUMP_STRING 驱动名的最大字符数（防畸形长度）。
        constexpr std::uint32_t kMaxDriverNameChars = 1024;
        // kUnloadedDriverSlots：内核 MmUnloadedDrivers 数组的固定槽位数。
        constexpr std::uint32_t kUnloadedDriverSlots = 50;
        // kMaxKernelStackFrames：内核调用栈最多展示的帧数。
        constexpr int kMaxKernelStackFrames = 64;
        // kPageBytes：基础页大小，完整转储按页翻译栈内存时的读取粒度。
        constexpr std::uint64_t kPageBytes = 0x1000;
        // kMaxKernelStackScanBytes：完整转储下从栈指针向上读取的上限。
        // x64 内核栈默认 24 KiB，给到 64 KiB 足以覆盖加大过的栈。
        constexpr std::uint64_t kMaxKernelStackScanBytes = 64ull * 1024ull;
        // kContext64Offset/kContext64Bytes：DUMP_HEADER64 内 CONTEXT 的位置与可用长度。
        constexpr std::uint64_t kContext64Offset = 0x348;
        constexpr std::uint64_t kContext64Bytes = 0xF00 - 0x348;
        // kException64Offset：DUMP_HEADER64 内 EXCEPTION_RECORD64 的位置。
        constexpr std::uint64_t kException64Offset = 0xF00;
        // kContext32Offset/kContext32Bytes：DUMP_HEADER32 内 CONTEXT 的位置与可用长度。
        constexpr std::uint64_t kContext32Offset = 0x320;
        constexpr std::uint64_t kContext32Bytes = 0x2CC;

#pragma pack(push, 8)
        // KernelDumpHeader64Prefix：DUMP_HEADER64 前 0x60 字节的固定前缀。
        // 只覆盖判别与 BugCheck 需要的字段，其余字段按显式偏移单独读取。
        struct KernelDumpHeader64Prefix
        {
            std::uint32_t Signature;           // 0x00：'PAGE'。
            std::uint32_t ValidDump;           // 0x04：'DU64'。
            std::uint32_t MajorVersion;        // 0x08：15=Free 版内核，0xC=Checked。
            std::uint32_t MinorVersion;        // 0x0C：内核构建号（如 26100）。
            std::uint64_t DirectoryTableBase;  // 0x10：崩溃时的 CR3。
            std::uint64_t PfnDataBase;         // 0x18：PFN 数据库指针。
            std::uint64_t PsLoadedModuleList;  // 0x20：内核模块链表头地址。
            std::uint64_t PsActiveProcessHead; // 0x28：进程链表头地址。
            std::uint32_t MachineImageType;    // 0x30：PE 机器类型（0x8664=x64）。
            std::uint32_t NumberProcessors;    // 0x34：逻辑处理器数。
            std::uint32_t BugCheckCode;        // 0x38：蓝屏停止码。
            std::uint32_t AlignmentPad;        // 0x3C：结构对齐保留。
            std::uint64_t BugCheckParameter[4]; // 0x40：停止码的四个参数。
        };
        static_assert(sizeof(KernelDumpHeader64Prefix) == 0x60,
            "DUMP_HEADER64 前缀必须是 0x60 字节");
        static_assert(offsetof(KernelDumpHeader64Prefix, BugCheckParameter) == 0x40,
            "BugCheckParameter 必须位于 0x40");

        // ExceptionRecord64：EXCEPTION_RECORD64 布局（位于头偏移 0xF00）。
        struct ExceptionRecord64
        {
            std::uint32_t ExceptionCode;    // 0x00：NTSTATUS 异常码。
            std::uint32_t ExceptionFlags;   // 0x04：异常标志。
            std::uint64_t ExceptionRecord;  // 0x08：链式记录指针。
            std::uint64_t ExceptionAddress; // 0x10：异常地址。
            std::uint32_t NumberParameters; // 0x18：参数个数。
            std::uint32_t UnusedAlignment;  // 0x1C：对齐保留。
            std::uint64_t ExceptionInformation[15]; // 0x20：参数数组。
        };
        static_assert(sizeof(ExceptionRecord64) == 0x98,
            "EXCEPTION_RECORD64 必须是 0x98 字节");

        // TriageDump64：TRIAGE_DUMP64 布局（位于文件偏移 0x2000）。
        // 各 *Offset 均为文件内偏移，SizeOfDump 为 triage 数据总长。
        struct TriageDump64
        {
            std::uint32_t ServicePackBuild;     // 0x00：Service Pack 构建号。
            std::uint32_t SizeOfDump;           // 0x04：triage 区总字节数。
            std::uint32_t ValidOffset;          // 0x08：有效性标记偏移。
            std::uint32_t ContextOffset;        // 0x0C：CONTEXT 副本偏移。
            std::uint32_t ExceptionOffset;      // 0x10：异常记录偏移。
            std::uint32_t MmOffset;             // 0x14：内存管理信息偏移。
            std::uint32_t UnloadedDriversOffset; // 0x18：已卸载驱动表偏移。
            std::uint32_t PrcbOffset;           // 0x1C：KPRCB 副本偏移。
            std::uint32_t ProcessOffset;        // 0x20：EPROCESS 副本偏移。
            std::uint32_t ThreadOffset;         // 0x24：ETHREAD 副本偏移。
            std::uint32_t CallStackOffset;      // 0x28：调用栈原始字节偏移。
            std::uint32_t SizeOfCallStack;      // 0x2C：调用栈字节数。
            std::uint32_t DriverListOffset;     // 0x30：驱动列表偏移。
            std::uint32_t DriverCount;          // 0x34：驱动条目数。
            std::uint32_t StringPoolOffset;     // 0x38：字符串池偏移。
            std::uint32_t StringPoolSize;       // 0x3C：字符串池字节数。
            std::uint32_t BrokenDriverOffset;   // 0x40：肇事驱动记录偏移。
            std::uint32_t TriageOptions;        // 0x44：triage 选项位。
            std::uint64_t TopOfStack;           // 0x48：崩溃线程栈顶虚拟地址。
            std::uint8_t ArchitectureSpecific[16]; // 0x50：架构相关保留区。
            std::uint64_t DataPageAddress;      // 0x60：附加数据页虚拟地址。
            std::uint32_t DataPageOffset;       // 0x68：附加数据页文件偏移。
            std::uint32_t DataPageSize;         // 0x6C：附加数据页字节数。
            std::uint32_t DebuggerDataOffset;   // 0x70：KDDEBUGGER_DATA64 偏移。
            std::uint32_t DebuggerDataSize;     // 0x74：KDDEBUGGER_DATA64 字节数。
            std::uint32_t DataBlocksOffset;     // 0x78：TRIAGE_DATA_BLOCK 数组偏移。
            std::uint32_t DataBlocksCount;      // 0x7C：TRIAGE_DATA_BLOCK 条数。
        };
        static_assert(sizeof(TriageDump64) == 0x80,
            "TRIAGE_DUMP64 必须是 0x80 字节");
        static_assert(offsetof(TriageDump64, TopOfStack) == 0x48,
            "TopOfStack 必须位于 0x48");

        // TriageDump64Prefix：TRIAGE_DUMP64 到 DebuggerDataSize 的稳定前缀。
        // 崩溃现场只依赖此前字段；显式前缀同时锁定该读取范围，避免遇到截断文件时
        // 把 TRIAGE 区后的任意字节解释成可用字段。
        struct TriageDump64Prefix
        {
            std::uint32_t ServicePackBuild;
            std::uint32_t SizeOfDump;
            std::uint32_t ValidOffset;
            std::uint32_t ContextOffset;
            std::uint32_t ExceptionOffset;
            std::uint32_t MmOffset;
            std::uint32_t UnloadedDriversOffset;
            std::uint32_t PrcbOffset;
            std::uint32_t ProcessOffset;
            std::uint32_t ThreadOffset;
            std::uint32_t CallStackOffset;
            std::uint32_t SizeOfCallStack;
            std::uint32_t DriverListOffset;
            std::uint32_t DriverCount;
            std::uint32_t StringPoolOffset;
            std::uint32_t StringPoolSize;
            std::uint32_t BrokenDriverOffset;
            std::uint32_t TriageOptions;
            std::uint64_t TopOfStack;
            std::uint8_t ArchitectureSpecific[16];
            std::uint64_t DataPageAddress;
            std::uint32_t DataPageOffset;
            std::uint32_t DataPageSize;
            std::uint32_t DebuggerDataOffset;
            std::uint32_t DebuggerDataSize;
        };
        static_assert(sizeof(TriageDump64Prefix) == 0x78,
            "TRIAGE_DUMP64 稳定前缀必须是 0x78 字节");

        // UnicodeString64：UNICODE_STRING64 布局（Buffer 为目标机虚拟地址）。
        struct UnicodeString64
        {
            std::uint16_t Length;        // Length：字符串字节数。
            std::uint16_t MaximumLength; // MaximumLength：缓冲区字节数。
            std::uint32_t Padding;       // Padding：对齐保留。
            std::uint64_t Buffer;        // Buffer：目标机地址（需经内存索引才能读到）。
        };
        static_assert(sizeof(UnicodeString64) == 0x10,
            "UNICODE_STRING64 必须是 0x10 字节");

        // KldrDataTableEntry64：KLDR_DATA_TABLE_ENTRY64（wdbgexts.h 公开布局）。
        struct KldrDataTableEntry64
        {
            std::uint64_t InLoadOrderLinksFlink; // 0x00：链表前向指针。
            std::uint64_t InLoadOrderLinksBlink; // 0x08：链表后向指针。
            std::uint64_t Undefined1;            // 0x10：保留。
            std::uint64_t Undefined2;            // 0x18：保留。
            std::uint64_t Undefined3;            // 0x20：保留。
            std::uint64_t NonPagedDebugInfo;     // 0x28：非分页调试信息指针。
            std::uint64_t DllBase;               // 0x30：驱动加载基址。
            std::uint64_t EntryPoint;            // 0x38：入口点地址。
            std::uint32_t SizeOfImage;           // 0x40：映像大小。
            std::uint32_t SizePad;               // 0x44：对齐保留。
            UnicodeString64 FullDllName;         // 0x48：完整路径（Buffer 不可用）。
            UnicodeString64 BaseDllName;         // 0x58：基本名（Buffer 不可用）。
            std::uint32_t Flags;                 // 0x68：加载标志。
            std::uint16_t LoadCount;             // 0x6C：加载计数。
            std::uint16_t Undefined5;            // 0x6E：保留。
            std::uint64_t Undefined6;            // 0x70：保留。
            std::uint32_t CheckSum;              // 0x78：PE CheckSum。
            std::uint32_t Padding1;              // 0x7C：对齐保留。
            std::uint32_t TimeDateStamp;         // 0x80：PE 时间戳。
            std::uint32_t Padding2;              // 0x84：对齐保留。
        };
        static_assert(sizeof(KldrDataTableEntry64) == 0x88,
            "KLDR_DATA_TABLE_ENTRY64 必须是 0x88 字节");

        // DumpDriverEntry64：triage 驱动列表条目 = 名字偏移 + KLDR 快照。
        struct DumpDriverEntry64
        {
            std::uint32_t DriverNameOffset; // DriverNameOffset：DUMP_STRING 的文件偏移。
            std::uint32_t Alignment;        // Alignment：对齐保留。
            KldrDataTableEntry64 LdrEntry;  // LdrEntry：驱动加载信息快照。
        };
        static_assert(sizeof(DumpDriverEntry64) == 0x90,
            "DUMP_DRIVER_ENTRY64 必须是 0x90 字节");

        // UnloadedDriver64：MmUnloadedDrivers 数组的一项（MI_UNLOADED_DRIVER）。
        // 记录驱动卸载前占据的地址区间——判断“驱动卸载后仍被调用”全靠它。
        struct UnloadedDriver64
        {
            UnicodeString64 Name;    // 0x00：驱动名（Buffer 为目标机地址）。
            std::uint64_t StartAddress; // 0x10：卸载前的映像起始地址。
            std::uint64_t EndAddress;   // 0x18：卸载前的映像结束地址。
            std::uint64_t UnloadTime;   // 0x20：卸载时刻（FILETIME）。
        };
        static_assert(sizeof(UnloadedDriver64) == 0x28,
            "MI_UNLOADED_DRIVER(64) 必须是 0x28 字节");

        // TriageDataBlock：TRIAGE_DATA_BLOCK（附加抓取的内存块描述）。
        struct TriageDataBlock
        {
            std::uint64_t Address; // Address：目标机虚拟地址。
            std::uint32_t Offset;  // Offset：数据在文件内的偏移。
            std::uint32_t Size;    // Size：数据字节数。
        };
        static_assert(sizeof(TriageDataBlock) == 0x10,
            "TRIAGE_DATA_BLOCK 必须是 0x10 字节");

        // DbgKdDataHeader64：KDDEBUGGER_DATA64 头的固定前缀。
        struct DbgKdDataHeader64
        {
            std::uint64_t Flink;
            std::uint64_t Blink;
            std::uint32_t OwnerTag;
            std::uint32_t Size;
        };
        static_assert(sizeof(DbgKdDataHeader64) == 0x18,
            "DBGKD_DEBUG_DATA_HEADER64 必须是 0x18 字节");

        // PhysicalMemoryRun64：物理内存段（以页为单位）。
        struct PhysicalMemoryRun64
        {
            std::uint64_t BasePage;  // BasePage：起始物理页号。
            std::uint64_t PageCount; // PageCount：页数。
        };
#pragma pack(pop)

        constexpr std::uint32_t kKdDebuggerOwnerTag = 0x4742444Bu;
        // KDDEBUGGER_DATA64 的字段偏移来自公开 wdbgexts.h 兼容布局。
        // 读取前仍以转储内 Header.Size 和快照长度做边界检查。
        constexpr std::uint32_t kKdOffsetKThreadKernelStack = 0x29C;
        constexpr std::uint32_t kKdOffsetKThreadInitialStack = 0x29E;
        constexpr std::uint32_t kKdOffsetKThreadApcProcess = 0x2A0;
        constexpr std::uint32_t kKdOffsetKThreadState = 0x2A2;
        constexpr std::uint32_t kKdSizeEProcess = 0x2A8;
        constexpr std::uint32_t kKdOffsetEprocessPeb = 0x2AA;
        constexpr std::uint32_t kKdOffsetEprocessParentCid = 0x2AC;
        constexpr std::uint32_t kKdOffsetEprocessDirectoryTableBase = 0x2AE;
        constexpr std::uint32_t kKdSizePrcb = 0x2B0;
        constexpr std::uint32_t kKdOffsetPrcbCurrentThread = 0x2B4;
        constexpr std::uint32_t kKdOffsetPrcbNumber = 0x2BE;
        constexpr std::uint32_t kKdSizeEThread = 0x2C0;

        // Hex 作用：把无符号整数格式化成 0x 大写十六进制文本。
        QString Hex(const std::uint64_t value)
        {
            return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
        }

        // FileTimeToText 作用：把 FILETIME（1601 起 100ns）转成本地时间文本。
        // 传入 fileTime100ns；返回 yyyy-MM-dd HH:mm:ss，0 时返回空串。
        QString FileTimeToText(const std::uint64_t fileTime100ns)
        {
            if (fileTime100ns == 0)
            {
                return QString();
            }
            // kEpochDelta100ns：1601-01-01 与 1970-01-01 的 100ns 差值。
            constexpr std::uint64_t kEpochDelta100ns = 116444736000000000ull;
            if (fileTime100ns <= kEpochDelta100ns)
            {
                return QString();
            }
            const std::uint64_t unixSeconds = (fileTime100ns - kEpochDelta100ns) / 10000000ull;
            return QDateTime::fromSecsSinceEpoch(static_cast<qint64>(unixSeconds))
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        }

        // UptimeToText 作用：把 100ns 时长转成“X 天 HH:MM:SS”文本。
        QString UptimeToText(const std::uint64_t duration100ns)
        {
            if (duration100ns == 0)
            {
                return QString();
            }
            const std::uint64_t totalSeconds = duration100ns / 10000000ull;
            const std::uint64_t days = totalSeconds / 86400;
            const std::uint64_t hours = (totalSeconds % 86400) / 3600;
            const std::uint64_t minutes = (totalSeconds % 3600) / 60;
            const std::uint64_t seconds = totalSeconds % 60;
            return QStringLiteral("%1 天 %2:%3:%4")
                .arg(days)
                .arg(hours, 2, 10, QLatin1Char('0'))
                .arg(minutes, 2, 10, QLatin1Char('0'))
                .arg(seconds, 2, 10, QLatin1Char('0'));
        }

        // MachineImageTypeText 作用：把 PE 机器类型转成架构文本。
        QString MachineImageTypeText(const std::uint32_t machineType)
        {
            switch (machineType)
            {
            case 0x014C: return QStringLiteral("x86");
            case 0x8664: return QStringLiteral("x64 (AMD64)");
            case 0xAA64: return QStringLiteral("ARM64");
            case 0x01C4: return QStringLiteral("ARM (Thumb-2)");
            default:
                return QStringLiteral("机器类型 %1").arg(Hex(machineType));
            }
        }

        // DumpTypeText 作用：把内核转储 DumpType 编号转成中文说明。
        QString DumpTypeText(const std::uint32_t dumpType)
        {
            switch (dumpType)
            {
            case 1: return QStringLiteral("完整内存转储 (Full)");
            case 2: return QStringLiteral("内核内存转储 (Summary/Kernel)");
            case 3: return QStringLiteral("仅转储头 (Header)");
            case 4: return QStringLiteral("小型内存转储 (Triage/Minidump)");
            case 5: return QStringLiteral("活动内存转储 (Bitmap Full)");
            case 6: return QStringLiteral("活动内核内存转储 (Bitmap Kernel)");
            case 7: return QStringLiteral("自动内存转储 (Automatic)");
            default:
                return QStringLiteral("类型 %1").arg(dumpType);
            }
        }

        // ProductTypeText 作用：把 VER_NT_* 产品类型转成中文。
        QString ProductTypeText(const std::uint32_t productType)
        {
            switch (productType)
            {
            case 1: return QStringLiteral("工作站 (VER_NT_WORKSTATION)");
            case 2: return QStringLiteral("域控制器 (VER_NT_DOMAIN_CONTROLLER)");
            case 3: return QStringLiteral("服务器 (VER_NT_SERVER)");
            default: return QString::number(productType);
            }
        }

        // kPageFillDword：内核转储头未使用区域的填充值（ASCII 'PAGE'）。
        // 转储写入器只填自己关心的字段，其余保持这个填充；因此读到它
        // 就等于“本字段没被填过”，绝不能当成真实取值去解释。
        constexpr std::uint32_t kPageFillDword = 0x45474150u;

        // WriterStatusText 作用：解释转储写入器状态，说明这份转储是否完整。
        QString WriterStatusText(const std::uint32_t writerStatus)
        {
            switch (writerStatus)
            {
            case 0: return QStringLiteral("0 —— 写入成功，转储完整");
            case 1: return QStringLiteral("1 —— 写入过程中出现错误，内容可能不完整");
            case 2: return QStringLiteral("2 —— 转储被截断（磁盘空间不足或页面文件太小）");
            case 3: return QStringLiteral("3 —— 转储设备不可用");
            case kPageFillDword:
                return QStringLiteral("未记录（该字段仍是 PAGE 填充，转储写入器没有填写）");
            default: return QStringLiteral("%1 —— 未收录的写入器状态").arg(writerStatus);
            }
        }

        // KernelBuildText 作用：把内核版本号组合成可读文本。
        // MajorVersion 的低 4 位是构建风格（15=Free 零售版，12=Checked 调试版），
        // 不是版本号的“主版本”，直接拼成 15.26100 会被误读成版本 15。
        QString KernelBuildText(const std::uint32_t majorVersion, const std::uint32_t minorVersion)
        {
            const std::uint32_t flavor = majorVersion & 0xFu;
            const QString flavorText = flavor == 15
                ? QStringLiteral("Free 零售版内核")
                : (flavor == 12 ? QStringLiteral("Checked 调试版内核")
                                : QStringLiteral("构建风格编号 %1").arg(flavor));
            return QStringLiteral("%1（%2）").arg(minorVersion).arg(flavorText);
        }

        // TriageRangeValid 作用：判断 triage 区里一个“偏移 + 长度”是否可信。
        // TRIAGE_DUMP64 从 0x50 起是架构相关联合体，其大小在不同架构上没有公开定论，
        // 因此它后面的 DataPage / DebuggerData / DataBlocks 三组字段有可能整体错位。
        // 用文件边界与“必须落在 triage 区之后”两条硬约束先筛一遍，
        // 字段错位时这些值几乎必然落在区间外，从而被安全地丢弃。
        bool TriageRangeValid(
            const DumpFileView& view,
            const std::uint64_t offset,
            const std::uint64_t bytes)
        {
            if (offset < kKernelHeader64Bytes || bytes == 0)
            {
                return false;
            }
            return view.contains(offset, bytes);
        }

        template <typename ValueType>
        bool TriageSnapshotRead(
            const DumpFileView& view,
            const std::uint32_t snapshotOffset,
            const std::uint32_t snapshotBytes,
            const std::uint32_t fieldOffset,
            ValueType* const valueOut)
        {
            if (valueOut == nullptr || fieldOffset > snapshotBytes ||
                sizeof(ValueType) > snapshotBytes - fieldOffset)
            {
                return false;
            }
            return view.readStruct(
                static_cast<std::uint64_t>(snapshotOffset) + fieldOffset,
                valueOut);
        }

        QString KthreadStateText(const std::uint32_t rawState)
        {
            const std::uint8_t state = static_cast<std::uint8_t>(rawState & 0xFFu);
            QString name;
            switch (state)
            {
            case 0: name = QStringLiteral("Initialized"); break;
            case 1: name = QStringLiteral("Ready"); break;
            case 2: name = QStringLiteral("Running"); break;
            case 3: name = QStringLiteral("Standby"); break;
            case 4: name = QStringLiteral("Terminated"); break;
            case 5: name = QStringLiteral("Waiting"); break;
            case 6: name = QStringLiteral("Transition"); break;
            case 7: name = QStringLiteral("DeferredReady"); break;
            case 8: name = QStringLiteral("GateWaitObsolete"); break;
            case 9: name = QStringLiteral("WaitingForProcessInSwap"); break;
            default: name = QStringLiteral("未知状态"); break;
            }
            return rawState == state
                ? name
                : QStringLiteral("%1（原始值 %2）").arg(name, Hex(rawState));
        }

        // ParseTriageExecutionContext 作用：把 TRIAGE 保存的当前处理器、线程、
        // 进程快照转成独立的“崩溃现场”事实页。字段偏移来自转储自己的
        // KDDEBUGGER_DATA64 兼容块，避免依赖固定 Windows 版本的私有结构偏移。
        void ParseTriageExecutionContext(
            const DumpFileView& view,
            const TriageDump64& triage,
            DumpParseResult& result)
        {
            constexpr std::uint32_t kKdDebuggerDataMaximumBytes = 0x380;
            if (!TriageRangeValid(view, triage.DebuggerDataOffset,
                    std::min<std::uint32_t>(triage.DebuggerDataSize,
                        kKdDebuggerDataMaximumBytes)) ||
                triage.DebuggerDataSize < sizeof(DbgKdDataHeader64))
            {
                result.diagnostics.append(QStringLiteral(
                    "TRIAGE 未提供完整 KD 调试数据块，无法解析崩溃现场对象。") );
                return;
            }

            DbgKdDataHeader64 kdHeader{};
            if (!view.readStruct(triage.DebuggerDataOffset, &kdHeader) ||
                kdHeader.OwnerTag != kKdDebuggerOwnerTag ||
                kdHeader.Size < kKdSizeEThread ||
                kdHeader.Size > triage.DebuggerDataSize)
            {
                result.diagnostics.append(QStringLiteral(
                    "TRIAGE KD 调试数据块校验失败，已跳过崩溃现场对象解析。"));
                return;
            }

            const auto readKdU16 = [&view, &triage, kdBytes = kdHeader.Size] (
                const std::uint32_t offset, std::uint16_t* const value) -> bool
            {
                return TriageSnapshotRead(view, triage.DebuggerDataOffset, kdBytes, offset, value);
            };
            std::uint16_t kdOffsetKThreadKernelStack = 0;
            std::uint16_t kdOffsetKThreadInitialStack = 0;
            std::uint16_t kdOffsetKThreadApcProcess = 0;
            std::uint16_t kdOffsetKThreadState = 0;
            std::uint16_t kdSizeEProcess = 0;
            std::uint16_t kdOffsetEprocessPeb = 0;
            std::uint16_t kdOffsetEprocessParentCid = 0;
            std::uint16_t kdOffsetEprocessDirectoryTableBase = 0;
            std::uint16_t kdSizePrcb = 0;
            std::uint16_t kdOffsetPrcbCurrentThread = 0;
            std::uint16_t kdOffsetPrcbNumber = 0;
            std::uint16_t kdSizeEThread = 0;
            if (!readKdU16(kKdOffsetKThreadKernelStack, &kdOffsetKThreadKernelStack) ||
                !readKdU16(kKdOffsetKThreadInitialStack, &kdOffsetKThreadInitialStack) ||
                !readKdU16(kKdOffsetKThreadApcProcess, &kdOffsetKThreadApcProcess) ||
                !readKdU16(kKdOffsetKThreadState, &kdOffsetKThreadState) ||
                !readKdU16(kKdSizeEProcess, &kdSizeEProcess) ||
                !readKdU16(kKdOffsetEprocessPeb, &kdOffsetEprocessPeb) ||
                !readKdU16(kKdOffsetEprocessParentCid, &kdOffsetEprocessParentCid) ||
                !readKdU16(kKdOffsetEprocessDirectoryTableBase,
                    &kdOffsetEprocessDirectoryTableBase) ||
                !readKdU16(kKdSizePrcb, &kdSizePrcb) ||
                !readKdU16(kKdOffsetPrcbCurrentThread, &kdOffsetPrcbCurrentThread) ||
                !readKdU16(kKdOffsetPrcbNumber, &kdOffsetPrcbNumber) ||
                !readKdU16(kKdSizeEThread, &kdSizeEThread) ||
                kdSizePrcb == 0 || kdSizeEThread == 0 || kdSizeEProcess == 0)
            {
                result.diagnostics.append(QStringLiteral(
                    "KD 调试数据块缺少对象偏移元数据，已跳过崩溃现场对象解析。"));
                return;
            }

            std::uint16_t cpuNumber = 0;
            std::uint64_t currentThread = 0;
            std::uint64_t threadProcess = 0;
            std::uint64_t kernelStack = 0;
            std::uint64_t initialStack = 0;
            std::uint32_t threadState = 0;
            std::uint64_t processDirectoryTableBase = 0;
            std::uint64_t parentProcessId = 0;
            std::uint64_t processPeb = 0;
            const bool haveCpu = TriageSnapshotRead(
                view, triage.PrcbOffset, kdSizePrcb, kdOffsetPrcbNumber, &cpuNumber);
            const bool haveCurrentThread = TriageSnapshotRead(
                view, triage.PrcbOffset, kdSizePrcb, kdOffsetPrcbCurrentThread,
                &currentThread);
            const bool haveThreadProcess = TriageSnapshotRead(
                view, triage.ThreadOffset, kdSizeEThread, kdOffsetKThreadApcProcess,
                &threadProcess);
            const bool haveKernelStack = TriageSnapshotRead(
                view, triage.ThreadOffset, kdSizeEThread, kdOffsetKThreadKernelStack,
                &kernelStack);
            const bool haveInitialStack = TriageSnapshotRead(
                view, triage.ThreadOffset, kdSizeEThread, kdOffsetKThreadInitialStack,
                &initialStack);
            const bool haveThreadState = TriageSnapshotRead(
                view, triage.ThreadOffset, kdSizeEThread, kdOffsetKThreadState,
                &threadState);
            const bool haveDirectoryTableBase = TriageSnapshotRead(
                view, triage.ProcessOffset, kdSizeEProcess,
                kdOffsetEprocessDirectoryTableBase, &processDirectoryTableBase);
            const bool haveParentProcessId = TriageSnapshotRead(
                view, triage.ProcessOffset, kdSizeEProcess,
                kdOffsetEprocessParentCid, &parentProcessId);
            const bool havePeb = TriageSnapshotRead(
                view, triage.ProcessOffset, kdSizeEProcess, kdOffsetEprocessPeb,
                &processPeb);

            result.executionContext.push_back({
                QStringLiteral("KD 调试数据大小"), Hex(kdHeader.Size) });
            result.executionContext.push_back({
                QStringLiteral("KPRCB 快照偏移"), Hex(triage.PrcbOffset) });
            result.executionContext.push_back({
                QStringLiteral("KTHREAD 快照偏移"), Hex(triage.ThreadOffset) });
            result.executionContext.push_back({
                QStringLiteral("EPROCESS 快照偏移"), Hex(triage.ProcessOffset) });
            if (haveCpu)
            {
                result.executionContext.push_back({
                    QStringLiteral("崩溃处理器编号"), QString::number(cpuNumber) });
            }
            if (haveCurrentThread)
            {
                result.executionContext.push_back({
                    QStringLiteral("当前 KTHREAD"), Hex(currentThread) });
            }
            if (haveThreadProcess)
            {
                result.executionContext.push_back({
                    QStringLiteral("当前 EPROCESS"), Hex(threadProcess) });
            }
            if (haveKernelStack)
            {
                result.executionContext.push_back({
                    QStringLiteral("当前内核栈"), Hex(kernelStack) });
            }
            if (haveInitialStack)
            {
                result.executionContext.push_back({
                    QStringLiteral("内核初始栈"), Hex(initialStack) });
            }
            if (haveThreadState)
            {
                result.executionContext.push_back({
                    QStringLiteral("KTHREAD 状态"), KthreadStateText(threadState) });
            }
            if (haveDirectoryTableBase)
            {
                result.executionContext.push_back({
                    QStringLiteral("进程目录表基址 (CR3)"),
                    Hex(processDirectoryTableBase) });
            }
            if (haveParentProcessId)
            {
                result.executionContext.push_back({
                    QStringLiteral("父进程 ID"), Hex(parentProcessId) });
            }
            if (havePeb)
            {
                result.executionContext.push_back({
                    QStringLiteral("进程 PEB"), Hex(processPeb) });
            }
        }

        // PlausibleTimestamp 作用：判断一个 PE 时间戳是否落在合理的日期区间。
        // triage 驱动列表里 TimeDateStamp 所在偏移随 Windows 版本变化
        //（Win10 起该位置已被其它字段占用），照读可能得到指针低 32 位冒充的时间戳。
        // 这里用日期区间兜底：不可能的值宁可留空，也不显示 1970 或 2100 年这种荒唐日期。
        bool PlausibleTimestamp(const std::uint32_t timeDateStamp)
        {
            // 下界取 1995 年、上界取 2038 年：早于 Windows NT 商用、
            // 晚于 32 位 time_t 上限的值都不可能是真实的构建时间。
            constexpr std::uint32_t kMinTimestamp = 0x2F000000u;
            constexpr std::uint32_t kMaxTimestamp = 0x7FFFFFFFu;
            return timeDateStamp >= kMinTimestamp && timeDateStamp <= kMaxTimestamp;
        }

        // LooksLikeDriverName 作用：判断解码出来的文本是否像一个驱动名/路径。
        // 驱动名全是 ASCII 路径字符，出现大量非可打印码点就说明长度单位理解错了。
        bool LooksLikeDriverName(const QString& text)
        {
            if (text.isEmpty())
            {
                return false;
            }
            int printable = 0;
            for (const QChar character : text)
            {
                const char16_t unit = character.unicode();
                if (unit >= 0x20 && unit < 0x7F)
                {
                    ++printable;
                }
            }
            // 允许少量非 ASCII（本地化路径），但主体必须是可打印 ASCII。
            return printable * 5 >= text.size() * 4;
        }

        // ReadDumpString 作用：读取 triage 驱动名 DUMP_STRING（长度 + UTF-16 文本）。
        // 长度字段的单位没有公开定论：既有按“字符数”也有按“字节数”的说法，
        // 差 2 倍会让驱动名截半或读进垃圾。这里先按字符数解码，
        // 结果不像驱动名时再按字节数重试一遍，取像的那个。
        // 传入 view 与文件偏移；返回驱动名，两种解释都不成立时返回空串。
        QString ReadDumpString(const DumpFileView& view, const std::uint64_t offset)
        {
            if (offset == 0)
            {
                return QString();
            }
            // length：原始长度字段；超出上限一律视为畸形数据。
            std::uint32_t length = 0;
            if (!view.readStruct(offset, &length) || length == 0 ||
                length > kMaxDriverNameChars * 2)
            {
                return QString();
            }
            // decode：按给定字符数解码文本；越界时返回空串。
            const auto decode = [&view, offset](const std::uint32_t charCount) -> QString
            {
                if (charCount == 0 || charCount > kMaxDriverNameChars)
                {
                    return QString();
                }
                const std::uint64_t textBytes = static_cast<std::uint64_t>(charCount) * 2;
                const unsigned char* const textData =
                    view.at(offset + sizeof(std::uint32_t), textBytes);
                if (textData == nullptr)
                {
                    return QString();
                }
                return QString::fromUtf16(
                    reinterpret_cast<const char16_t*>(textData),
                    static_cast<qsizetype>(charCount));
            };

            const QString asCharCount = decode(length);
            if (LooksLikeDriverName(asCharCount))
            {
                return asCharCount;
            }
            const QString asByteCount = decode(length / 2);
            if (LooksLikeDriverName(asByteCount))
            {
                return asByteCount;
            }
            // 两种解释都不像驱动名时返回较长的那个，至少保留可辨认的片段。
            return asCharCount.isEmpty() ? asByteCount : asCharCount;
        }

        // ReadUnicodeStringFromMemory 作用：按目标机地址读取 UNICODE_STRING 的内容。
        // 传入 view、memory 内存索引与 name 字符串描述符；
        // 转储里没有抓到该缓冲区时返回空串（小型转储很常见）。
        QString ReadUnicodeStringFromMemory(
            const DumpFileView& view,
            const DumpMemoryReader& memory,
            const UnicodeString64& name)
        {
            if (name.Buffer == 0 || name.Length == 0 || name.Length > kMaxDriverNameChars * 2)
            {
                return QString();
            }
            // textBytes：先把长度向下对齐到偶数，再同时用于分配与读取。
            // Length 直接来自转储文件、完全不可信；若它是奇数而这里分别用
            // Length/2 分配、用 Length 读取，memcpy 就会比缓冲区多写 1 字节
            // ——那是货真价实的堆越界写，必须在同一个变量上取长度。
            const std::uint32_t textBytes = static_cast<std::uint32_t>(name.Length) & ~1u;
            if (textBytes == 0)
            {
                return QString();
            }
            // buffer：按 textBytes 读取 UTF-16 内容；跨块或未捕获时读取失败。
            std::vector<char16_t> buffer(textBytes / sizeof(char16_t));
            if (!memory.read(view, name.Buffer, textBytes, buffer.data()))
            {
                return QString();
            }
            return QString::fromUtf16(buffer.data(), static_cast<qsizetype>(buffer.size()));
        }

        // AppendLayoutEntry 作用：把 triage 区的一段布局登记到“数据布局”页。
        void AppendLayoutEntry(
            DumpParseResult& result,
            const std::uint32_t type,
            const QString& name,
            const std::uint64_t offset,
            const std::uint64_t size,
            const QString& note)
        {
            if (offset == 0)
            {
                return;
            }
            StreamEntry entry{};
            entry.type = type;
            entry.typeName = name;
            entry.rva = offset;
            entry.size = size;
            entry.note = note;
            result.streams.push_back(std::move(entry));
        }

        // ParseTriageDrivers 作用：解析 triage 驱动列表为模块表。
        void ParseTriageDrivers(
            const DumpFileView& view,
            const TriageDump64& triage,
            DumpParseResult& result)
        {
            const std::uint32_t driverCount =
                std::min<std::uint32_t>(triage.DriverCount, kMaxDriverEntries);
            if (driverCount != triage.DriverCount)
            {
                result.diagnostics.append(
                    QStringLiteral("驱动数 %1 超过解析上限，仅展示前 %2 条。")
                        .arg(triage.DriverCount)
                        .arg(driverCount));
            }
            result.modules.reserve(driverCount);
            for (std::uint32_t index = 0; index < driverCount; ++index)
            {
                DumpDriverEntry64 driver{};
                if (!view.readStruct(
                        static_cast<std::uint64_t>(triage.DriverListOffset) +
                            static_cast<std::uint64_t>(index) * sizeof(DumpDriverEntry64),
                        &driver))
                {
                    result.diagnostics.append(QStringLiteral("驱动条目越界，列表提前结束。"));
                    break;
                }
                ModuleEntry entry{};
                entry.name = ReadDumpString(view, driver.DriverNameOffset);
                if (entry.name.isEmpty())
                {
                    entry.name = QStringLiteral("(名称不可用)");
                }
                entry.base = driver.LdrEntry.DllBase;
                entry.size = driver.LdrEntry.SizeOfImage;
                entry.checksum = driver.LdrEntry.CheckSum;
                // 时间戳所在偏移随内核版本变化，只在数值落在合理日期区间时才采信。
                if (PlausibleTimestamp(driver.LdrEntry.TimeDateStamp))
                {
                    entry.timeDateStamp = driver.LdrEntry.TimeDateStamp;
                    entry.timestampText =
                        QDateTime::fromSecsSinceEpoch(driver.LdrEntry.TimeDateStamp)
                            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
                }
                result.modules.push_back(std::move(entry));
            }
        }

        // PlausibleDriverRange 作用：判断一对起止地址是否像一段驱动映像区间。
        // 判据：起点落在内核地址空间、终点大于起点、跨度不超过 256MB。
        bool PlausibleDriverRange(const std::uint64_t start, const std::uint64_t end)
        {
            // kKernelSpaceStart：x64 规范地址高半区下界。
            constexpr std::uint64_t kKernelSpaceStart = 0xFFFF800000000000ull;
            constexpr std::uint64_t kMaxImageBytes = 256ull * 1024ull * 1024ull;
            if (start < kKernelSpaceStart || end <= start)
            {
                return false;
            }
            return end - start <= kMaxImageBytes;
        }

        // ScoreUnloadedDriverStride 作用：按给定步长试读已卸载驱动表并打分。
        // 返回看起来合理的槽位数量，用于在两种候选布局之间做选择。
        std::uint32_t ScoreUnloadedDriverStride(
            const DumpFileView& view,
            const std::uint64_t tableOffset,
            const std::uint64_t stride)
        {
            std::uint32_t score = 0;
            for (std::uint32_t index = 0; index < kUnloadedDriverSlots; ++index)
            {
                // 起止地址在两种布局里都紧跟 UNICODE_STRING64，偏移一致。
                std::uint64_t start = 0;
                std::uint64_t end = 0;
                const std::uint64_t slotOffset =
                    tableOffset + static_cast<std::uint64_t>(index) * stride;
                if (!view.readStruct(slotOffset + sizeof(UnicodeString64), &start) ||
                    !view.readStruct(slotOffset + sizeof(UnicodeString64) + 8, &end))
                {
                    break;
                }
                if (PlausibleDriverRange(start, end))
                {
                    ++score;
                }
            }
            return score;
        }

        // ParseTriageUnloadedDrivers 作用：解析 triage 区的已卸载驱动表。
        // 该结构没有公开定义，实际存在两种布局：0x28 字节（含卸载时间）
        // 与 0x20 字节（不含）。这里先按两种步长各试读一遍、统计有多少槽位的
        // 地址区间看起来合理，再用得分高的那个正式解析——比硬编一种布局稳妥得多。
        // 数组容量沿用内核侧的 50 槽（这是推断，不是文档保证），
        // 因此每一槽都独立做边界与合理性校验，多读到的垃圾会被自然丢弃。
        void ParseTriageUnloadedDrivers(
            const DumpFileView& view,
            const DumpMemoryReader& memory,
            const TriageDump64& triage,
            DumpParseResult& result)
        {
            const std::uint64_t tableOffset = triage.UnloadedDriversOffset;
            if (!TriageRangeValid(view, tableOffset, sizeof(UnloadedDriver64)))
            {
                return;
            }
            // kStrideWithTime/kStrideWithoutTime：两种候选布局的条目步长。
            constexpr std::uint64_t kStrideWithTime = sizeof(UnloadedDriver64);
            constexpr std::uint64_t kStrideWithoutTime = 0x20;
            const std::uint32_t scoreWithTime =
                ScoreUnloadedDriverStride(view, tableOffset, kStrideWithTime);
            const std::uint32_t scoreWithoutTime =
                ScoreUnloadedDriverStride(view, tableOffset, kStrideWithoutTime);
            if (scoreWithTime == 0 && scoreWithoutTime == 0)
            {
                // 两种布局都读不出合理区间，说明偏移本身就不对，直接放弃。
                return;
            }
            const bool useTimeLayout = scoreWithTime >= scoreWithoutTime;
            const std::uint64_t stride = useTimeLayout ? kStrideWithTime : kStrideWithoutTime;

            for (std::uint32_t index = 0; index < kUnloadedDriverSlots; ++index)
            {
                const std::uint64_t slotOffset =
                    tableOffset + static_cast<std::uint64_t>(index) * stride;
                UnicodeString64 name{};
                std::uint64_t start = 0;
                std::uint64_t end = 0;
                std::uint64_t unloadTime = 0;
                if (!view.readStruct(slotOffset, &name) ||
                    !view.readStruct(slotOffset + sizeof(UnicodeString64), &start) ||
                    !view.readStruct(slotOffset + sizeof(UnicodeString64) + 8, &end))
                {
                    break;
                }
                if (useTimeLayout)
                {
                    view.readStruct(slotOffset + sizeof(UnicodeString64) + 16, &unloadTime);
                }
                // 空槽与地址区间不合理的槽直接跳过，不进表。
                if (!PlausibleDriverRange(start, end))
                {
                    continue;
                }
                UnloadedModuleEntry entry{};
                entry.name = ReadUnicodeStringFromMemory(view, memory, name);
                if (entry.name.isEmpty())
                {
                    entry.name = QStringLiteral("(名称未捕获)");
                }
                entry.base = start;
                entry.endAddress = end;
                entry.size = static_cast<std::uint32_t>(
                    std::min<std::uint64_t>(end - start, 0xFFFFFFFFull));
                entry.timestampText = FileTimeToText(unloadTime);
                result.unloadedModules.push_back(std::move(entry));
            }
        }

        // ParseTriageArea 作用：解析小型转储的 TRIAGE_DUMP64 区：
        // 布局偏移 → 数据布局页、驱动列表 → 模块表、已卸载驱动 → 已卸载模块表、
        // TRIAGE 数据块 → 内存表与内存索引。
        // 传入的 memory 会被填充，triageOut 输出 triage 头供后续栈扫描使用。
        bool ParseTriageArea(
            const DumpFileView& view,
            DumpParseResult& result,
            DumpMemoryReader& memory,
            TriageDump64* const triageOut)
        {
            TriageDump64Prefix triagePrefix{};
            if (!view.readStruct(kKernelHeader64Bytes, &triagePrefix))
            {
                result.diagnostics.append(QStringLiteral("TRIAGE 区读取失败，文件可能被截断。"));
                return false;
            }

            // triage：后续路径继续使用完整结构。先复制已验证的稳定前缀；完整结构
            // 不在文件范围时尾部保持零值，避免读取截断文件外的字节。
            TriageDump64 triage{};
            std::memcpy(&triage, &triagePrefix, sizeof(triagePrefix));
            if (view.contains(kKernelHeader64Bytes, sizeof(triage)))
            {
                view.readStruct(kKernelHeader64Bytes, &triage);
            }

            // 布局偏移表：让用户直观看到 triage 区里每一段的位置与大小。
            AppendLayoutEntry(result, 1, QStringLiteral("Context"), triage.ContextOffset, 0,
                QStringLiteral("崩溃处理器的 CONTEXT 副本"));
            AppendLayoutEntry(result, 2, QStringLiteral("Exception"), triage.ExceptionOffset,
                sizeof(ExceptionRecord64),
                QStringLiteral("异常记录（KeBugCheckEx 构造）"));
            AppendLayoutEntry(result, 3, QStringLiteral("Mm"), triage.MmOffset, 0,
                QStringLiteral("内存管理器 triage 信息"));
            AppendLayoutEntry(result, 4, QStringLiteral("UnloadedDrivers"),
                triage.UnloadedDriversOffset,
                static_cast<std::uint64_t>(kUnloadedDriverSlots) * sizeof(UnloadedDriver64),
                QStringLiteral("最近卸载的驱动记录（含卸载前地址区间）"));
            AppendLayoutEntry(result, 5, QStringLiteral("Prcb"), triage.PrcbOffset, 0,
                QStringLiteral("崩溃处理器 KPRCB 副本"));
            AppendLayoutEntry(result, 6, QStringLiteral("Process"), triage.ProcessOffset, 0,
                QStringLiteral("崩溃时当前 EPROCESS 副本"));
            AppendLayoutEntry(result, 7, QStringLiteral("Thread"), triage.ThreadOffset, 0,
                QStringLiteral("崩溃时当前 ETHREAD 副本"));
            AppendLayoutEntry(result, 8, QStringLiteral("CallStack"), triage.CallStackOffset,
                triage.SizeOfCallStack,
                QStringLiteral("崩溃线程内核栈原始字节（调用栈重建的数据源）"));
            AppendLayoutEntry(result, 9, QStringLiteral("DriverList"), triage.DriverListOffset,
                static_cast<std::uint64_t>(triage.DriverCount) * sizeof(DumpDriverEntry64),
                QStringLiteral("已加载驱动列表（KLDR 快照）"));
            AppendLayoutEntry(result, 10, QStringLiteral("StringPool"), triage.StringPoolOffset,
                triage.StringPoolSize,
                QStringLiteral("驱动名字符串池"));
            AppendLayoutEntry(result, 11, QStringLiteral("BrokenDriver"), triage.BrokenDriverOffset,
                sizeof(std::uint64_t),
                QStringLiteral("转储自报的肇事驱动记录"));
            AppendLayoutEntry(result, 12, QStringLiteral("DebuggerData"), triage.DebuggerDataOffset,
                triage.DebuggerDataSize,
                QStringLiteral("KDDEBUGGER_DATA64 调试器数据块"));
            AppendLayoutEntry(result, 13, QStringLiteral("DataBlocks"), triage.DataBlocksOffset,
                static_cast<std::uint64_t>(triage.DataBlocksCount) * sizeof(TriageDataBlock),
                QStringLiteral("附加抓取的内存块目录"));

            // 概览补充 triage 关键信息。
            if (triage.ServicePackBuild != 0)
            {
                result.overview.push_back({ QStringLiteral("Service Pack 构建"),
                    QString::number(triage.ServicePackBuild) });
            }
            if (triage.TopOfStack != 0)
            {
                result.overview.push_back({ QStringLiteral("崩溃线程栈顶"),
                    Hex(triage.TopOfStack) });
            }
            if (triage.SizeOfCallStack != 0)
            {
                result.overview.push_back({ QStringLiteral("捕获调用栈大小"),
                    QStringLiteral("%1 字节").arg(triage.SizeOfCallStack) });
            }

            ParseTriageDrivers(view, triage, result);

            // TRIAGE 数据块：转储额外抓取的内存片段，既进内存表也进内存索引。
            // DataBlocksOffset/Count 位于架构相关联合体之后，是最可能错位的两个字段，
            // 因此先整体校验目录本身是否落在文件内，再逐条校验每个块。
            const std::uint32_t blockCount =
                std::min<std::uint32_t>(triage.DataBlocksCount, kMaxTriageDataBlocks);
            const bool dataBlocksValid = TriageRangeValid(
                view,
                triage.DataBlocksOffset,
                static_cast<std::uint64_t>(blockCount) * sizeof(TriageDataBlock));
            if (blockCount != 0 && !dataBlocksValid)
            {
                result.diagnostics.append(
                    QStringLiteral("TRIAGE 数据块目录越界，本转储的附加内存块信息已跳过。"));
            }
            for (std::uint32_t index = 0; dataBlocksValid && index < blockCount; ++index)
            {
                TriageDataBlock block{};
                if (!view.readStruct(
                        static_cast<std::uint64_t>(triage.DataBlocksOffset) +
                            static_cast<std::uint64_t>(index) * sizeof(TriageDataBlock),
                        &block))
                {
                    break;
                }
                if (!TriageRangeValid(view, block.Offset, block.Size))
                {
                    continue;
                }
                MemoryRegionEntry entry{};
                entry.base = block.Address;
                entry.size = block.Size;
                entry.source = QStringLiteral("TRIAGE 数据块");
                ++result.memoryRegionTotal;
                ++result.memoryRegionShown;
                result.memoryRegions.push_back(std::move(entry));
                memory.addRange(block.Address, block.Offset, block.Size);

                // 原始预览：只复制经 TriageRangeValid 验证的前若干块与有限字节，
                // 防止恶意 DMP 用大量块或超大长度耗尽内存。完整块长度仍保留在元数据，
                // UI 会明确说明未展示的尾部字节。
                if (result.byteBlocks.size() < kMaxTriageByteBlockPreviews)
                {
                    const std::uint32_t previewBytes = std::min<std::uint32_t>(
                        block.Size, kTriageByteBlockPreviewBytes);
                    const unsigned char* const preview = view.at(block.Offset, previewBytes);
                    if (preview != nullptr)
                    {
                        DumpByteBlock byteBlock{};
                        byteBlock.address = block.Address;
                        byteBlock.fileOffset = block.Offset;
                        byteBlock.capturedBytes = block.Size;
                        byteBlock.source = QStringLiteral("TRIAGE 数据块");
                        byteBlock.previewBytes.assign(preview, preview + previewBytes);
                        result.byteBlocks.push_back(std::move(byteBlock));
                    }
                }
            }
            if (blockCount > kMaxTriageByteBlockPreviews)
            {
                result.diagnostics.append(
                    QStringLiteral("TRIAGE 数据块共有 %1 条，原始预览仅保留前 %2 条。")
                        .arg(blockCount)
                        .arg(kMaxTriageByteBlockPreviews));
            }
            // 附加数据页与内核栈同样登记进内存索引，供地址读取使用。
            if (triage.DataPageAddress != 0 &&
                TriageRangeValid(view, triage.DataPageOffset, triage.DataPageSize))
            {
                memory.addRange(triage.DataPageAddress, triage.DataPageOffset, triage.DataPageSize);
            }
            if (triage.TopOfStack != 0 &&
                TriageRangeValid(view, triage.CallStackOffset, triage.SizeOfCallStack))
            {
                memory.addRange(triage.TopOfStack, triage.CallStackOffset, triage.SizeOfCallStack);
            }
            memory.finalize(view);

            // 已卸载驱动表要在内存索引建好之后解析，才能读到名字缓冲区。
            ParseTriageUnloadedDrivers(view, memory, triage, result);

            *triageOut = triage;
            return true;
        }

        // ParsePhysicalMemoryRuns 作用：解析完整/内核转储头里的物理内存段描述。
        // 传入 view 与描述区偏移；每段换算成字节后进内存表。
        void ParsePhysicalMemoryRuns(
            const DumpFileView& view,
            const std::uint64_t descriptorOffset,
            DumpParseResult& result)
        {
            // kMaxRuns：union 区 700 字节最多容纳 42 段；超出即视为无效标记。
            constexpr std::uint32_t kMaxRuns = 42;
            std::uint32_t numberOfRuns = 0;
            std::uint64_t numberOfPages = 0;
            if (!view.readStruct(descriptorOffset, &numberOfRuns) ||
                !view.readStruct(descriptorOffset + 8, &numberOfPages))
            {
                return;
            }
            if (numberOfRuns == 0 || numberOfRuns > kMaxRuns)
            {
                return;
            }
            result.overview.push_back({ QStringLiteral("物理内存总页数"),
                QStringLiteral("%1 (约 %2 MB)")
                    .arg(numberOfPages)
                    .arg(numberOfPages / 256) });
            for (std::uint32_t index = 0; index < numberOfRuns; ++index)
            {
                PhysicalMemoryRun64 run{};
                if (!view.readStruct(
                        descriptorOffset + 16 +
                            static_cast<std::uint64_t>(index) * sizeof(PhysicalMemoryRun64),
                        &run))
                {
                    break;
                }
                MemoryRegionEntry entry{};
                entry.base = run.BasePage * 0x1000ull;
                entry.size = run.PageCount * 0x1000ull;
                entry.source = QStringLiteral("物理内存段");
                ++result.memoryRegionTotal;
                ++result.memoryRegionShown;
                result.memoryRegions.push_back(std::move(entry));
            }
        }

        // AppendBugCheckDetails 作用：把停止码、名称、含义、归类与四个参数的
        // 逐项解读写进异常详情页。这是内核转储解析里信息密度最高的一段。
        void AppendBugCheckDetails(
            const std::uint32_t code,
            const std::uint64_t parameters[4],
            const ModuleIndex& modules,
            const std::uint32_t pointerSize,
            DumpParseResult& result)
        {
            // codeText：数值 + 官方名称（查表命中时）。
            QString codeText = Hex(code);
            const QString codeName = BugCheckCodeNameEx(code);
            if (!codeName.isEmpty())
            {
                codeText += QStringLiteral(" (%1)").arg(codeName);
            }
            result.exceptionInfo.push_back({ QStringLiteral("停止代码"), codeText });

            const QString meaning = BugCheckMeaning(code);
            if (!meaning.isEmpty())
            {
                result.exceptionInfo.push_back({ QStringLiteral("停止码含义"), meaning });
            }
            result.exceptionInfo.push_back({ QStringLiteral("故障归类"),
                BugCheckCategoryText(BugCheckCategoryOf(code)) });

            // 四个参数逐项展开：参数名 + 数值 + 结合数值的解读。
            const std::vector<BugCheckParameterInfo> parameterInfos =
                DescribeBugCheckParameters(code, parameters, modules, pointerSize);
            for (std::size_t index = 0; index < parameterInfos.size(); ++index)
            {
                const BugCheckParameterInfo& info = parameterInfos[index];
                // name：没有已知语义时退化成“参数 N”。
                const QString name = info.label.isEmpty()
                    ? QStringLiteral("参数 %1").arg(index + 1)
                    : QStringLiteral("参数 %1：%2").arg(index + 1).arg(info.label);
                const QString value = info.detail.isEmpty()
                    ? info.value
                    : QStringLiteral("%1  —  %2").arg(info.value, info.detail);
                result.exceptionInfo.push_back({ name, value });
            }

            // 嵌套 NTSTATUS 单独提一行：0x1E/0x7E/0x3B 这类停止码的真正原因在这里。
            const std::uint32_t nestedStatus = NestedStatusFromBugCheck(code, parameters);
            if (nestedStatus != 0)
            {
                const QString nestedName = ExceptionCodeName(nestedStatus);
                const QString nestedMeaning = ExceptionCodeMeaning(nestedStatus);
                if (!nestedName.isEmpty() || !nestedMeaning.isEmpty())
                {
                    result.exceptionInfo.push_back({
                        QStringLiteral("真正的异常原因"),
                        QStringLiteral("%1 %2 %3")
                            .arg(Hex(nestedStatus), nestedName, nestedMeaning)
                            .trimmed() });
                }
            }
        }
    }

    void ParseKernelDump64(const DumpFileView& view, DumpParseResult& result)
    {
        result.kind = DumpKind::KernelDump64;
        result.recognized = true;
        if (view.size < kKernelHeader64Bytes)
        {
            result.errorText = QStringLiteral("文件小于 0x2000 字节，PAGEDU64 头不完整。");
            return;
        }
        KernelDumpHeader64Prefix header{};
        if (!view.readStruct(0, &header))
        {
            result.errorText = QStringLiteral("PAGEDU64 头读取失败。");
            return;
        }

        // dumpType/systemTime 等字段位于头部后段，按官方布局显式偏移读取。
        std::uint32_t dumpType = 0;
        std::uint64_t systemTime = 0;
        std::uint64_t systemUpTime = 0;
        std::uint64_t requiredDumpSpace = 0;
        std::uint32_t miniDumpFields = 0;
        std::uint32_t secondaryDataState = 0;
        std::uint32_t productType = 0;
        std::uint32_t suiteMask = 0;
        std::uint32_t writerStatus = 0;
        view.readStruct(0xF98, &dumpType);
        view.readStruct(0xFA0, &requiredDumpSpace);
        view.readStruct(0xFA8, &systemTime);
        view.readStruct(0x1030, &systemUpTime);
        view.readStruct(0x1038, &miniDumpFields);
        view.readStruct(0x103C, &secondaryDataState);
        view.readStruct(0x1040, &productType);
        view.readStruct(0x1044, &suiteMask);
        view.readStruct(0x1048, &writerStatus);

        // arch/pointerSize：后续 CONTEXT 与栈扫描都要用。
        const ContextArch arch = ContextArchFromMachineImageType(header.MachineImageType);
        result.pointerSize = ContextPointerSize(arch);
        result.bugCheckCode = header.BugCheckCode;
        for (int index = 0; index < 4; ++index)
        {
            result.bugCheckParameters[index] = header.BugCheckParameter[index];
        }

        // ---------- 概览 ----------
        result.overview.push_back({ QStringLiteral("转储类别"),
            QStringLiteral("64 位内核转储 (PAGEDU64)") });
        result.overview.push_back({ QStringLiteral("转储类型"), DumpTypeText(dumpType) });
        // bugCheckLine：概览里也放一行停止码，让用户第一眼就看到。
        QString bugCheckLine = Hex(header.BugCheckCode);
        const QString bugCheckName = BugCheckCodeNameEx(header.BugCheckCode);
        if (!bugCheckName.isEmpty())
        {
            bugCheckLine += QStringLiteral(" (%1)").arg(bugCheckName);
        }
        result.overview.push_back({ QStringLiteral("停止代码"), bugCheckLine });
        const QString crashTime = FileTimeToText(systemTime);
        if (!crashTime.isEmpty())
        {
            result.overview.push_back({ QStringLiteral("崩溃时间"), crashTime });
        }
        const QString uptime = UptimeToText(systemUpTime);
        if (!uptime.isEmpty())
        {
            result.overview.push_back({ QStringLiteral("崩溃前运行时长"), uptime });
        }
        result.overview.push_back({ QStringLiteral("内核构建号"),
            KernelBuildText(header.MajorVersion, header.MinorVersion) });
        result.overview.push_back({ QStringLiteral("CPU 架构"),
            MachineImageTypeText(header.MachineImageType) });
        result.overview.push_back({ QStringLiteral("逻辑处理器数"),
            QString::number(header.NumberProcessors) });
        if (productType != 0 && productType != kPageFillDword)
        {
            result.overview.push_back({ QStringLiteral("产品类型"), ProductTypeText(productType) });
        }
        if (suiteMask != 0 && suiteMask != kPageFillDword)
        {
            result.overview.push_back({ QStringLiteral("套件掩码"), Hex(suiteMask) });
        }
        // 写入器状态直接决定这份转储可不可信，务必展示。
        result.overview.push_back({ QStringLiteral("转储写入器状态"),
            WriterStatusText(writerStatus) });
        // 只有真正被写入过、且非零的状态才值得告警；PAGE 填充说明字段没填。
        if (writerStatus != 0 && writerStatus != kPageFillDword)
        {
            result.diagnostics.append(
                QStringLiteral("转储写入器报告了非零状态（%1），本文件可能不完整，"
                    "解析结果仅供参考。").arg(writerStatus));
        }
        if (requiredDumpSpace != 0)
        {
            result.overview.push_back({ QStringLiteral("转储所需空间"),
                QStringLiteral("%1 字节").arg(requiredDumpSpace) });
        }
        if (miniDumpFields != 0)
        {
            result.overview.push_back({ QStringLiteral("小型转储字段位"), Hex(miniDumpFields) });
        }
        if (secondaryDataState != 0)
        {
            result.overview.push_back({ QStringLiteral("附加数据状态"), Hex(secondaryDataState) });
        }
        result.overview.push_back({ QStringLiteral("PsLoadedModuleList"),
            Hex(header.PsLoadedModuleList) });
        result.overview.push_back({ QStringLiteral("PsActiveProcessHead"),
            Hex(header.PsActiveProcessHead) });
        result.overview.push_back({ QStringLiteral("DirectoryTableBase (CR3)"),
            Hex(header.DirectoryTableBase) });
        std::uint64_t kdDebuggerDataBlock = 0;
        view.readStruct(0x80, &kdDebuggerDataBlock);
        if (kdDebuggerDataBlock != 0)
        {
            result.overview.push_back({ QStringLiteral("KdDebuggerDataBlock"),
                Hex(kdDebuggerDataBlock) });
        }
        // comment：管理员可通过 CrashControl 配置的注释文本（多数为空）。
        // 未配置时这段区域保持 'PAGE' 填充，展示出来就是一长串 PAGEPAGE…，
        // 是纯噪声，必须识别出来跳过。
        const unsigned char* const commentData = view.at(0xFB0, 128);
        if (commentData != nullptr && commentData[0] != 0 &&
            std::memcmp(commentData, "PAGE", 4) != 0)
        {
            std::uint32_t commentLength = 0;
            while (commentLength < 128 && commentData[commentLength] != 0)
            {
                ++commentLength;
            }
            result.overview.push_back({ QStringLiteral("注释"),
                QString::fromLocal8Bit(
                    reinterpret_cast<const char*>(commentData),
                    static_cast<qsizetype>(commentLength)) });
        }

        // ---------- 内存/驱动：必须先于归因完成 ----------
        // memory：已捕获内存的虚拟地址索引，栈扫描与名称读取都依赖它。
        // physical/walker 必须声明在 memory 之前：memory 会持有 walker 的裸指针，
        // 后声明者先析构，这个顺序保证 memory 在其后端还活着的时候被销毁。
        PhysicalMemoryMap physical;
        std::optional<PageTableWalker> walker;
        DumpMemoryReader memory;
        TriageDump64 triage{};
        bool hasTriage = false;
        if (dumpType == 4)
        {
            hasTriage = ParseTriageArea(view, result, memory, &triage);
            if (hasTriage)
            {
                ParseTriageExecutionContext(view, triage, result);
            }
        }
        else
        {
            // 完整/内核转储没有 TRIAGE 驱动表，但转储头给出了 CR3 与
            // PsLoadedModuleList。只要能把物理页索引起来并走通页表，
            // 就能沿链表枚举驱动，整条归因链随之可用，全程不需要 PDB。
            //
            // 布局判定以位图头的签名为准而不是只信 DumpType：DumpType 字段
            // 在部分样本上与实际落盘布局不一致，签名才是硬证据。
            if (!physical.buildBitmap(view, kKernelHeader64Bytes))
            {
                physical.buildClassic(view, 0x88, kKernelHeader64Bytes);
            }

            if (!physical.valid())
            {
                // 退回只展示头里声明的物理段，至少让内存页有内容。
                ParsePhysicalMemoryRuns(view, 0x88, result);
                result.diagnostics.append(
                    QStringLiteral("未能建立物理内存映射（文件可能被截断或采用未知布局），"
                        "无法枚举驱动与重建调用栈。"));
            }
            else
            {
                physical.appendRegions(result);
                result.overview.push_back(
                    { QStringLiteral("物理内存布局"), physical.layoutText() });
                result.overview.push_back({ QStringLiteral("转储覆盖物理页数"),
                    QStringLiteral("%1 (约 %2 MB)")
                        .arg(physical.pageCount())
                        .arg(physical.pageCount() / 256) });

                walker.emplace(view, physical, header.DirectoryTableBase);
                if (!walker->usable())
                {
                    result.diagnostics.append(
                        QStringLiteral("转储头未提供可用的页目录基址（DirectoryTableBase），"
                            "无法把内核虚拟地址翻译到物理页，驱动列表与调用栈不可用。"));
                }
                else
                {
                    // 挂上页表后端后，栈扫描的 call 指令校验、名称读取等
                    // 依赖虚拟地址的能力对完整转储同样生效。
                    memory.attachPageTable(&walker.value());
                    result.overview.push_back({ QStringLiteral("页目录基址 (CR3)"),
                        Hex(walker->directoryTableBase()) });

                    const KernelModuleScanResult scan = EnumerateLoadedDrivers(
                        *walker, header.PsLoadedModuleList, result.modules);
                    if (scan.acceptedCount > 0)
                    {
                        result.overview.push_back({ QStringLiteral("驱动列表来源"),
                            QStringLiteral("PsLoadedModuleList 链表遍历（无需符号）") });
                    }
                    if (!scan.listReadable)
                    {
                        result.diagnostics.append(
                            QStringLiteral("驱动链表头 %1 所在内存页不在转储中，无法枚举驱动。")
                                .arg(Hex(header.PsLoadedModuleList)));
                    }
                    else if (scan.acceptedCount == 0)
                    {
                        result.diagnostics.append(
                            QStringLiteral("沿 PsLoadedModuleList 未取得任何通过校验的驱动条目"
                                "（丢弃 %1 项）：%2")
                                .arg(scan.rejectedCount)
                                .arg(scan.stopReason.isEmpty()
                                    ? QStringLiteral("链表结构与预期布局不符")
                                    : scan.stopReason));
                    }
                    else if (scan.truncated || scan.rejectedCount > 0)
                    {
                        // 部分成功也要说清楚，避免把不完整的驱动列表当成全集，
                        // 进而误判"某驱动没加载"。
                        result.diagnostics.append(
                            QStringLiteral("驱动链表遍历未走完：已取得 %1 项，丢弃 %2 项。%3")
                                .arg(scan.acceptedCount)
                                .arg(scan.rejectedCount)
                                .arg(scan.stopReason));
                    }
                }
            }
            memory.finalize(view);
        }

        // modules：模块地址索引，后面所有“地址 → 模块”的翻译都靠它。
        ModuleIndex modules;
        modules.build(result.modules, result.unloadedModules, result.pointerSize);

        // ---------- 崩溃点寄存器 ----------
        // CONTEXT 的取值优先级：triage 区里的副本 → 转储头 0x348 的副本。
        // 头部那份在 Win10/11 的相当多样本上是全零或过期内容，
        // 直接用它会得到一个毫无意义的“崩溃点”，因此 triage 副本优先。
        std::uint64_t contextOffset = kContext64Offset;
        std::uint64_t contextBytes = kContext64Bytes;
        if (hasTriage &&
            TriageRangeValid(view, triage.ContextOffset, ContextMinimumBytes(arch)))
        {
            contextOffset = triage.ContextOffset;
            // triage 区里 CONTEXT 之后紧跟其它段，长度按文件剩余量兜底即可，
            // ReadContextRegisters 内部对每个字段都还会再做一次边界检查。
            contextBytes = view.size - triage.ContextOffset;
        }
        result.registers = ReadContextRegisters(
            view, contextOffset, contextBytes, arch, 0, modules);
        std::uint64_t contextIp = 0;
        std::uint64_t contextSp = 0;
        // 帧指针当前用不到（栈重建走扫描而非帧链），按接口约定传 nullptr 跳过。
        ReadContextPointers(
            view, contextOffset, contextBytes, arch, &contextIp, &contextSp, nullptr);

        // ---------- 异常详情 ----------
        // parameterFaultPreview：停止码参数里的“出错指令地址”。
        // 它比 CONTEXT 的 IP 更准——后者常停在 KeBugCheckEx 内部。
        const std::uint64_t parameterFaultPreview =
            FaultingAddressFromBugCheck(header.BugCheckCode, header.BugCheckParameter);
        AppendBugCheckDetails(
            header.BugCheckCode, header.BugCheckParameter, modules, result.pointerSize, result);

        // exceptionRecord：KeBugCheckEx 之外的路径（如内核未处理异常）会填这里。
        ExceptionRecord64 exceptionRecord{};
        if (view.readStruct(kException64Offset, &exceptionRecord) &&
            exceptionRecord.ExceptionCode != 0)
        {
            QString codeText = Hex(exceptionRecord.ExceptionCode);
            const QString codeName = ExceptionCodeName(exceptionRecord.ExceptionCode);
            if (!codeName.isEmpty())
            {
                codeText += QStringLiteral(" (%1)").arg(codeName);
            }
            result.exceptionInfo.push_back({ QStringLiteral("异常代码"), codeText });
            const QString exceptionMeaning = ExceptionCodeMeaning(exceptionRecord.ExceptionCode);
            if (!exceptionMeaning.isEmpty())
            {
                result.exceptionInfo.push_back({ QStringLiteral("异常含义"), exceptionMeaning });
            }
            const QString addressNote = modules.annotate(exceptionRecord.ExceptionAddress);
            result.exceptionInfo.push_back({ QStringLiteral("异常地址"),
                addressNote.isEmpty()
                    ? Hex(exceptionRecord.ExceptionAddress)
                    : QStringLiteral("%1  —  %2")
                        .arg(Hex(exceptionRecord.ExceptionAddress), addressNote) });
            result.exceptionCode = exceptionRecord.ExceptionCode;
        }

        // 崩溃点指令/栈指针：优先用 CONTEXT，其次用停止码参数里的指令地址。
        if (contextIp != 0)
        {
            // 这里的 IP 来自转储捕获时的 CONTEXT，通常已经停在 KeBugCheckEx 的
            // 内部断点上，不是真正的故障指令；真正的故障地址由停止码参数给出。
            // 名字必须说清楚，否则会有人拿它去查肇事驱动，方向就全错了。
            const QString ipNote = modules.annotate(contextIp);
            result.exceptionInfo.push_back({
                QStringLiteral("捕获时的指令指针（多为 KeBugCheckEx 内部，非故障点）"),
                ipNote.isEmpty() ? Hex(contextIp)
                                 : QStringLiteral("%1  —  %2").arg(Hex(contextIp), ipNote) });
        }
        if (contextSp != 0)
        {
            result.exceptionInfo.push_back({ QStringLiteral("捕获时的栈指针"), Hex(contextSp) });
        }
        // 故障指令地址单列一行：这才是排查要盯的地址。
        if (parameterFaultPreview != 0)
        {
            const QString faultNote = modules.annotate(parameterFaultPreview);
            result.exceptionInfo.push_back({ QStringLiteral("故障指令地址（停止码参数给出）"),
                faultNote.isEmpty()
                    ? Hex(parameterFaultPreview)
                    : QStringLiteral("%1  —  %2").arg(Hex(parameterFaultPreview), faultNote) });
        }

        // faultingAddress：归因的核心输入，优先用停止码参数给出的故障指令地址。
        // faultingAddress 只接受停止码参数给出的故障指令地址。
        // 不能退回 contextIp：内核转储的 CONTEXT 是 KeBugCheckEx 调用点的快照，
        // 那个地址永远落在 ntoskrnl 里。一旦把它当成“崩溃指令地址”，
        // 归因就会以最高权重把票投给 ntoskrnl，并在结论里断言崩溃发生在那儿——
        // 对使用者是纯粹的误导。没有可信的故障地址时宁可留空，
        // 让归因退回到调用栈证据上。
        result.faultingAddress = parameterFaultPreview;

        // ---------- 转储自报的肇事驱动 ----------
        if (hasTriage &&
            TriageRangeValid(view, triage.BrokenDriverOffset, sizeof(std::uint64_t)))
        {
            std::uint64_t brokenDriver = 0;
            // 这 8 个字节的含义随版本变化，未必真是一个驱动地址；
            // 只有当它能归属到某个已知模块时才敢按“肇事驱动”的口径展示，
            // 否则一个随机数值会被读者当成定案证据。归不到就只作原始值列出。
            if (view.readStruct(triage.BrokenDriverOffset, &brokenDriver) && brokenDriver != 0)
            {
                const AddressNote brokenNote = modules.resolve(brokenDriver);
                if (!brokenNote.symbolText.isEmpty())
                {
                    result.exceptionInfo.push_back({ QStringLiteral("转储自报的肇事驱动"),
                        QStringLiteral("%1  —  %2")
                            .arg(Hex(brokenDriver), brokenNote.symbolText) });
                }
                else
                {
                    result.exceptionInfo.push_back({
                        QStringLiteral("TRIAGE 肇事驱动字段（未能归属到模块，仅供参考）"),
                        Hex(brokenDriver) });
                }
            }
        }

        // ---------- 调用栈重建 ----------
        if (hasTriage &&
            TriageRangeValid(view, triage.CallStackOffset, triage.SizeOfCallStack))
        {
            StackScanInput input{};
            input.stackFileOffset = triage.CallStackOffset;
            input.stackBytes = triage.SizeOfCallStack;
            input.stackBaseAddress = triage.TopOfStack;
            input.stackPointer = contextSp;
            input.instructionPointer = result.faultingAddress != 0 ? result.faultingAddress : contextIp;
            input.pointerSize = result.pointerSize;
            input.threadId = 0;
            result.stackFrames =
                ScanStackFrames(view, input, modules, memory, kMaxKernelStackFrames);
        }
        else if (walker.has_value() && walker->usable() && contextSp != 0)
        {
            // 完整/内核转储没有 TRIAGE 栈块，崩溃线程的内核栈按虚拟地址散落在
            // 物理页里，文件偏移并不连续。先逐页翻译读进一段连续缓冲，再交给
            // 同一个扫描器处理。
            //
            // 缓冲本身构成一个临时视图，扫描器只用它取栈上的槽位；候选地址的
            // call 指令校验走 memory 的页表后端，用的是真实文件视图——两者不会
            // 混用，这也是 DumpMemoryReader::read 在走页表分支时忽略入参 view 的原因。
            const std::uint64_t stackBase = contextSp & ~0xFFFull;
            std::vector<unsigned char> stackBuffer(kMaxKernelStackScanBytes, 0);
            std::uint64_t stackBytes = 0;
            while (stackBytes < kMaxKernelStackScanBytes)
            {
                if (!walker->readVirtual(
                        stackBase + stackBytes, kPageBytes, stackBuffer.data() + stackBytes))
                {
                    // 未映射页即栈的边界，正常终止而不是错误。
                    break;
                }
                stackBytes += kPageBytes;
            }

            if (stackBytes == 0)
            {
                result.diagnostics.append(
                    QStringLiteral("崩溃线程栈所在页不在转储中（栈指针 %1），无法重建调用栈。")
                        .arg(Hex(contextSp)));
            }
            else
            {
                stackBuffer.resize(static_cast<std::size_t>(stackBytes));
                const DumpFileView stackView{ stackBuffer.data(), stackBytes };
                StackScanInput input{};
                input.stackFileOffset = 0;
                input.stackBytes = stackBytes;
                input.stackBaseAddress = stackBase;
                input.stackPointer = contextSp;
                input.instructionPointer =
                    result.faultingAddress != 0 ? result.faultingAddress : contextIp;
                input.pointerSize = result.pointerSize;
                input.threadId = 0;
                result.stackFrames =
                    ScanStackFrames(stackView, input, modules, memory, kMaxKernelStackFrames);
            }
        }
        else if (dumpType != 4 && contextSp == 0)
        {
            // 完整转储头里的 CONTEXT 副本在不少 Win10/11 样本上是全零，
            // 没有栈指针就没有扫描起点。说清楚原因，别让人以为是解析失败。
            result.diagnostics.append(
                QStringLiteral("转储头中的 CONTEXT 未提供栈指针，无法定位崩溃线程栈，"
                    "调用栈不可重建。"));
        }

        if (!result.modules.empty())
        {
            result.overview.push_back({ QStringLiteral("已加载驱动数"),
                QString::number(result.modules.size()) });
        }
        if (!result.unloadedModules.empty())
        {
            result.overview.push_back({ QStringLiteral("已卸载驱动数"),
                QString::number(result.unloadedModules.size()) });
        }

        // ---------- 归因结论 ----------
        BuildAnalysis(modules, result);
        result.success = true;
    }

    void ParseKernelDump32(const DumpFileView& view, DumpParseResult& result)
    {
        result.kind = DumpKind::KernelDump32;
        result.recognized = true;
        if (view.size < kKernelHeader32Bytes)
        {
            result.errorText = QStringLiteral("文件小于 0x1000 字节，PAGEDUMP 头不完整。");
            return;
        }

        // 32 位头字段全部按官方布局显式偏移读取（结构简单，无需本地结构体）。
        std::uint32_t majorVersion = 0;
        std::uint32_t minorVersion = 0;
        std::uint32_t machineImageType = 0;
        std::uint32_t numberProcessors = 0;
        std::uint32_t bugCheckCode = 0;
        std::uint32_t bugCheckParameters32[4] = {};
        std::uint32_t dumpType = 0;
        std::uint64_t systemTime = 0;
        view.readStruct(0x08, &majorVersion);
        view.readStruct(0x0C, &minorVersion);
        view.readStruct(0x20, &machineImageType);
        view.readStruct(0x24, &numberProcessors);
        view.readStruct(0x28, &bugCheckCode);
        view.readStruct(0x2C, &bugCheckParameters32[0]);
        view.readStruct(0x30, &bugCheckParameters32[1]);
        view.readStruct(0x34, &bugCheckParameters32[2]);
        view.readStruct(0x38, &bugCheckParameters32[3]);
        view.readStruct(0xF88, &dumpType);
        view.readStruct(0xFC0, &systemTime);

        const ContextArch arch = ContextArchFromMachineImageType(machineImageType);
        result.pointerSize = ContextPointerSize(arch);
        result.bugCheckCode = bugCheckCode;
        // 参数提升为 64 位后复用同一套 BugCheck 详情输出。
        for (int index = 0; index < 4; ++index)
        {
            result.bugCheckParameters[index] = bugCheckParameters32[index];
        }

        result.overview.push_back({ QStringLiteral("转储类别"),
            QStringLiteral("32 位内核转储 (PAGEDUMP)") });
        result.overview.push_back({ QStringLiteral("转储类型"), DumpTypeText(dumpType) });
        QString bugCheckLine = Hex(bugCheckCode);
        const QString bugCheckName = BugCheckCodeNameEx(bugCheckCode);
        if (!bugCheckName.isEmpty())
        {
            bugCheckLine += QStringLiteral(" (%1)").arg(bugCheckName);
        }
        result.overview.push_back({ QStringLiteral("停止代码"), bugCheckLine });
        const QString crashTime = FileTimeToText(systemTime);
        if (!crashTime.isEmpty())
        {
            result.overview.push_back({ QStringLiteral("崩溃时间"), crashTime });
        }
        result.overview.push_back({ QStringLiteral("内核构建号"),
            KernelBuildText(majorVersion, minorVersion) });
        result.overview.push_back({ QStringLiteral("CPU 架构"),
            MachineImageTypeText(machineImageType) });
        result.overview.push_back({ QStringLiteral("逻辑处理器数"),
            QString::number(numberProcessors) });

        // 32 位转储没有 TRIAGE 驱动列表，模块索引为空，
        // 参数解读仍能给出 IRQL / 访问类型 / 嵌套 NTSTATUS 这些不依赖模块的部分。
        ModuleIndex modules;
        modules.build(result.modules, result.unloadedModules, result.pointerSize);
        AppendBugCheckDetails(
            bugCheckCode, result.bugCheckParameters, modules, result.pointerSize, result);

        // 崩溃点寄存器：x86 CONTEXT 位于头偏移 0x320。
        result.registers = ReadContextRegisters(
            view, kContext32Offset, kContext32Bytes, arch, 0, modules);
        std::uint64_t contextIp = 0;
        std::uint64_t contextSp = 0;
        ReadContextPointers(
            view, kContext32Offset, kContext32Bytes, arch, &contextIp, &contextSp, nullptr);
        if (contextIp != 0)
        {
            result.exceptionInfo.push_back({ QStringLiteral("崩溃点指令指针"), Hex(contextIp) });
        }
        // 同 64 位路径：只采信停止码参数给出的故障地址，不回退到 CONTEXT 的 IP。
        result.faultingAddress =
            FaultingAddressFromBugCheck(bugCheckCode, result.bugCheckParameters);

        result.diagnostics.append(
            QStringLiteral("32 位内核转储只解析头部信息：本格式不含 TRIAGE 驱动列表，"
                "无法把崩溃地址归属到具体驱动。"));
        BuildAnalysis(modules, result);
        result.success = true;
    }
}
