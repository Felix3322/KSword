#pragma once

#include <QString>

#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>

namespace ks::kernel
{
    struct CleanImageBaselineResult
    {
        bool available = false;
        bool identityMatched = false;
        bool diskTrustVerified = false;
        bool codeIntegrityTrusted = false;
        bool relocationApplied = false;
        bool differs = false;
        std::uint64_t moduleBase = 0;
        std::uint64_t preferredImageBase = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t relativeVirtualAddress = 0;
        std::uint32_t signingLevel = 0;
        QString moduleName;
        QString imagePath;
        QString imageSha256;
        QString signingThumbprint;
        QString statusText;
        std::vector<std::uint8_t> cleanBytes;
        std::vector<std::uint8_t> observedBytes;
    };


    struct IdtHandlerObservation
    {
        std::uint32_t vector = 0;
        std::uint64_t handler = 0;
    };

    struct TrustedIdtBaselineResult
    {
        bool available = false;
        bool identityMatched = false;
        bool diskTrustVerified = false;
        bool codeIntegrityTrusted = false;
        bool profileHashMatched = false;
        bool handlerMatches = false;
        std::uint32_t vector = 0;
        std::uint32_t expectedCandidateCount = 0;
        std::uint64_t observedHandler = 0;
        std::uint64_t expectedHandler = 0;
        QString imagePath;
        QString imageSha256;
        QString profilePath;
        QString sourceSymbol;
        QString statusText;
    };


    // 一段内存与磁盘净映像不一致的连续区间。
    struct KernelTextDiffRange
    {
        // origin 说明这段差异能否被已知的良性机制解释。
        enum class Origin : int
        {
            // 落在 PE 动态重定位表标注的位点内（import optimization / retpoline），
            // 这类改写由加载器在启动期完成，属于正常现象。
            KnownDynamicRelocation = 0,
            // 无法用任何已知机制解释的代码改写。
            Unexplained
        };

        std::uint32_t rva = 0;
        std::uint32_t length = 0;
        std::uint64_t kernelAddress = 0;
        Origin origin = Origin::Unexplained;
        QString sectionName;
        std::vector<std::uint8_t> cleanBytes;
        std::vector<std::uint8_t> observedBytes;
    };

    // 单个模块的可执行节完整性扫描结果。
    struct KernelTextIntegrityResult
    {
        bool available = false;
        bool identityMatched = false;
        bool diskTrustVerified = false;
        bool relocationApplied = false;
        // 该映像存在本工具未解析的动态重定位符号；此时「无法解释」的判定要保守看待。
        bool unparsedDynamicRelocations = false;
        std::uint64_t moduleBase = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t executableSectionCount = 0;
        std::uint64_t scannedBytes = 0;
        std::uint64_t unreadableBytes = 0;
        std::uint64_t differingBytes = 0;
        std::uint32_t knownRangeCount = 0;
        std::uint32_t unexplainedRangeCount = 0;
        std::uint32_t truncatedRangeCount = 0;
        QString moduleName;
        QString imagePath;
        QString imageSha256;
        QString statusText;
        std::vector<KernelTextDiffRange> ranges;
    };

    struct KernelTextScanOptions
    {
        // 空表示扫描全部已加载模块；否则按基名子串（不区分大小写）过滤。
        QString moduleFilter;
        // 每个模块最多保留的差异区间数量，超出部分只计数不保留字节。
        std::uint32_t maxRangesPerModule = 64U;
        // 单个差异区间最多保留的字节数，用于 UI 预览。
        std::uint32_t maxRangeBytes = 64U;
        // 单次内核读取的块大小，受协议上限约束。
        std::uint32_t chunkBytes = 64U * 1024U;
        // 置位后扫描会在下一个块边界提前返回。
        const std::atomic_bool* cancelFlag = nullptr;
        // 每完成一个模块回调一次，供 UI 增量显示进度。在工作线程上被调用。
        std::function<void(const KernelTextIntegrityResult&)> onModuleComplete;
    };

    class KernelCleanImageBaseline final
    {
    public:
        static CleanImageBaselineResult compareAddress(
            std::uint64_t kernelAddress,
            std::uint32_t byteCount,
            const std::vector<std::uint8_t>& observedBytes = {},
            bool requireTrustedDiskImage = false);

        static bool readKernelBytes(
            std::uint64_t kernelAddress,
            std::uint32_t byteCount,
            std::vector<std::uint8_t>& bytesOut,
            QString& errorTextOut);

        static std::vector<TrustedIdtBaselineResult>
        compareIdtHandlers(
            const std::vector<IdtHandlerObservation>& observations);

        // 遍历已加载内核模块，逐个把可执行节的内存内容与经过重定位的磁盘净映像
        // 全量比对。这是针对「把 RX 页改成 RW 后直接改代码」这类手法的检测面：
        // 只要代码被改过，比对就会留下差异区间。
        static std::vector<KernelTextIntegrityResult> scanExecutableSections(
            const KernelTextScanOptions& options);
    };
}
