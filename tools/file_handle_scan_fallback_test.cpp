// Regression harness for the R0 file-handle scan policy and query volume.
//
// The fake DriverClient covers five production bugs:
// 1. A successful R0 enumeration with zero target matches must not fall back to
//    the much slower R3 DuplicateHandle path.
// 2. Once an object type index is known to be non-File, later handles of that
//    type must be skipped without another R0 object-name query. File-like
//    counts must describe all File handles examined, not only target matches.
// 3. A process that exits between the process snapshot and its HandleTable
//    query is normal system churn, not an R0 enumeration failure.
// 4. A handle closed between enumeration and object lookup is likewise normal
//    churn and must not inflate the R0 object-query failure diagnostic.
// 5. A successful partial query for an unnamed File object is unmatchable, but
//    it is not an R0 transport/query failure.

#include "../Ksword5.1/Ksword5.1/ksword/file/file_handle_tools.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace
{
    constexpr int kEmptyScenario = 0;
    constexpr int kTypedHandleScenario = 1;
    constexpr std::uint32_t kHandleBase = 0x1000;
    constexpr std::uint32_t kNonFileHandleCount = 900;
    constexpr std::uint32_t kFileHandleCount = 100;
    constexpr std::uint32_t kNonFileTypeIndex = 42;
    constexpr std::uint32_t kFileTypeIndex = 37;
    constexpr long kNtStatusInvalidCid =
        static_cast<long>(static_cast<std::int32_t>(0xC000000BU));
    constexpr wchar_t kTargetPath[] = L"C:\\ksword-regression\\occupied.dat";

    std::atomic_int g_scenario = kEmptyScenario;
    std::atomic_bool g_kernelEnumerationCompleted = false;
    std::atomic_bool g_r3FallbackEntered = false;
    std::atomic_bool g_cancelRequested = false;
    std::atomic_uint32_t g_objectQueryCount = 0;
    std::atomic_uint32_t g_activeObjectQueryCount = 0;
    std::atomic_uint32_t g_peakObjectQueryCount = 0;

    void RecordQueryStarted()
    {
        const std::uint32_t activeCount =
            g_activeObjectQueryCount.fetch_add(1, std::memory_order_acq_rel) + 1;
        std::uint32_t peakCount = g_peakObjectQueryCount.load(std::memory_order_acquire);
        while (activeCount > peakCount &&
               !g_peakObjectQueryCount.compare_exchange_weak(
                   peakCount,
                   activeCount,
                   std::memory_order_acq_rel,
                   std::memory_order_acquire))
        {
        }
    }

    void RecordQueryFinished()
    {
        g_activeObjectQueryCount.fetch_sub(1, std::memory_order_acq_rel);
    }

    std::size_t DiagnosticCount(
        const std::wstring& diagnosticText,
        const std::wstring& label)
    {
        const std::size_t labelOffset = diagnosticText.find(label);
        if (labelOffset == std::wstring::npos)
        {
            return 0;
        }
        std::size_t offset = labelOffset + label.size();
        std::size_t value = 0;
        while (offset < diagnosticText.size() &&
               diagnosticText[offset] >= L'0' && diagnosticText[offset] <= L'9')
        {
            value = (value * 10U) + static_cast<std::size_t>(diagnosticText[offset] - L'0');
            ++offset;
        }
        return value;
    }
}

namespace ksword::ark
{
    ProcessEnumResult DriverClient::enumerateProcesses(unsigned long) const
    {
        ProcessEnumResult result{};
        result.io.ok = true;
        ProcessEntry entry{};
        entry.processId = ::GetCurrentProcessId();
        result.entries.push_back(entry);
        ProcessEntry exitedEntry{};
        exitedEntry.processId = entry.processId + 100000U;
        result.entries.push_back(exitedEntry);
        result.totalCount = 2;
        result.returnedCount = 2;
        return result;
    }

    HandleEnumResult DriverClient::enumerateProcessHandles(
        const std::uint32_t processId,
        unsigned long) const
    {
        HandleEnumResult result{};
        if (processId != ::GetCurrentProcessId())
        {
            result.io.ok = false;
            result.io.ntStatus = kNtStatusInvalidCid;
            result.processId = processId;
            result.lastStatus = kNtStatusInvalidCid;
            return result;
        }
        result.io.ok = true;
        result.processId = processId;
        if (g_scenario.load(std::memory_order_acquire) == kTypedHandleScenario)
        {
            const std::uint32_t totalCount = kNonFileHandleCount + kFileHandleCount;
            result.entries.reserve(totalCount);
            for (std::uint32_t index = 0; index < totalCount; ++index)
            {
                HandleEntry entry{};
                entry.processId = processId;
                entry.handleValue = kHandleBase + index;
                entry.grantedAccess = 0x00120089;
                entry.objectTypeIndex = index < kNonFileHandleCount
                    ? kNonFileTypeIndex
                    : kFileTypeIndex;
                result.entries.push_back(entry);
            }
            result.totalCount = totalCount;
            result.returnedCount = totalCount;
        }
        g_kernelEnumerationCompleted.store(true, std::memory_order_release);
        return result;
    }

    HandleObjectQueryResult DriverClient::queryHandleObject(
        const std::uint32_t processId,
        const std::uint64_t handleValue,
        unsigned long,
        unsigned long) const
    {
        g_objectQueryCount.fetch_add(1, std::memory_order_acq_rel);
        RecordQueryStarted();

        HandleObjectQueryResult result{};
        result.io.ok = true;
        result.processId = processId;
        result.handleValue = handleValue;
        result.queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_OK;
        result.actualGrantedAccess = 0x00120089;
        const std::uint64_t fileHandleBase = kHandleBase + kNonFileHandleCount;
        if (handleValue < fileHandleBase)
        {
            result.objectTypeIndex = kNonFileTypeIndex;
            result.typeName = L"Event";
            result.objectName = L"\\BaseNamedObjects\\ksword-regression-event";
            RecordQueryFinished();
            return result;
        }

        // Model the per-File ObQueryNameString/IOCTL latency seen in the live
        // scan. A serial production loop remains deterministic but slow, while
        // bounded parallel queries produce the same result with overlap.
        ::Sleep(3);
        result.objectTypeIndex = kFileTypeIndex;
        result.typeName = L"File";
        if (handleValue == fileHandleBase + kFileHandleCount - 3U)
        {
            result.io.ok = false;
            RecordQueryFinished();
            return result;
        }
        if (handleValue == fileHandleBase + kFileHandleCount - 2U)
        {
            result.queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_PARTIAL;
            RecordQueryFinished();
            return result;
        }
        if (handleValue == fileHandleBase + kFileHandleCount - 1U)
        {
            result.queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_HANDLE_REFERENCE_FAILED;
            result.objectReferenceStatus = kNtStatusInvalidCid;
            RecordQueryFinished();
            return result;
        }
        if (handleValue == fileHandleBase)
        {
            result.objectName = kTargetPath;
        }
        else
        {
            result.objectName = L"C:\\ksword-regression\\other-" +
                std::to_wstring(handleValue - fileHandleBase) + L".dat";
        }
        RecordQueryFinished();
        return result;
    }
}

namespace ks::process
{
    std::string QueryProcessPathByPid(std::uint32_t)
    {
        return {};
    }
}

namespace ks::str
{
    std::wstring Utf8ToUtf16(const std::string& text)
    {
        if (text.empty())
        {
            return {};
        }
        const int length = ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0);
        if (length <= 0)
        {
            return {};
        }
        std::wstring result(static_cast<std::size_t>(length), L'\0');
        ::MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            result.data(),
            length);
        return result;
    }

    std::string Utf16ToUtf8(const std::wstring& text)
    {
        if (text.empty())
        {
            return {};
        }
        const int length = ::WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (length <= 0)
        {
            return {};
        }
        std::string result(static_cast<std::size_t>(length), '\0');
        ::WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            result.data(),
            length,
            nullptr,
            nullptr);
        return result;
    }
}

int wmain()
{
    ks::file::HandleUsageScanOptions emptyOptions{};
    emptyOptions.tryKernelHandleTable = true;
    emptyOptions.progressCallback = [](const std::string& stepText, float)
    {
        if (stepText == "准备抓取系统句柄快照")
        {
            g_r3FallbackEntered.store(true, std::memory_order_release);
            g_cancelRequested.store(true, std::memory_order_release);
        }
    };
    emptyOptions.cancellationCallback = []()
    {
        return g_cancelRequested.load(std::memory_order_acquire);
    };
    (void)ks::file::ScanHandleUsageByPaths({ kTargetPath }, emptyOptions);
    if (!g_kernelEnumerationCompleted.load(std::memory_order_acquire))
    {
        return 2;
    }
    if (g_r3FallbackEntered.load(std::memory_order_acquire))
    {
        return 1;
    }

    g_scenario.store(kTypedHandleScenario, std::memory_order_release);
    g_kernelEnumerationCompleted.store(false, std::memory_order_release);
    g_r3FallbackEntered.store(false, std::memory_order_release);
    g_cancelRequested.store(false, std::memory_order_release);
    g_objectQueryCount.store(0, std::memory_order_release);
    g_activeObjectQueryCount.store(0, std::memory_order_release);
    g_peakObjectQueryCount.store(0, std::memory_order_release);

    ks::file::HandleUsageScanOptions typedOptions{};
    typedOptions.tryKernelHandleTable = true;
    typedOptions.progressCallback = [](const std::string& stepText, float)
    {
        if (stepText == "准备抓取系统句柄快照")
        {
            g_r3FallbackEntered.store(true, std::memory_order_release);
        }
    };
    const ks::file::HandleUsageScanResult result =
        ks::file::ScanHandleUsageByPaths({ kTargetPath }, typedOptions);
    const std::uint32_t queryCount = g_objectQueryCount.load(std::memory_order_acquire);
    const std::uint32_t peakQueryCount = g_peakObjectQueryCount.load(std::memory_order_acquire);
    const bool hasEnumFailureDiagnostic =
        result.diagnosticText.find(L"R0枚举失败进程:") != std::wstring::npos;
    const std::size_t objectFailureDiagnosticCount =
        DiagnosticCount(result.diagnosticText, L"R0对象查询失败:");

    std::cout << "R3_FALLBACK=" << (g_r3FallbackEntered.load() ? 1 : 0) << '\n'
              << "OBJECT_QUERIES=" << queryCount << '\n'
              << "PEAK_OBJECT_QUERIES=" << peakQueryCount << '\n'
              << "FILE_LIKE_HANDLES=" << result.fileLikeHandleCount << '\n'
              << "MATCHED_HANDLES=" << result.matchedHandleCount << '\n'
              << "ENUM_CHURN_REPORTED_AS_ERROR=" << (hasEnumFailureDiagnostic ? 1 : 0) << '\n'
              << "OBJECT_FAILURES=" << objectFailureDiagnosticCount << '\n';

    if (g_r3FallbackEntered.load(std::memory_order_acquire))
    {
        return 3;
    }
    if (queryCount > kFileHandleCount + 2)
    {
        return 4;
    }
    if (hasEnumFailureDiagnostic)
    {
        return 8;
    }
    if (objectFailureDiagnosticCount != 1U)
    {
        return 9;
    }
    if (peakQueryCount < 2)
    {
        return 7;
    }
    if (result.fileLikeHandleCount != kFileHandleCount)
    {
        return 5;
    }
    if (result.matchedHandleCount != 1)
    {
        return 6;
    }
    return 0;
}
