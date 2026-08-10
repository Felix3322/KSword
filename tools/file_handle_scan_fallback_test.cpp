// Regression harness for the R0 file-handle scan policy and query volume.
//
// The fake DriverClient covers two production bugs:
// 1. A successful R0 enumeration with zero target matches must not fall back to
//    the much slower R3 DuplicateHandle path.
// 2. Once an object type index is known to be non-File, later handles of that
//    type must be skipped without another R0 object-name query. File-like
//    counts must describe all File handles examined, not only target matches.

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
    constexpr wchar_t kTargetPath[] = L"C:\\ksword-regression\\occupied.dat";

    std::atomic_int g_scenario = kEmptyScenario;
    std::atomic_bool g_kernelEnumerationCompleted = false;
    std::atomic_bool g_r3FallbackEntered = false;
    std::atomic_bool g_cancelRequested = false;
    std::atomic_uint32_t g_objectQueryCount = 0;
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
        result.totalCount = 1;
        result.returnedCount = 1;
        return result;
    }

    HandleEnumResult DriverClient::enumerateProcessHandles(
        const std::uint32_t processId,
        unsigned long) const
    {
        HandleEnumResult result{};
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
            return result;
        }

        result.objectTypeIndex = kFileTypeIndex;
        result.typeName = L"File";
        if (handleValue == fileHandleBase)
        {
            result.objectName = kTargetPath;
        }
        else
        {
            result.objectName = L"C:\\ksword-regression\\other-" +
                std::to_wstring(handleValue - fileHandleBase) + L".dat";
        }
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

    std::cout << "R3_FALLBACK=" << (g_r3FallbackEntered.load() ? 1 : 0) << '\n'
              << "OBJECT_QUERIES=" << queryCount << '\n'
              << "FILE_LIKE_HANDLES=" << result.fileLikeHandleCount << '\n'
              << "MATCHED_HANDLES=" << result.matchedHandleCount << '\n';

    if (g_r3FallbackEntered.load(std::memory_order_acquire))
    {
        return 3;
    }
    if (queryCount > kFileHandleCount + 2)
    {
        return 4;
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
