// Regression harness for the R0 -> R3 file-handle scan fallback policy.
//
// A successful R0 enumeration with zero target matches is a valid empty result,
// not an unavailable backend. The fake DriverClient below makes that state
// deterministic and records whether production code unnecessarily enters the
// much slower R3 DuplicateHandle path.

#include "../Ksword5.1/Ksword5.1/ksword/file/file_handle_tools.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace
{
    std::atomic_bool g_kernelEnumerationCompleted = false;
    std::atomic_bool g_r3FallbackEntered = false;
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
        g_kernelEnumerationCompleted.store(true, std::memory_order_release);
        return result;
    }

    HandleObjectQueryResult DriverClient::queryHandleObject(
        std::uint32_t,
        std::uint64_t,
        unsigned long,
        unsigned long) const
    {
        return {};
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
    wchar_t executablePath[MAX_PATH] = {};
    const DWORD executablePathLength = ::GetModuleFileNameW(
        nullptr,
        executablePath,
        static_cast<DWORD>(std::size(executablePath)));
    if (executablePathLength == 0 || executablePathLength >= std::size(executablePath))
    {
        return 2;
    }

    std::thread scanThread([path = std::wstring(executablePath)]()
        {
            ks::file::HandleUsageScanOptions options{};
            options.tryKernelHandleTable = true;
            options.progressCallback = [](const std::string& stepText, float)
            {
                if (stepText == "准备抓取系统句柄快照")
                {
                    g_r3FallbackEntered.store(true, std::memory_order_release);
                }
            };
            (void)ks::file::ScanHandleUsageByPaths({ path }, options);
        });
    scanThread.detach();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (g_r3FallbackEntered.load(std::memory_order_acquire))
        {
            ::ExitProcess(1);
        }
        if (g_kernelEnumerationCompleted.load(std::memory_order_acquire))
        {
            // Give the production selector enough time to enter R3 after the
            // deterministic fake R0 result has returned.
            ::Sleep(100);
            ::ExitProcess(g_r3FallbackEntered.load(std::memory_order_acquire) ? 1U : 0U);
        }
        ::Sleep(1);
    }
    ::ExitProcess(3);
}
