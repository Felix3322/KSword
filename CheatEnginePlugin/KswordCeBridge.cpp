#include "KswordCeBridge.h"

#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace ksword::ce
{
    namespace
    {
        // BridgeState 用途：集中保存 CE 函数槽、原实现和代理句柄到 PID 的映射。
        struct BridgeState
        {
            std::mutex mutex;
            ExportedFunctions* exportedFunctions = nullptr;
            int pluginId = -1;
            int pointerChangeRegistrationId = -1;
            ReadProcessMemoryFunction originalReadProcessMemory = nullptr;
            WriteProcessMemoryFunction originalWriteProcessMemory = nullptr;
            OpenProcessFunction originalOpenProcess = nullptr;
            VirtualQueryExFunction originalVirtualQueryEx = nullptr;
            std::unordered_map<HANDLE, DWORD> proxyProcessIds;
            bool initialized = false;
        };

        BridgeState g_bridgeState; // g_bridgeState：插件进程内唯一桥接状态。
        const ksword::ark::DriverClient g_driverClient; // g_driverClient：统一 KSword R3 驱动入口。

        // showCeMessage：调用 CE 自带消息框，避免插件引入额外 GUI 框架。
        void showCeMessage(char* const message)
        {
            ShowMessageFunction showMessage = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
                if (g_bridgeState.exportedFunctions != nullptr)
                {
                    showMessage = g_bridgeState.exportedFunctions->showMessage;
                }
            }
            if (showMessage != nullptr)
            {
                showMessage(message);
            }
        }

        // resolveProcessId：
        // - 输入：CE 传入的真实进程句柄或代理事件句柄。
        // - 处理：优先查代理映射，再查询真实句柄，最后使用 CE 当前 PID。
        // - 返回：可用于 KSword IOCTL 的 PID；无法解析时返回 0。
        DWORD resolveProcessId(const HANDLE processHandle)
        {
            ULONG* openedProcessId = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
                const auto proxyIterator =
                    g_bridgeState.proxyProcessIds.find(processHandle);
                if (proxyIterator != g_bridgeState.proxyProcessIds.end())
                {
                    return proxyIterator->second;
                }
                if (g_bridgeState.exportedFunctions != nullptr)
                {
                    openedProcessId =
                        g_bridgeState.exportedFunctions->openedProcessId;
                }
            }

            // resolvedProcessId 用途：保存 GetProcessId 对真实句柄的解析结果。
            const DWORD resolvedProcessId = ::GetProcessId(processHandle);
            if (resolvedProcessId != 0U)
            {
                return resolvedProcessId;
            }
            if (openedProcessId != nullptr)
            {
                return static_cast<DWORD>(*openedProcessId);
            }
            return 0U;
        }

        // bridgeOpenProcess：
        // - 输入：CE 的 OpenProcess 参数。
        // - 处理：先保留正常句柄语义；权限不足时创建可 CloseHandle 的代理句柄。
        // - 返回：真实句柄或映射到 PID 的事件句柄。
        HANDLE WINAPI bridgeOpenProcess(
            const DWORD desiredAccess,
            const BOOL inheritHandle,
            const DWORD processId)
        {
            OpenProcessFunction originalOpenProcess = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
                originalOpenProcess = g_bridgeState.originalOpenProcess;
            }

            // processHandle 用途：优先保存 CE 原有 OpenProcess 返回的正常句柄。
            HANDLE processHandle = nullptr;
            if (originalOpenProcess != nullptr)
            {
                processHandle =
                    originalOpenProcess(desiredAccess, inheritHandle, processId);
                if (processHandle == nullptr)
                {
                    processHandle = originalOpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                        inheritHandle,
                        processId);
                }
            }
            if (processHandle != nullptr)
            {
                // 真实句柄值可能复用旧代理句柄数值，先删除可能过期的 PID 映射。
                std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
                g_bridgeState.proxyProcessIds.erase(processHandle);
                return processHandle;
            }

            // proxyHandle 用途：让 CE 的打开流程继续，同时把实际访问交给 KSword R0。
            HANDLE proxyHandle = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (proxyHandle == nullptr)
            {
                return nullptr;
            }
            {
                std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
                g_bridgeState.proxyProcessIds[proxyHandle] = processId;
            }
            ::SetLastError(ERROR_SUCCESS);
            return proxyHandle;
        }

        // bridgeReadProcessMemory：
        // - 输入：CE 目标句柄、地址、输出缓冲和长度。
        // - 处理：按 R0 单次 1 MiB 上限分片，通过 DriverClient 读取。
        // - 返回：全部完成时 TRUE；部分复制时设置 ERROR_PARTIAL_COPY。
        BOOL WINAPI bridgeReadProcessMemory(
            const HANDLE processHandle,
            const LPCVOID baseAddress,
            const LPVOID buffer,
            const SIZE_T bytesToRead,
            SIZE_T* const bytesRead)
        {
            if (bytesRead != nullptr)
            {
                *bytesRead = 0U;
            }
            if (buffer == nullptr || (bytesToRead > 0U && baseAddress == nullptr))
            {
                ::SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            if (bytesToRead == 0U)
            {
                ::SetLastError(ERROR_SUCCESS);
                return TRUE;
            }

            // processId/totalBytesRead 用途：标识 R0 目标并累计跨分片结果。
            const DWORD processId = resolveProcessId(processHandle);
            SIZE_T totalBytesRead = 0U;
            if (processId == 0U)
            {
                ::SetLastError(ERROR_INVALID_HANDLE);
                return FALSE;
            }

            while (totalBytesRead < bytesToRead)
            {
                const SIZE_T remainingBytes = bytesToRead - totalBytesRead;
                const SIZE_T chunkSize = std::min<SIZE_T>(
                    remainingBytes,
                    static_cast<SIZE_T>(KSWORD_ARK_MEMORY_READ_MAX_BYTES));
                const auto currentAddress =
                    reinterpret_cast<std::uintptr_t>(baseAddress) +
                    totalBytesRead;
                const auto readResult = g_driverClient.readVirtualMemory(
                    processId,
                    static_cast<std::uint64_t>(currentAddress),
                    static_cast<std::uint32_t>(chunkSize),
                    0UL);

                // copiedBytes 用途：同时受响应计数、数据数组和当前分片长度约束。
                const SIZE_T copiedBytes = std::min<SIZE_T>(
                    chunkSize,
                    std::min<SIZE_T>(
                        static_cast<SIZE_T>(readResult.bytesRead),
                        readResult.data.size()));
                if (copiedBytes > 0U)
                {
                    std::memcpy(
                        static_cast<std::uint8_t*>(buffer) + totalBytesRead,
                        readResult.data.data(),
                        copiedBytes);
                    totalBytesRead += copiedBytes;
                }
                if (!readResult.io.ok || copiedBytes != chunkSize)
                {
                    break;
                }
            }

            if (bytesRead != nullptr)
            {
                *bytesRead = totalBytesRead;
            }
            const BOOL completed = totalBytesRead == bytesToRead ? TRUE : FALSE;
            ::SetLastError(completed != FALSE ? ERROR_SUCCESS : ERROR_PARTIAL_COPY);
            return completed;
        }

        // bridgeWriteProcessMemory：
        // - 输入：CE 目标句柄、地址、源缓冲和长度。
        // - 处理：按 R0 256 KiB 上限分片，标记为 CE 用户已确认的写操作。
        // - 返回：全部写入时 TRUE；不自动启用 FORCE，保留驱动安全边界。
        BOOL WINAPI bridgeWriteProcessMemory(
            const HANDLE processHandle,
            const LPVOID baseAddress,
            const LPCVOID buffer,
            const SIZE_T bytesToWrite,
            SIZE_T* const bytesWritten)
        {
            if (bytesWritten != nullptr)
            {
                *bytesWritten = 0U;
            }
            if (buffer == nullptr || (bytesToWrite > 0U && baseAddress == nullptr))
            {
                ::SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            if (bytesToWrite == 0U)
            {
                ::SetLastError(ERROR_SUCCESS);
                return TRUE;
            }

            // processId/totalBytesWritten 用途：标识 R0 目标并累计跨分片写入量。
            const DWORD processId = resolveProcessId(processHandle);
            SIZE_T totalBytesWritten = 0U;
            if (processId == 0U)
            {
                ::SetLastError(ERROR_INVALID_HANDLE);
                return FALSE;
            }

            while (totalBytesWritten < bytesToWrite)
            {
                const SIZE_T remainingBytes = bytesToWrite - totalBytesWritten;
                const SIZE_T chunkSize = std::min<SIZE_T>(
                    remainingBytes,
                    static_cast<SIZE_T>(KSWORD_ARK_MEMORY_WRITE_MAX_BYTES));
                const auto* chunkBegin =
                    static_cast<const std::uint8_t*>(buffer) +
                    totalBytesWritten;
                std::vector<std::uint8_t> chunk(
                    chunkBegin,
                    chunkBegin + chunkSize);
                const auto currentAddress =
                    reinterpret_cast<std::uintptr_t>(baseAddress) +
                    totalBytesWritten;
                const auto writeResult = g_driverClient.writeVirtualMemory(
                    processId,
                    static_cast<std::uint64_t>(currentAddress),
                    chunk,
                    KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED);

                // currentWritten 用途：限制驱动返回值不超过本次请求长度。
                const SIZE_T currentWritten = std::min<SIZE_T>(
                    chunkSize,
                    static_cast<SIZE_T>(writeResult.bytesWritten));
                totalBytesWritten += currentWritten;
                if (!writeResult.io.ok ||
                    writeResult.writeStatus != KSWORD_ARK_MEMORY_WRITE_STATUS_OK ||
                    currentWritten != chunkSize)
                {
                    break;
                }
            }

            if (bytesWritten != nullptr)
            {
                *bytesWritten = totalBytesWritten;
            }
            const BOOL completed =
                totalBytesWritten == bytesToWrite ? TRUE : FALSE;
            ::SetLastError(completed != FALSE ? ERROR_SUCCESS : ERROR_PARTIAL_COPY);
            return completed;
        }

        // bridgeVirtualQueryEx：
        // - 输入：CE 目标句柄、查询地址和 MEMORY_BASIC_INFORMATION 缓冲。
        // - 处理：调用 KSword R0 ZwQueryVirtualMemory 路径并转换固定响应。
        // - 返回：成功时返回结构大小；失败时返回 0。
        SIZE_T WINAPI bridgeVirtualQueryEx(
            const HANDLE processHandle,
            const LPCVOID address,
            PMEMORY_BASIC_INFORMATION const information,
            const SIZE_T informationLength)
        {
            if (information == nullptr ||
                informationLength < sizeof(MEMORY_BASIC_INFORMATION))
            {
                ::SetLastError(ERROR_BAD_LENGTH);
                return 0U;
            }

            // processId/queryResult 用途：解析目标并获取 R0 虚拟内存区域信息。
            const DWORD processId = resolveProcessId(processHandle);
            if (processId == 0U)
            {
                ::SetLastError(ERROR_INVALID_HANDLE);
                return 0U;
            }
            const auto queryResult = g_driverClient.queryVirtualMemory(
                processId,
                static_cast<std::uint64_t>(
                    reinterpret_cast<std::uintptr_t>(address)),
                0UL);
            if (!queryResult.io.ok ||
                (queryResult.fieldFlags & KSWORD_ARK_MEMORY_FIELD_BASIC_PRESENT) == 0U ||
                (queryResult.queryStatus != KSWORD_ARK_MEMORY_QUERY_STATUS_OK &&
                 queryResult.queryStatus != KSWORD_ARK_MEMORY_QUERY_STATUS_PARTIAL))
            {
                ::SetLastError(
                    queryResult.io.win32Error != ERROR_SUCCESS
                        ? queryResult.io.win32Error
                        : ERROR_PARTIAL_COPY);
                return 0U;
            }

            // result 用途：先完整清零，再将跨位宽协议字段收窄到当前 CE 架构。
            MEMORY_BASIC_INFORMATION result{};
            result.BaseAddress = reinterpret_cast<PVOID>(
                static_cast<std::uintptr_t>(queryResult.baseAddress));
            result.AllocationBase = reinterpret_cast<PVOID>(
                static_cast<std::uintptr_t>(queryResult.allocationBase));
            result.AllocationProtect =
                static_cast<DWORD>(queryResult.allocationProtect);
            result.RegionSize = static_cast<SIZE_T>(queryResult.regionSize);
            result.State = static_cast<DWORD>(queryResult.state);
            result.Protect = static_cast<DWORD>(queryResult.protect);
            result.Type = static_cast<DWORD>(queryResult.type);
            *information = result;
            ::SetLastError(ERROR_SUCCESS);
            return sizeof(MEMORY_BASIC_INFORMATION);
        }

        // installFunctionPointerHooks：保存当前实现并原子式覆盖 CE 函数槽。
        bool installFunctionPointerHooks()
        {
            ExportedFunctions* exportedFunctions =
                g_bridgeState.exportedFunctions;
            if (exportedFunctions == nullptr ||
                exportedFunctions->readProcessMemory == nullptr ||
                exportedFunctions->writeProcessMemory == nullptr ||
                exportedFunctions->openProcess == nullptr ||
                exportedFunctions->virtualQueryEx == nullptr)
            {
                return false;
            }

            // 各 slot 变量用途：CE 字段保存的是“函数指针变量的地址”，需要解引用后替换。
            auto* readSlot = exportedFunctions->readProcessMemory;
            auto* writeSlot = static_cast<WriteProcessMemoryFunction*>(
                exportedFunctions->writeProcessMemory);
            auto* openSlot = static_cast<OpenProcessFunction*>(
                exportedFunctions->openProcess);
            auto* querySlot = static_cast<VirtualQueryExFunction*>(
                exportedFunctions->virtualQueryEx);
            if (*readSlot != &bridgeReadProcessMemory)
            {
                g_bridgeState.originalReadProcessMemory = *readSlot;
                *readSlot = &bridgeReadProcessMemory;
            }
            if (*writeSlot != &bridgeWriteProcessMemory)
            {
                g_bridgeState.originalWriteProcessMemory = *writeSlot;
                *writeSlot = &bridgeWriteProcessMemory;
            }
            if (*openSlot != &bridgeOpenProcess)
            {
                g_bridgeState.originalOpenProcess = *openSlot;
                *openSlot = &bridgeOpenProcess;
            }
            if (*querySlot != &bridgeVirtualQueryEx)
            {
                g_bridgeState.originalVirtualQueryEx = *querySlot;
                *querySlot = &bridgeVirtualQueryEx;
            }
            return true;
        }
    }

    BOOL initializeBridge(
        ExportedFunctions* const exportedFunctions,
        const int pluginId)
    {
        if (exportedFunctions == nullptr ||
            exportedFunctions->sizeofExportedFunctions <
                static_cast<int>(kRequiredExportedFunctionsSize))
        {
            return FALSE;
        }

        // driverHandle 用途：初始化前验证读写控制句柄，失败时不修改 CE 函数表。
        auto driverHandle = g_driverClient.open();
        if (!driverHandle.isValid())
        {
            if (exportedFunctions->showMessage != nullptr)
            {
                char message[] =
                    "KSword CE Bridge: cannot open \\\\.\\KswordARKLog. "
                    "Load the KSword driver first.";
                exportedFunctions->showMessage(message);
            }
            return FALSE;
        }

        // 初始化状态与 hook 安装在同一临界区完成，避免 CE 工作线程看到半状态。
        {
            std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
            g_bridgeState.exportedFunctions = exportedFunctions;
            g_bridgeState.pluginId = pluginId;
            if (!installFunctionPointerHooks())
            {
                g_bridgeState.exportedFunctions = nullptr;
                g_bridgeState.pluginId = -1;
                return FALSE;
            }
            g_bridgeState.initialized = true;
        }

        // 回调注册可能同步进入 CE 代码，因此在桥接互斥锁外调用以避免重入死锁。
        if (exportedFunctions->registerFunction != nullptr)
        {
            FunctionPointerChangeInitialization initialization{};
            initialization.callbackRoutine = &notifyFunctionPointersChanged;
            const int registrationId = exportedFunctions->registerFunction(
                pluginId,
                PluginType::functionPointerChange,
                &initialization);
            std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
            g_bridgeState.pointerChangeRegistrationId = registrationId;
        }

        char message[] =
            "KSword CE Bridge enabled: process open, memory query, read and "
            "write now use the KSword driver.";
        showCeMessage(message);
        return TRUE;
    }

    BOOL disableBridge()
    {
        UnregisterFunction unregisterFunction = nullptr;
        int pluginId = -1;
        int registrationId = -1;
        {
            std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
            if (!g_bridgeState.initialized ||
                g_bridgeState.exportedFunctions == nullptr)
            {
                return TRUE;
            }

            // 恢复时只改仍指向本插件的槽，避免覆盖其他插件稍后安装的实现。
            ExportedFunctions* const exportedFunctions =
                g_bridgeState.exportedFunctions;
            auto* readSlot = exportedFunctions->readProcessMemory;
            auto* writeSlot = static_cast<WriteProcessMemoryFunction*>(
                exportedFunctions->writeProcessMemory);
            auto* openSlot = static_cast<OpenProcessFunction*>(
                exportedFunctions->openProcess);
            auto* querySlot = static_cast<VirtualQueryExFunction*>(
                exportedFunctions->virtualQueryEx);
            if (readSlot != nullptr && *readSlot == &bridgeReadProcessMemory)
            {
                *readSlot = g_bridgeState.originalReadProcessMemory;
            }
            if (writeSlot != nullptr && *writeSlot == &bridgeWriteProcessMemory)
            {
                *writeSlot = g_bridgeState.originalWriteProcessMemory;
            }
            if (openSlot != nullptr && *openSlot == &bridgeOpenProcess)
            {
                *openSlot = g_bridgeState.originalOpenProcess;
            }
            if (querySlot != nullptr && *querySlot == &bridgeVirtualQueryEx)
            {
                *querySlot = g_bridgeState.originalVirtualQueryEx;
            }

            // 保存注销参数后先清空状态，真正进入 CE 的调用放到互斥锁外。
            unregisterFunction = exportedFunctions->unregisterFunction;
            pluginId = g_bridgeState.pluginId;
            registrationId = g_bridgeState.pointerChangeRegistrationId;
            g_bridgeState.proxyProcessIds.clear();
            g_bridgeState.exportedFunctions = nullptr;
            g_bridgeState.pluginId = -1;
            g_bridgeState.pointerChangeRegistrationId = -1;
            g_bridgeState.initialized = false;
        }

        if (registrationId >= 0 && unregisterFunction != nullptr)
        {
            unregisterFunction(pluginId, registrationId);
        }
        return TRUE;
    }

    void __stdcall notifyFunctionPointersChanged(const int reserved)
    {
        UNREFERENCED_PARAMETER(reserved);
        std::lock_guard<std::mutex> lock(g_bridgeState.mutex);
        if (g_bridgeState.initialized)
        {
            (void)installFunctionPointerHooks();
        }
    }
}
