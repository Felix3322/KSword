#pragma once

// ============================================================
// ProcessAffinityUtils.h
// 作用：
// - 为进程列表右键菜单与进程详细信息窗口提供一致的 CPU 亲和性读写入口；
// - 只封装当前 Windows processor group 的 Get/SetProcessAffinityMask 语义；
// - 调用方负责把掩码映射为具体 UI 与用户可见状态。
// ============================================================

#include <string>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace ks::process
{
    struct ProcessAffinityMasks
    {
        ULONG_PTR processMask = 0; // processMask：当前进程已启用的逻辑核心位图。
        ULONG_PTR systemMask = 0;  // systemMask：当前 processor group 中可分配的逻辑核心位图。
    };

    inline bool QueryProcessAffinityMasks(
        const DWORD processId,
        ProcessAffinityMasks* const masksOut,
        std::string* const detailTextOut)
    {
        if (masksOut == nullptr || processId == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid process affinity query input";
            }
            return false;
        }

        *masksOut = ProcessAffinityMasks{};
        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (processHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "OpenProcess(PROCESS_QUERY_INFORMATION) failed(" +
                    std::to_string(::GetLastError()) + ")";
            }
            return false;
        }

        const BOOL queryOk = ::GetProcessAffinityMask(
            processHandle,
            &masksOut->processMask,
            &masksOut->systemMask);
        const DWORD errorCode = queryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(processHandle);

        if (queryOk == FALSE || masksOut->systemMask == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = queryOk == FALSE
                    ? "GetProcessAffinityMask failed(" + std::to_string(errorCode) + ")"
                    : "GetProcessAffinityMask returned an empty system mask";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    inline bool SetProcessAffinityMaskByPid(
        const DWORD processId,
        const ULONG_PTR requestedMask,
        std::string* const detailTextOut)
    {
        if (processId == 0U || requestedMask == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid process affinity update input";
            }
            return false;
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
            FALSE,
            processId);
        if (processHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_SET_INFORMATION) failed(" +
                    std::to_string(::GetLastError()) + ")";
            }
            return false;
        }

        ULONG_PTR currentMask = 0;
        ULONG_PTR systemMask = 0;
        if (::GetProcessAffinityMask(processHandle, &currentMask, &systemMask) == FALSE)
        {
            const DWORD errorCode = ::GetLastError();
            ::CloseHandle(processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "GetProcessAffinityMask failed(" + std::to_string(errorCode) + ")";
            }
            return false;
        }

        if ((requestedMask & ~systemMask) != 0U)
        {
            ::CloseHandle(processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "requested affinity mask contains unavailable logical processors";
            }
            return false;
        }

        if (currentMask == requestedMask)
        {
            ::CloseHandle(processHandle);
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "unchanged";
            }
            return true;
        }

        const BOOL setOk = ::SetProcessAffinityMask(processHandle, requestedMask);
        const DWORD errorCode = setOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(processHandle);
        if (setOk == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "SetProcessAffinityMask failed(" + std::to_string(errorCode) + ")";
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }
}
