#include "ArkDriverClient.h"

#include <cstddef>
#include <string>

namespace
{
    // copyDriverCommunicationName：
    // - 输入：R3 DriverObject 名称和 shared 协议固定缓冲；
    // - 处理：按字符边界复制并保证 NUL 终止；
    // - 返回：无；BLIND 时该名称是端到端目标身份的一部分。
    void copyDriverCommunicationName(
        wchar_t* destination,
        const std::size_t destinationChars,
        const std::wstring& source)
    {
        if (destination == nullptr || destinationChars == 0U)
        {
            return;
        }

        const std::size_t sourceChars = source.size();
        const std::size_t copyChars =
            sourceChars < (destinationChars - 1U)
            ? sourceChars
            : (destinationChars - 1U);
        for (std::size_t charIndex = 0U; charIndex < copyChars; ++charIndex)
        {
            destination[charIndex] = source[charIndex];
        }
        destination[copyChars] = L'\0';
    }

    // fixedDriverBlindWideToString：
    // - 输入：R0 固定宽字符数组和最大字符数；
    // - 处理：在第一个 NUL 或边界处停止，避免读取越界；
    // - 返回：安全构造的 std::wstring。
    std::wstring fixedDriverBlindWideToString(
        const wchar_t* source,
        const std::size_t sourceChars)
    {
        if (source == nullptr || sourceChars == 0U)
        {
            return std::wstring();
        }

        std::size_t textChars = 0U;
        while (textChars < sourceChars && source[textChars] != L'\0')
        {
            ++textChars;
        }
        return std::wstring(source, textChars);
    }
}

namespace ksword::ark
{
    DriverCommunicationControlResult DriverClient::controlDriverCommunication(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long action,
        const std::uint64_t expectedDriverObjectAddress) const
    {
        // 输入：已加载模块精确基址、canonical DriverObject 名称、对象地址和控制 action。
        // 处理：BLIND 用三元身份复核目标，原 MajorFunction 指针始终保留在 R0。
        // 返回：固定响应；lastStatus 表示业务结果，io 表示传输/协议结果。
        DriverCommunicationControlResult result{};
        result.action = action;
        result.targetedMask = KSWORD_ARK_DRIVER_COMMUNICATION_MAJOR_MASK_ALL;
        KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST request{};
        KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE response{};
        request.version = KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION;
        request.action = action;
        request.flags =
            KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_TARGET_MODULE_BASE_PRESENT |
            KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_UI_CONFIRMED;
        if (expectedDriverObjectAddress != 0U)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_COMMUNICATION_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT;
        }
        request.targetModuleBase = static_cast<unsigned long long>(moduleBase);
        request.expectedDriverObjectAddress =
            static_cast<unsigned long long>(expectedDriverObjectAddress);
        copyDriverCommunicationName(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            canonicalDriverName);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_DRIVER_COMMUNICATION,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!result.io.ok)
        {
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_CONTROL_DRIVER_COMMUNICATION) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < sizeof(response))
        {
            result.io.ok = false;
            result.io.message =
                "driver-communication response too small, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
            return result;
        }
        if (response.version != KSWORD_ARK_DRIVER_COMMUNICATION_PROTOCOL_VERSION)
        {
            result.io.ok = false;
            result.io.message =
                "driver-communication protocol mismatch, version=" +
                std::to_string(response.version);
            return result;
        }

        // 响应复制：所有字段均为只读诊断信息；地址不作为后续请求凭据。
        result.version = response.version;
        result.action = response.action;
        result.state = response.state;
        result.responseFlags = response.responseFlags;
        result.lastStatus = response.lastStatus;
        result.targetedMask = response.targetedMask;
        result.changedMask = response.changedMask;
        result.activeMask = response.activeMask;
        result.ownedMask = response.ownedMask;
        result.conflictMask = response.conflictMask;
        result.generation = response.generation;
        result.driverObjectAddress = response.driverObjectAddress;
        result.driverStart = response.driverStart;
        result.rejectDispatchAddress = response.rejectDispatchAddress;
        result.driverName = fixedDriverBlindWideToString(
            response.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        result.io.ntStatus = result.lastStatus;
        result.io.message = "driver-communication control completed";
        return result;
    }

    DriverCommunicationControlResult DriverClient::queryDriverCommunication(
        const std::uint64_t moduleBase,
        const std::wstring& displayName) const
    {
        // QUERY 不修改 R0 状态，只返回指定模块是否存在活动/冲突记录。
        return controlDriverCommunication(
            moduleBase,
            displayName,
            KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_QUERY,
            0U);
    }

    DriverCommunicationControlResult DriverClient::blindDriverCommunication(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const std::uint64_t expectedDriverObjectAddress) const
    {
        // BLIND 由 R0 safety policy 复核 UI_CONFIRMED 后事务替换五个通信槽。
        return controlDriverCommunication(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_BLIND,
            expectedDriverObjectAddress);
    }

    DriverCommunicationControlResult DriverClient::restoreDriverCommunication(
        const std::uint64_t moduleBase,
        const std::wstring& displayName) const
    {
        // RESTORE 是逃生路径，不依赖危险策略开关；R0 仅恢复仍由本功能接管的槽。
        return controlDriverCommunication(
            moduleBase,
            displayName,
            KSWORD_ARK_DRIVER_COMMUNICATION_ACTION_RESTORE,
            0U);
    }
}
