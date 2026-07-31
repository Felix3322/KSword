#include "ArkDriverClient.h"

#include <sstream>

namespace ksword::ark
{
    namespace
    {
        // isUnsupportedSystemTimeError：
        // - 输入：DeviceIoControl 的 Win32 错误；
        // - 处理：识别旧驱动缺少 IOCTL 的兼容场景；
        // - 返回：可向 UI 显示“需要更新 R0”的布尔值。
        bool isUnsupportedSystemTimeError(const unsigned long error)
        {
            return error == ERROR_INVALID_FUNCTION ||
                error == ERROR_NOT_SUPPORTED;
        }
    }

    // querySystemTime：
    // - 调用：页面进入、周期刷新或控制前调用；
    // - 输入：无业务参数，只发送版本化查询包；
    // - 返回：完整系统变速状态和协议诊断。
    SystemTimeQueryResult DriverClient::querySystemTime() const
    {
        SystemTimeQueryResult result{};
        KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST request{};

        request.version =
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
        request.size = sizeof(request);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        result.unsupported = !result.io.ok &&
            isUnsupportedSystemTimeError(result.io.win32Error);

        if (result.io.ok &&
            (result.io.bytesReturned < sizeof(result.response) ||
             result.response.version !=
                KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
             result.response.size != sizeof(result.response)))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
        }
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream
            << "system-time query status="
            << result.response.status
            << ", flags=0x" << std::hex
            << result.response.stateFlags
            << ", generation=" << std::dec
            << result.response.generation
            << ", command=" << result.response.command
            << ", factor=" << result.response.factor
            << ", build=" << result.response.osBuildNumber;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    // controlSystemTime：
    // - 调用：用户确认后设置加速/减速，或无条件恢复 1x；
    // - 输入：命令、倍率、期望代次和 UI 确认状态；
    // - 返回：动作前后状态，所有设备访问仍封装在 ArkDriverClient。
    SystemTimeControlResult DriverClient::controlSystemTime(
        const unsigned long command,
        const unsigned long factor,
        const unsigned long expectedGeneration,
        const bool uiConfirmed) const
    {
        SystemTimeControlResult result{};
        KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST request{};

        request.version =
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.command = command;
        request.factor = factor;
        request.expectedGeneration = expectedGeneration;
        if (uiConfirmed)
        {
            request.flags |=
                KSWORD_ARK_SYSTEM_TIME_CONTROL_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_SYSTEM_TIME_CONFIRMATION_TOKEN;
        }

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_SYSTEM_TIME,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        result.unsupported = !result.io.ok &&
            isUnsupportedSystemTimeError(result.io.win32Error);

        if (result.io.ok &&
            (result.io.bytesReturned < sizeof(result.response) ||
             result.response.version !=
                KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
             result.response.size != sizeof(result.response)))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
        }
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream
            << "system-time control command="
            << command
            << ", requestedFactor=" << factor
            << ", status=" << result.response.status
            << ", oldFlags=0x" << std::hex
            << result.response.oldStateFlags
            << ", newFlags=0x"
            << result.response.newStateFlags
            << ", generation=" << std::dec
            << result.response.oldGeneration
            << "->" << result.response.newGeneration;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }
}
