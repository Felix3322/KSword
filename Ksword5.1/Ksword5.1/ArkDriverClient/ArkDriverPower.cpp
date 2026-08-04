#include "ArkDriverClient.h"

#include <sstream>

namespace ksword::ark
{
    namespace
    {
        // isCpuPowerIoctlUnsupportedError：仅识别旧驱动未注册命令的明确 Win32 映射。
        bool isCpuPowerIoctlUnsupportedError(const unsigned long win32Error)
        {
            return win32Error == ERROR_INVALID_FUNCTION ||
                win32Error == ERROR_NOT_SUPPORTED;
        }

        // formatCpuPowerIoMessage：生成包含能力、flags 与语义状态的稳定诊断文本。
        std::string formatCpuPowerIoMessage(
            const char* operationName,
            const IoResult& io,
            const KSWORD_ARK_CPU_POWER_RESPONSE& response)
        {
            std::ostringstream stream;
            stream << operationName
                << ", ioctl=" << (io.ok ? "ok" : "fail")
                << ", win32=" << io.win32Error
                << ", bytes=" << io.bytesReturned
                << ", status=0x" << std::hex
                << static_cast<unsigned long>(response.lastStatus)
                << ", fields=0x" << response.fieldFlags
                << ", response=0x" << response.responseFlags
                << ", capability=0x" << response.capabilityFlags
                << std::dec
                << ", reason=" << response.failureReason
                << ", updated=" << response.updatedProcessorCount
                << ", failed=" << response.failedProcessorCount;
            return stream.str();
        }
    }

    CpuPowerResult DriverClient::queryCpuPowerState() const
    {
        // result.response 直接作为固定输出缓冲区。
        CpuPowerResult result{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_CPU_POWER,
            nullptr,
            0UL,
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        // 旧驱动兼容状态与 AMD/锁定等业务状态严格分离。
        result.unsupported = !result.io.ok &&
            isCpuPowerIoctlUnsupportedError(result.io.win32Error);
        if (result.io.bytesReturned >= sizeof(result.response))
        {
            result.io.ntStatus = result.response.lastStatus;
        }
        result.io.message = result.unsupported
            ? "IOCTL_KSWORD_ARK_QUERY_CPU_POWER unsupported by current driver"
            : formatCpuPowerIoMessage(
                "IOCTL_KSWORD_ARK_QUERY_CPU_POWER",
                result.io,
                result.response);
        return result;
    }

    CpuPowerResult DriverClient::controlCpuPower(
        const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST& request) const
    {
        // DeviceIoControl 需要非常量输入指针，mutableRequest 不改变调用方对象。
        KSWORD_ARK_CPU_POWER_CONTROL_REQUEST mutableRequest = request;
        CpuPowerResult result{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_CPU_POWER,
            &mutableRequest,
            static_cast<unsigned long>(sizeof(mutableRequest)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        // 参数/锁定/安全策略失败不能误报为“旧驱动”。
        result.unsupported = !result.io.ok &&
            isCpuPowerIoctlUnsupportedError(result.io.win32Error);
        if (result.io.bytesReturned >= sizeof(result.response))
        {
            result.io.ntStatus = result.response.lastStatus;
        }
        result.io.message = result.unsupported
            ? "IOCTL_KSWORD_ARK_CONTROL_CPU_POWER unsupported by current driver"
            : formatCpuPowerIoMessage(
                "IOCTL_KSWORD_ARK_CONTROL_CPU_POWER",
                result.io,
                result.response);
        return result;
    }
}
