#include "ArkDriverClient.h"

#include <sstream>

namespace ksword::ark
{
    IdtBaselineRestoreResult DriverClient::restoreIdtBaseline(
        const std::uint16_t processorGroup,
        const std::uint8_t processorNumber,
        const std::uint8_t vector,
        const std::uint64_t expectedRawLow,
        const std::uint64_t expectedRawHigh,
        const bool force,
        const bool uiConfirmed) const
    {
        // Build a fixed request that binds restoration to the exact row the UI
        // displayed. The kernel performs an additional IDTR and compare-exchange check.
        IdtBaselineRestoreResult result{};
        KSWORD_ARK_RESTORE_IDT_BASELINE_REQUEST request{};
        KSWORD_ARK_RESTORE_IDT_BASELINE_RESPONSE response{};
        request.version = KSWORD_ARK_KERNEL_BASELINE_PROTOCOL_VERSION;
        request.size = sizeof(request);
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_IDT_RESTORE_FLAG_UI_CONFIRMED;
        }
        if (force)
        {
            request.flags |= KSWORD_ARK_IDT_RESTORE_FLAG_FORCE;
        }
        request.confirmationToken = KSWORD_ARK_IDT_RESTORE_CONFIRMATION_TOKEN;
        request.processorGroup = processorGroup;
        request.processorNumber = processorNumber;
        request.vector = vector;
        request.expectedRawLow = expectedRawLow;
        request.expectedRawHigh = expectedRawHigh;

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_RESTORE_IDT_BASELINE,
            &request,
            sizeof(request),
            &response,
            sizeof(response));
        result.unsupported = !result.io.ok &&
            (result.io.win32Error == ERROR_INVALID_FUNCTION ||
             result.io.win32Error == ERROR_NOT_SUPPORTED);
        result.status = response.status;
        result.baselineGeneration = response.baselineGeneration;
        result.lastStatus = response.lastStatus;
        result.entryAddress = response.entryAddress;
        result.beforeRawLow = response.beforeRawLow;
        result.beforeRawHigh = response.beforeRawHigh;
        result.baselineRawLow = response.baselineRawLow;
        result.baselineRawHigh = response.baselineRawHigh;
        result.afterRawLow = response.afterRawLow;
        result.afterRawHigh = response.afterRawHigh;
        result.io.ntStatus = response.lastStatus;

        std::ostringstream stream;
        stream << "IDT baseline " << (force ? "restore" : "preflight")
            << ", cpu=" << processorGroup << ":" << static_cast<unsigned int>(processorNumber)
            << ", vector=" << static_cast<unsigned int>(vector)
            << ", status=" << result.status
            << ", ntstatus=0x" << std::hex << static_cast<unsigned long>(result.lastStatus);
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }
}
