#include "ArkDriverClient.h"

#include <sstream>

namespace ksword::ark
{
    namespace
    {
        bool isUnsupportedHvmError(const unsigned long error)
        {
            return error == ERROR_INVALID_FUNCTION ||
                error == ERROR_NOT_SUPPORTED;
        }
    }

    HvmStatusResult DriverClient::queryHvmStatus() const
    {
        HvmStatusResult result{};
        KSWORD_ARK_QUERY_HVM_REQUEST request{};
        request.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        request.size = sizeof(request);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_HVM,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream << "HVM query status=" << result.response.queryStatus
            << ", state=0x" << std::hex << result.response.stateFlags
            << ", features=0x" << result.response.featureFlags
            << ", generation=" << std::dec << result.response.generation
            << ", processors=" << result.response.preparedProcessorCount
            << "/" << result.response.processorCount;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmControlResult DriverClient::controlHvm(
        const unsigned long command,
        const unsigned long expectedGeneration,
        const bool force,
        const bool allowNested,
        const bool uiConfirmed) const
    {
        HvmControlResult result{};
        KSWORD_ARK_CONTROL_HVM_REQUEST request{};
        request.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.command = command;
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
        }
        if (force)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_FORCE;
        }
        if (allowNested)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED;
        }
        request.confirmationToken =
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        request.expectedGeneration = expectedGeneration;

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_HVM,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream << "HVM control command=" << command
            << ", status=" << result.response.status
            << ", state=0x" << std::hex
            << result.response.newStateFlags
            << ", generation=" << std::dec
            << result.response.newGeneration
            << ", prepared="
            << result.response.preparedProcessorCount
            << ", passed="
            << result.response.selfTestPassedProcessorCount;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }
}
