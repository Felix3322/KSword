#include "ArkDriverClient.h"

#include <algorithm>
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
            << "/" << result.response.processorCount
            << ", vmExits=" << result.response.vmExitCount
            << ", lastExitReason=" << result.response.lastExitReason;
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
        const bool uiConfirmed,
        const bool enableEptEvents,
        const bool enableNestedVmx,
        const bool enableEvmcs) const
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
        if (enableEptEvents)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPT_EVENTS;
        }
        if (enableNestedVmx)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX;
        }
        if (enableEvmcs)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS;
        }
        if (command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST)
        {
            request.flags |= KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST;
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
            << result.response.selfTestPassedProcessorCount
            << ", vmExits=" << result.response.vmExitCount
            << ", lastExitReason=" << result.response.lastExitReason;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmEptRuleResult DriverClient::controlHvmEptRule(
        const unsigned long operation,
        const unsigned long expectedGeneration,
        const unsigned long ruleId,
        const unsigned long deniedAccess,
        const std::uint64_t physicalAddress,
        const std::uint64_t pageCount,
        const bool log,
        const bool allowOnce,
        const bool uiConfirmed) const
    {
        HvmEptRuleResult result{};
        KSWORD_ARK_HVM_EPT_RULE_REQUEST request{};
        request.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.operation = operation;
        request.expectedGeneration = expectedGeneration;
        request.ruleId = ruleId;
        request.deniedAccess = deniedAccess;
        request.physicalAddress = physicalAddress;
        request.pageCount = pageCount;
        if (log)
        {
            request.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG;
        }
        if (allowOnce)
        {
            request.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE;
        }
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        }

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HVM_EPT_RULE,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream << "HVM EPT operation=" << operation
            << ", status=" << result.response.status
            << ", implementation=" << result.response.implementation
            << ", ruleId=" << result.response.ruleId
            << ", ruleCount=" << result.response.ruleCount
            << ", generation=" << result.response.generation;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    HvmEventResult DriverClient::queryHvmEvents(
        const std::uint64_t afterSequence,
        const unsigned long maxRows,
        const bool clear) const
    {
        HvmEventResult result{};
        KSWORD_ARK_HVM_EVENT_QUERY_REQUEST request{};
        request.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.operation = clear
            ? KSWORD_ARK_HVM_EVENT_QUERY_CLEAR
            : KSWORD_ARK_HVM_EVENT_QUERY_READ;
        request.afterSequence = afterSequence;
        request.maxRows = (std::min)(
            maxRows,
            static_cast<unsigned long>(
                KSWORD_ARK_HVM_MAX_EVENT_ROWS));

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HVM_EVENTS,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedHvmError(result.io.win32Error);

        std::ostringstream stream;
        stream << "HVM event operation=" << request.operation
            << ", returned=" << result.response.returnedRows
            << ", available=" << result.response.availableRows
            << ", dropped=" << result.response.droppedRows
            << ", newest=" << result.response.newestSequence;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }
}
