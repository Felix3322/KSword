#include "ArkDriverClient.h"

#include <cstddef>
#include <sstream>
#include <string>

namespace
{
    void copyDispatchDriverName(
        wchar_t* destination,
        const std::size_t destinationChars,
        const std::wstring& source)
    {
        if (destination == nullptr || destinationChars == 0U)
        {
            return;
        }
        const std::size_t copyChars =
            source.size() < (destinationChars - 1U)
            ? source.size()
            : (destinationChars - 1U);
        for (std::size_t index = 0U; index < copyChars; ++index)
        {
            destination[index] = source[index];
        }
        destination[copyChars] = L'\0';
    }

    std::wstring fixedDispatchDriverName(
        const wchar_t* source,
        const std::size_t sourceChars)
    {
        std::size_t length = 0U;
        if (source == nullptr)
        {
            return std::wstring();
        }
        while (length < sourceChars && source[length] != L'\0')
        {
            ++length;
        }
        return std::wstring(source, length);
    }

    bool isUnsupportedDispatchIoctl(const unsigned long error)
    {
        return error == ERROR_INVALID_FUNCTION ||
            error == ERROR_NOT_SUPPORTED ||
            error == ERROR_INVALID_PARAMETER;
    }
}

namespace ksword::ark
{
    DriverDispatchControlResult DriverClient::controlDriverDispatch(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long action,
        const unsigned long majorFunction,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint64_t expectedCurrentDispatchAddress,
        const std::uint64_t desiredDispatchAddress,
        const std::uint32_t expectedGeneration,
        const bool uiConfirmed) const
    {
        DriverDispatchControlResult result{};
        KSWORD_ARK_DRIVER_DISPATCH_REQUEST request{};
        KSWORD_ARK_DRIVER_DISPATCH_RESPONSE response{};

        request.version = KSWORD_ARK_DRIVER_DISPATCH_PROTOCOL_VERSION;
        request.action = action;
        request.flags =
            KSWORD_ARK_DRIVER_DISPATCH_FLAG_TARGET_MODULE_BASE_PRESENT;
        request.majorFunction = majorFunction;
        request.targetModuleBase =
            static_cast<unsigned long long>(moduleBase);
        request.expectedDriverObjectAddress =
            static_cast<unsigned long long>(expectedDriverObjectAddress);
        request.expectedCurrentDispatchAddress =
            static_cast<unsigned long long>(expectedCurrentDispatchAddress);
        request.desiredDispatchAddress =
            static_cast<unsigned long long>(desiredDispatchAddress);
        request.expectedGeneration = expectedGeneration;

        if (expectedDriverObjectAddress != 0U)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_DRIVER_OBJECT_PRESENT;
        }
        if (action == KSWORD_ARK_DRIVER_DISPATCH_ACTION_APPLY)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_CURRENT_PRESENT;
        }
        if (expectedGeneration != 0U)
        {
            request.flags |=
                KSWORD_ARK_DRIVER_DISPATCH_FLAG_EXPECTED_GENERATION_PRESENT;
        }
        if (uiConfirmed)
        {
            request.flags |= KSWORD_ARK_DRIVER_DISPATCH_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_DRIVER_DISPATCH_CONFIRMATION_TOKEN;
        }
        copyDispatchDriverName(
            request.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
            canonicalDriverName);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_DRIVER_DISPATCH,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!result.io.ok)
        {
            result.unsupported =
                isUnsupportedDispatchIoctl(result.io.win32Error);
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_CONTROL_DRIVER_DISPATCH) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < sizeof(response))
        {
            result.io.ok = false;
            result.io.message =
                "driver-dispatch response too small, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
            return result;
        }
        if (response.version != KSWORD_ARK_DRIVER_DISPATCH_PROTOCOL_VERSION ||
            response.action != action ||
            response.majorFunction != majorFunction ||
            response.targetModuleBase != moduleBase ||
            (response.lastStatus >= 0 &&
             expectedDriverObjectAddress != 0U &&
             response.driverObjectAddress != expectedDriverObjectAddress))
        {
            result.io.ok = false;
            result.io.message = "driver-dispatch response protocol mismatch";
            return result;
        }

        result.version = response.version;
        result.action = response.action;
        result.state = response.state;
        result.responseFlags = response.responseFlags;
        result.lastStatus = response.lastStatus;
        result.majorFunction = response.majorFunction;
        result.generation = response.generation;
        result.targetModuleBase = response.targetModuleBase;
        result.driverObjectAddress = response.driverObjectAddress;
        result.currentDispatchAddress = response.currentDispatchAddress;
        result.originalDispatchAddress = response.originalDispatchAddress;
        result.appliedDispatchAddress = response.appliedDispatchAddress;
        result.requestedDispatchAddress = response.requestedDispatchAddress;
        result.selfDriverObjectAddress = response.selfDriverObjectAddress;
        result.driverName = fixedDispatchDriverName(
            response.driverName,
            KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        result.io.ntStatus = result.lastStatus;

        std::ostringstream stream;
        stream << "action=" << result.action
            << ", major=0x" << std::hex << result.majorFunction
            << ", status=0x" << static_cast<unsigned long>(result.lastStatus)
            << ", current=0x" << result.currentDispatchAddress
            << ", original=0x" << result.originalDispatchAddress
            << ", applied=0x" << result.appliedDispatchAddress
            << std::dec << ", generation=" << result.generation;
        result.io.message = stream.str();
        return result;
    }

    DriverDispatchControlResult DriverClient::queryDriverDispatch(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long majorFunction,
        const std::uint64_t expectedDriverObjectAddress) const
    {
        return controlDriverDispatch(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_DISPATCH_ACTION_QUERY,
            majorFunction,
            expectedDriverObjectAddress);
    }

    DriverDispatchControlResult DriverClient::applyDriverDispatch(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long majorFunction,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint64_t expectedCurrentDispatchAddress,
        const std::uint64_t desiredDispatchAddress,
        const std::uint32_t expectedGeneration) const
    {
        return controlDriverDispatch(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_DISPATCH_ACTION_APPLY,
            majorFunction,
            expectedDriverObjectAddress,
            expectedCurrentDispatchAddress,
            desiredDispatchAddress,
            expectedGeneration,
            true);
    }

    DriverDispatchControlResult DriverClient::restoreDriverDispatch(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long majorFunction,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration) const
    {
        return controlDriverDispatch(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_DISPATCH_ACTION_RESTORE,
            majorFunction,
            expectedDriverObjectAddress,
            0U,
            0U,
            expectedGeneration,
            false);
    }

    DriverDispatchControlResult DriverClient::abandonDriverDispatch(
        const std::uint64_t moduleBase,
        const std::wstring& canonicalDriverName,
        const unsigned long majorFunction,
        const std::uint64_t expectedDriverObjectAddress,
        const std::uint32_t expectedGeneration) const
    {
        return controlDriverDispatch(
            moduleBase,
            canonicalDriverName,
            KSWORD_ARK_DRIVER_DISPATCH_ACTION_ABANDON,
            majorFunction,
            expectedDriverObjectAddress,
            0U,
            0U,
            expectedGeneration,
            true);
    }
}
