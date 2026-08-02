#include "ArkDriverClient.h"

#include <cstring>
#include <limits>

namespace ksword::ark
{
    IoResult DriverClient::setBugcheckBitmap(
        const std::uint32_t width,
        const std::uint32_t height,
        const std::uint32_t stride,
        const std::uint32_t brandColorRgb,
        const std::vector<std::uint8_t>& bgraPixels) const
    {
        IoResult result{};
        const std::uint64_t expectedStride = static_cast<std::uint64_t>(width) * 4ULL;
        const std::uint64_t expectedBytes = expectedStride * static_cast<std::uint64_t>(height);

        if (width == 0 || height == 0 ||
            width > KSWORD_ARK_BUGCHECK_BITMAP_MAX_WIDTH ||
            height > KSWORD_ARK_BUGCHECK_BITMAP_MAX_HEIGHT ||
            stride != expectedStride ||
            expectedBytes == 0 ||
            expectedBytes > KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES ||
            bgraPixels.size() != static_cast<std::size_t>(expectedBytes))
        {
            result.win32Error = ERROR_INVALID_PARAMETER;
            return result;
        }

        const std::size_t payloadBytes = sizeof(KSWORD_ARK_BUGCHECK_BITMAP_HEADER) + bgraPixels.size();
        if (payloadBytes > std::numeric_limits<unsigned long>::max())
        {
            result.win32Error = ERROR_ARITHMETIC_OVERFLOW;
            return result;
        }

        KSWORD_ARK_BUGCHECK_BITMAP_HEADER header{};
        header.version = KSWORD_ARK_BUGCHECK_BITMAP_PROTOCOL_VERSION;
        header.size = sizeof(header);
        header.magic = KSWORD_ARK_BUGCHECK_BITMAP_MAGIC;
        header.width = width;
        header.height = height;
        header.stride = stride;
        header.format = KSWORD_ARK_BUGCHECK_BITMAP_FORMAT_BGRA32;
        header.brandColorRgb = brandColorRgb & 0x00FFFFFFUL;
        header.dataLength = static_cast<unsigned long>(bgraPixels.size());

        std::vector<std::uint8_t> payload(payloadBytes);
        std::memcpy(payload.data(), &header, sizeof(header));
        std::memcpy(payload.data() + sizeof(header), bgraPixels.data(), bgraPixels.size());

        return deviceIoControl(
            IOCTL_KSWORD_ARK_SET_BUGCHECK_BITMAP,
            payload.data(),
            static_cast<unsigned long>(payload.size()),
            nullptr,
            0);
    }
    BugcheckGuardResult DriverClient::configureBugcheckGuard(
        const unsigned long action,
        const unsigned long delaySeconds,
        const bool uiConfirmed,
        const bool tryIgnoreError,
        DriverHandle* const existingHandle) const
    {
        BugcheckGuardResult result{};
        KSWORD_ARK_BUGCHECK_GUARD_REQUEST request{};

        request.size = sizeof(request);
        request.version = KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION;
        request.action = action;
        request.delaySeconds = delaySeconds;
        if (uiConfirmed) {
            request.flags = KSWORD_ARK_BUGCHECK_GUARD_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_BUGCHECK_GUARD_CONFIRMATION_TOKEN;
        }
        if (tryIgnoreError) {
            request.flags |= KSWORD_ARK_BUGCHECK_GUARD_FLAG_TRY_IGNORE_ERROR;
        }
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONFIGURE_BUGCHECK_GUARD,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)),
            existingHandle);
        result.unsupported = !result.io.ok &&
            (result.io.win32Error == ERROR_INVALID_FUNCTION ||
             result.io.win32Error == ERROR_NOT_SUPPORTED);
        if (result.io.ok &&
            (result.io.bytesReturned < sizeof(result.response) ||
             result.response.version != KSWORD_ARK_BUGCHECK_GUARD_PROTOCOL_VERSION ||
             result.response.size != sizeof(result.response))) {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
        }
        result.io.ntStatus = result.response.lastStatus;
        return result;
    }
}
