#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <sstream>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        bool isRawDiskUnsupportedError(const unsigned long win32Error)
        {
            return win32Error == ERROR_INVALID_FUNCTION
                || win32Error == ERROR_NOT_SUPPORTED;
        }

        void describeRawDiskFailure(
            IoResult& io,
            bool& unsupported,
            const char* const operationName)
        {
            if (io.ok)
            {
                return;
            }

            unsupported = isRawDiskUnsupportedError(io.win32Error);
            std::ostringstream stream;
            stream << operationName << " failed, error=" << io.win32Error;
            if (unsupported)
            {
                stream << ", unsupported=true";
            }
            io.message = stream.str();
        }
    }

    RawDiskBackendResult DriverClient::queryRawDiskBackend(
        const unsigned long diskNumber,
        const unsigned long requestedBackend,
        const unsigned long flags) const
    {
        RawDiskBackendResult result{};
        KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.diskNumber = diskNumber;
        request.requestedBackend = requestedBackend;
        request.flags = flags;
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        describeRawDiskFailure(
            result.io,
            result.unsupported,
            "IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND");
        result.io.ntStatus = result.response.lastStatus;

        if (result.io.ok)
        {
            std::ostringstream stream;
            stream << "raw disk backend query disk=" << diskNumber
                << ", mask=0x" << std::hex << result.response.availableBackendMask
                << ", capabilities=0x" << result.response.capabilityFlags
                << ", status=" << std::dec << result.response.status;
            result.io.message = stream.str();
        }
        return result;
    }

    RawDiskReadResult DriverClient::readRawDisk(
        const unsigned long diskNumber,
        const unsigned long backend,
        const std::uint64_t offset,
        const unsigned long length,
        const unsigned long flags) const
    {
        RawDiskReadResult result{};
        if (length == 0UL || length > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "raw disk read length is outside the protocol boundary";
            return result;
        }

        KSWORD_ARK_RAW_DISK_READ_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.diskNumber = diskNumber;
        request.backend = backend;
        request.flags = flags;
        request.length = length;
        request.offset = offset;
        const std::size_t responseBytes =
            KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE
            + static_cast<std::size_t>(length);
        std::vector<std::uint8_t> responseBuffer(responseBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_READ_RAW_DISK,
            &request,
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        describeRawDiskFailure(
            result.io,
            result.unsupported,
            "IOCTL_KSWORD_ARK_READ_RAW_DISK");

        if (result.io.bytesReturned < KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE)
        {
            return result;
        }

        const auto* response =
            reinterpret_cast<const KSWORD_ARK_RAW_DISK_READ_RESPONSE*>(responseBuffer.data());
        result.status = response->status;
        result.backendUsed = response->backendUsed;
        result.logicalSectorSize = response->logicalSectorSize;
        result.io.ntStatus = response->lastStatus;
        const std::size_t availableBytes =
            static_cast<std::size_t>(result.io.bytesReturned)
            - KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        const std::size_t completedBytes = std::min<std::size_t>(
            response->bytesTransferred,
            availableBytes);
        result.bytes.assign(
            response->data,
            response->data + static_cast<std::ptrdiff_t>(completedBytes));

        if (result.io.ok)
        {
            std::ostringstream stream;
            stream << "raw disk read disk=" << diskNumber
                << ", backend=" << backend
                << ", offset=" << offset
                << ", bytes=" << result.bytes.size();
            result.io.message = stream.str();
        }
        return result;
    }

    RawDiskWriteResult DriverClient::writeRawDisk(
        const unsigned long diskNumber,
        const unsigned long backend,
        const std::uint64_t offset,
        const std::vector<std::uint8_t>& bytes,
        const unsigned long flags) const
    {
        RawDiskWriteResult result{};
        if (bytes.empty()
            || bytes.size() > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES
            || bytes.size() > static_cast<std::size_t>(std::numeric_limits<unsigned long>::max()))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "raw disk write length is outside the protocol boundary";
            return result;
        }

        const std::size_t requestBytes =
            KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE + bytes.size();
        std::vector<std::uint8_t> requestBuffer(requestBytes, 0U);
        auto* request =
            reinterpret_cast<KSWORD_ARK_RAW_DISK_WRITE_REQUEST*>(requestBuffer.data());
        request->version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
        request->size = static_cast<unsigned long>(requestBytes);
        request->diskNumber = diskNumber;
        request->backend = backend;
        request->flags = flags;
        request->length = static_cast<unsigned long>(bytes.size());
        request->confirmationToken = KSWORD_ARK_RAW_DISK_CONFIRMATION_TOKEN;
        request->offset = offset;
        std::memcpy(request->data, bytes.data(), bytes.size());
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_WRITE_RAW_DISK,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            &result.response,
            sizeof(result.response));
        describeRawDiskFailure(
            result.io,
            result.unsupported,
            "IOCTL_KSWORD_ARK_WRITE_RAW_DISK");
        result.io.ntStatus = result.response.lastStatus;

        if (result.io.ok)
        {
            std::ostringstream stream;
            stream << "raw disk write disk=" << diskNumber
                << ", backend=" << backend
                << ", offset=" << offset
                << ", transferred=" << result.response.bytesTransferred
                << ", status=" << result.response.status;
            result.io.message = stream.str();
        }
        return result;
    }
}
