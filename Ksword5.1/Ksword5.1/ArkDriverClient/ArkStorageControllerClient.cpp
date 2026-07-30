#include "ArkStorageControllerClient.h"

#include <SetupAPI.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <sstream>

namespace ksword::ark
{
    namespace
    {
        std::string formatWin32Failure(const char* operation, const unsigned long error)
        {
            std::ostringstream stream;
            stream << operation << " failed, error=" << error;
            return stream.str();
        }
    }

    ArkStorageControllerClient::~ArkStorageControllerClient()
    {
        close();
    }

    bool ArkStorageControllerClient::open(const std::uint32_t interfaceIndex)
    {
        static const GUID interfaceGuid =
            KSWORD_ARK_STORAGE_CONTROLLER_INTERFACE_GUID_INIT;
        HDEVINFO deviceInfo;
        SP_DEVICE_INTERFACE_DATA interfaceData{};
        DWORD requiredBytes = 0U;

        close();
        deviceInfo = SetupDiGetClassDevsW(
            &interfaceGuid,
            nullptr,
            nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (deviceInfo == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        interfaceData.cbSize = sizeof(interfaceData);
        if (SetupDiEnumDeviceInterfaces(
                deviceInfo,
                nullptr,
                &interfaceGuid,
                interfaceIndex,
                &interfaceData) == FALSE)
        {
            SetupDiDestroyDeviceInfoList(deviceInfo);
            return false;
        }
        SetupDiGetDeviceInterfaceDetailW(
            deviceInfo,
            &interfaceData,
            nullptr,
            0U,
            &requiredBytes,
            nullptr);
        if (requiredBytes < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W))
        {
            SetupDiDestroyDeviceInfoList(deviceInfo);
            return false;
        }
        std::vector<std::uint8_t> detailBuffer(requiredBytes, 0U);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(
            detailBuffer.data());
        detail->cbSize = sizeof(*detail);
        if (SetupDiGetDeviceInterfaceDetailW(
                deviceInfo,
                &interfaceData,
                detail,
                requiredBytes,
                nullptr,
                nullptr) == FALSE)
        {
            SetupDiDestroyDeviceInfoList(deviceInfo);
            return false;
        }
        m_handle = CreateFileW(
            detail->DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            0U,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        SetupDiDestroyDeviceInfoList(deviceInfo);
        return isOpen();
    }

    void ArkStorageControllerClient::close()
    {
        if (isOpen())
        {
            CloseHandle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
        }
    }

    bool ArkStorageControllerClient::isOpen() const noexcept
    {
        return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr;
    }

    StorageControllerIoResult ArkStorageControllerClient::invoke(
        const unsigned long ioctl,
        void* const input,
        const unsigned long inputBytes,
        void* const output,
        const unsigned long outputBytes) const
    {
        StorageControllerIoResult result;
        if (!isOpen())
        {
            result.win32Error = ERROR_INVALID_HANDLE;
            result.message = "controller companion is not open";
            return result;
        }
        DWORD bytesReturned = 0U;
        result.ok = DeviceIoControl(
            m_handle,
            ioctl,
            input,
            inputBytes,
            output,
            outputBytes,
            &bytesReturned,
            nullptr) != FALSE;
        result.bytesReturned = bytesReturned;
        result.win32Error = result.ok ? ERROR_SUCCESS : GetLastError();
        if (!result.ok)
        {
            result.message = formatWin32Failure("DeviceIoControl", result.win32Error);
        }
        return result;
    }

    StorageControllerQueryResult ArkStorageControllerClient::query() const
    {
        StorageControllerQueryResult result;
        KSWORD_ARK_QUERY_STORAGE_CONTROLLER_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
        request.size = sizeof(request);
        result.io = invoke(
            IOCTL_KSWORD_ARK_QUERY_STORAGE_CONTROLLER,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        return result;
    }

    StorageControllerControlResult ArkStorageControllerClient::acquire(
        const std::uint32_t expectedGeneration,
        const std::uint32_t timeoutMilliseconds) const
    {
        StorageControllerControlResult result;
        KSWORD_ARK_CONTROL_STORAGE_CONTROLLER_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.command = KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_ACQUIRE;
        request.flags =
            KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_EXCLUSIVE |
            KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_UI_CONFIRMED;
        request.expectedGeneration = expectedGeneration;
        request.confirmationToken = KSWORD_ARK_STORAGE_CONTROLLER_CONFIRMATION_TOKEN;
        request.timeoutMilliseconds = timeoutMilliseconds;
        result.io = invoke(
            IOCTL_KSWORD_ARK_CONTROL_STORAGE_CONTROLLER,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        return result;
    }

    StorageControllerControlResult ArkStorageControllerClient::release(
        const std::uint32_t expectedGeneration,
        const std::uint64_t sessionId) const
    {
        StorageControllerControlResult result;
        KSWORD_ARK_CONTROL_STORAGE_CONTROLLER_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.command = KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_RELEASE;
        request.expectedGeneration = expectedGeneration;
        request.expectedSessionId = sessionId;
        result.io = invoke(
            IOCTL_KSWORD_ARK_CONTROL_STORAGE_CONTROLLER,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        return result;
    }

    StorageControllerControlResult ArkStorageControllerClient::reset(
        const std::uint32_t expectedGeneration,
        const std::uint64_t sessionId,
        const std::uint32_t timeoutMilliseconds) const
    {
        StorageControllerControlResult result;
        KSWORD_ARK_CONTROL_STORAGE_CONTROLLER_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.command = KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_RESET;
        request.flags =
            KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_EXCLUSIVE |
            KSWORD_ARK_STORAGE_CONTROLLER_CONTROL_FLAG_UI_CONFIRMED;
        request.expectedGeneration = expectedGeneration;
        request.confirmationToken = KSWORD_ARK_STORAGE_CONTROLLER_CONFIRMATION_TOKEN;
        request.timeoutMilliseconds = timeoutMilliseconds;
        request.expectedSessionId = sessionId;
        result.io = invoke(
            IOCTL_KSWORD_ARK_CONTROL_STORAGE_CONTROLLER,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        return result;
    }

    StorageControllerTransferResult ArkStorageControllerClient::read(
        const std::uint32_t expectedGeneration,
        const std::uint64_t sessionId,
        const std::uint64_t offset,
        const std::uint32_t length,
        const std::uint32_t timeoutMilliseconds) const
    {
        StorageControllerTransferResult result;
        if (length == 0U ||
            length > KSWORD_ARK_STORAGE_CONTROLLER_MAX_TRANSFER_BYTES)
        {
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "read length is outside the protocol boundary";
            return result;
        }
        const std::size_t headerBytes =
            KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE_HEADER_SIZE;
        if (static_cast<std::size_t>(length) >
                std::numeric_limits<std::size_t>::max() - headerBytes ||
            headerBytes + static_cast<std::size_t>(length) >
                std::numeric_limits<unsigned long>::max())
        {
            result.io.win32Error = ERROR_ARITHMETIC_OVERFLOW;
            result.io.message = "read response size overflows the transport";
            return result;
        }
        KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
        request.size = KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST_HEADER_SIZE;
        request.operation = KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_READ;
        request.expectedGeneration = expectedGeneration;
        request.length = length;
        request.timeoutMilliseconds = timeoutMilliseconds;
        request.sessionId = sessionId;
        request.offset = offset;
        const std::size_t responseBytes =
            headerBytes + static_cast<std::size_t>(length);
        std::vector<std::uint8_t> responseBuffer(responseBytes, 0U);
        result.io = invoke(
            IOCTL_KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER,
            &request,
            KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST_HEADER_SIZE,
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (result.io.bytesReturned >=
            KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE_HEADER_SIZE)
        {
            const auto* response =
                reinterpret_cast<const KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE*>(
                    responseBuffer.data());
            std::memcpy(
                &result.response,
                response,
                KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE_HEADER_SIZE);
            const std::size_t available =
                result.io.bytesReturned -
                KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE_HEADER_SIZE;
            const std::size_t completed = std::min<std::size_t>(
                response->bytesTransferred,
                available);
            result.bytes.assign(response->data, response->data + completed);
        }
        return result;
    }

    StorageControllerTransferResult ArkStorageControllerClient::write(
        const std::uint32_t expectedGeneration,
        const std::uint64_t sessionId,
        const std::uint64_t offset,
        const std::vector<std::uint8_t>& bytes,
        const std::vector<std::uint8_t>& expectedBeforeHash,
        const std::uint32_t flags,
        const std::uint32_t timeoutMilliseconds) const
    {
        StorageControllerTransferResult result;
        if (bytes.empty() ||
            bytes.size() > KSWORD_ARK_STORAGE_CONTROLLER_MAX_TRANSFER_BYTES ||
            bytes.size() > std::numeric_limits<unsigned long>::max())
        {
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "write payload is outside the protocol boundary";
            return result;
        }
        const std::size_t requestBytes =
            KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST_HEADER_SIZE +
            bytes.size();
        std::vector<std::uint8_t> requestBuffer(requestBytes, 0U);
        auto* request =
            reinterpret_cast<KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST*>(
                requestBuffer.data());
        request->version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
        request->size = static_cast<unsigned long>(requestBytes);
        request->operation = KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_WRITE;
        request->flags =
            flags |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_UI_CONFIRMED |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_VERIFY |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FLUSH;
        request->expectedGeneration = expectedGeneration;
        request->length = static_cast<unsigned long>(bytes.size());
        request->confirmationToken = KSWORD_ARK_STORAGE_CONTROLLER_CONFIRMATION_TOKEN;
        request->timeoutMilliseconds = timeoutMilliseconds;
        request->sessionId = sessionId;
        request->offset = offset;
        if (expectedBeforeHash.size() ==
            KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES)
        {
            std::memcpy(
                request->expectedBeforeHash,
                expectedBeforeHash.data(),
                expectedBeforeHash.size());
            request->flags |=
                KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_EXPECT_BEFORE_HASH;
        }
        std::memcpy(request->data, bytes.data(), bytes.size());
        result.io = invoke(
            IOCTL_KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            &result.response,
            KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE_HEADER_SIZE);
        return result;
    }

    StorageControllerTransferResult ArkStorageControllerClient::rollback(
        const std::uint32_t expectedGeneration,
        const std::uint64_t sessionId,
        const std::uint64_t offset,
        const std::uint32_t length,
        const std::uint32_t timeoutMilliseconds) const
    {
        StorageControllerTransferResult result;
        KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
        request.size = KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST_HEADER_SIZE;
        request.operation = KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_ROLLBACK;
        request.flags =
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_UI_CONFIRMED |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FLUSH |
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_VERIFY;
        request.expectedGeneration = expectedGeneration;
        request.length = length;
        request.confirmationToken = KSWORD_ARK_STORAGE_CONTROLLER_CONFIRMATION_TOKEN;
        request.timeoutMilliseconds = timeoutMilliseconds;
        request.sessionId = sessionId;
        request.offset = offset;
        result.io = invoke(
            IOCTL_KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER,
            &request,
            KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_REQUEST_HEADER_SIZE,
            &result.response,
            KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE_HEADER_SIZE);
        return result;
    }

    StorageControllerAuditResult ArkStorageControllerClient::queryAudit(
        const std::uint64_t afterSequence) const
    {
        StorageControllerAuditResult result;
        KSWORD_ARK_QUERY_STORAGE_CONTROLLER_AUDIT_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_CONTROLLER_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.maximumRows = KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROWS;
        request.afterSequence = afterSequence;
        result.io = invoke(
            IOCTL_KSWORD_ARK_QUERY_STORAGE_CONTROLLER_AUDIT,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        return result;
    }
}
