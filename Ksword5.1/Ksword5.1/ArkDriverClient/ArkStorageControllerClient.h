#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "../../../shared/driver/KswordArkStorageControllerIoctl.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::ark
{
    struct StorageControllerIoResult
    {
        bool ok = false;
        unsigned long win32Error = ERROR_SUCCESS;
        unsigned long bytesReturned = 0;
        std::string message;
    };

    struct StorageControllerQueryResult
    {
        StorageControllerIoResult io;
        KSWORD_ARK_QUERY_STORAGE_CONTROLLER_RESPONSE response{};
    };

    struct StorageControllerControlResult
    {
        StorageControllerIoResult io;
        KSWORD_ARK_CONTROL_STORAGE_CONTROLLER_RESPONSE response{};
    };

    struct StorageControllerTransferResult
    {
        StorageControllerIoResult io;
        KSWORD_ARK_TRANSFER_STORAGE_CONTROLLER_RESPONSE response{};
        std::vector<std::uint8_t> bytes;
    };

    struct StorageControllerAuditResult
    {
        StorageControllerIoResult io;
        KSWORD_ARK_QUERY_STORAGE_CONTROLLER_AUDIT_RESPONSE response{};
    };

    /*
     * This client targets only the separately installed PnP controller
     * companion.  It is intentionally not part of DriverClient, so a normal
     * KswordARK handle can never be mistaken for direct hardware ownership.
     */
    class ArkStorageControllerClient final
    {
    public:
        ArkStorageControllerClient() = default;
        ~ArkStorageControllerClient();

        ArkStorageControllerClient(const ArkStorageControllerClient&) = delete;
        ArkStorageControllerClient& operator=(const ArkStorageControllerClient&) = delete;

        bool open(std::uint32_t interfaceIndex = 0U);
        void close();
        bool isOpen() const noexcept;
        StorageControllerQueryResult query() const;
        StorageControllerControlResult acquire(
            std::uint32_t expectedGeneration,
            std::uint32_t timeoutMilliseconds = 5000U) const;
        StorageControllerControlResult release(
            std::uint32_t expectedGeneration,
            std::uint64_t sessionId) const;
        StorageControllerControlResult reset(
            std::uint32_t expectedGeneration,
            std::uint64_t sessionId,
            std::uint32_t timeoutMilliseconds = 5000U) const;
        StorageControllerTransferResult read(
            std::uint32_t expectedGeneration,
            std::uint64_t sessionId,
            std::uint64_t offset,
            std::uint32_t length,
            std::uint32_t timeoutMilliseconds = 5000U) const;
        StorageControllerTransferResult write(
            std::uint32_t expectedGeneration,
            std::uint64_t sessionId,
            std::uint64_t offset,
            const std::vector<std::uint8_t>& bytes,
            const std::vector<std::uint8_t>& expectedBeforeHash,
            std::uint32_t flags,
            std::uint32_t timeoutMilliseconds = 5000U) const;
        StorageControllerTransferResult rollback(
            std::uint32_t expectedGeneration,
            std::uint64_t sessionId,
            std::uint64_t offset,
            std::uint32_t length,
            std::uint32_t timeoutMilliseconds = 5000U) const;
        StorageControllerAuditResult queryAudit(
            std::uint64_t afterSequence = 0ULL) const;

    private:
        StorageControllerIoResult invoke(
            unsigned long ioctl,
            void* input,
            unsigned long inputBytes,
            void* output,
            unsigned long outputBytes) const;

        HANDLE m_handle = INVALID_HANDLE_VALUE;
    };
}
