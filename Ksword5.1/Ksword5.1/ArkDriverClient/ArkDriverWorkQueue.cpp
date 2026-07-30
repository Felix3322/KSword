#include "ArkDriverClient.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        constexpr std::size_t kWorkQueueHeaderSize =
            KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;

        bool isUnsupportedWorkQueueIoctlError(const unsigned long win32Error)
        {
            return win32Error == ERROR_INVALID_FUNCTION ||
                win32Error == ERROR_NOT_SUPPORTED ||
                win32Error == ERROR_INVALID_PARAMETER;
        }

        std::string boundedWorkQueueAnsi(
            const char* const text,
            const std::size_t capacity)
        {
            if (text == nullptr || capacity == 0U)
            {
                return {};
            }
            std::size_t length = 0U;
            while (length < capacity && text[length] != '\0')
            {
                ++length;
            }
            return std::string(text, text + length);
        }

        void rejectWorkQueueResponse(
            WorkQueueEnumResult* const result,
            const std::string& message)
        {
            if (result == nullptr)
            {
                return;
            }
            result->io.ok = false;
            result->io.win32Error = ERROR_INVALID_DATA;
            result->io.message = message;
            result->entries.clear();
        }

        bool workQueueHeaderIsConsistent(
            const KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE& header)
        {
            if (header.size != kWorkQueueHeaderSize ||
                header.version != KSWORD_ARK_WORK_QUEUE_PROTOCOL_VERSION ||
                header.queryStatus > KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED ||
                (header.statusFlags & ~KSWORD_ARK_WORK_QUEUE_STATUS_VALID_MASK) != 0UL ||
                header.entrySize != sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY) ||
                header.nodeCount > KSWORD_ARK_WORK_QUEUE_MAX_NODES ||
                header.returnedCount > header.totalCount ||
                header.reserved0 != 0UL ||
                header.reserved1 != 0UL ||
                header.reserved2 != 0UL)
            {
                return false;
            }

            const bool identityAndLayout =
                (header.statusFlags &
                 (KSWORD_ARK_WORK_QUEUE_STATUS_IDENTITY_MATCHED |
                  KSWORD_ARK_WORK_QUEUE_STATUS_LAYOUT_VALIDATED)) ==
                (KSWORD_ARK_WORK_QUEUE_STATUS_IDENTITY_MATCHED |
                 KSWORD_ARK_WORK_QUEUE_STATUS_LAYOUT_VALIDATED);
            if ((header.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK ||
                 header.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL) &&
                !identityAndLayout)
            {
                return false;
            }
            if (header.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK &&
                (header.statusFlags & KSWORD_ARK_WORK_QUEUE_STATUS_PARTIAL) != 0UL)
            {
                return false;
            }
            if (header.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL &&
                (header.statusFlags & KSWORD_ARK_WORK_QUEUE_STATUS_PARTIAL) == 0UL)
            {
                return false;
            }
            if (header.queryStatus != KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK &&
                header.queryStatus != KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL &&
                (header.returnedCount != 0UL || header.totalCount != 0UL))
            {
                return false;
            }
            return true;
        }

        bool workQueueEntryIsConsistent(
            const KSWORD_ARK_WORK_QUEUE_ENTRY& entry,
            const unsigned long nodeCount)
        {
            if (entry.size != sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY) ||
                (entry.rowKind != KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM &&
                 entry.rowKind != KSWORD_ARK_WORK_QUEUE_ROW_WORKER_THREAD) ||
                entry.queueType < KSWORD_ARK_WORK_QUEUE_TYPE_CRITICAL ||
                entry.queueType > KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER ||
                entry.nodeIndex >= nodeCount ||
                (entry.flags & ~KSWORD_ARK_WORK_QUEUE_ENTRY_VALID_MASK) != 0UL ||
                entry.status > KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED ||
                entry.reserved0 != 0UL ||
                entry.queueAddress == 0ULL ||
                (entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_QUEUE_VALIDATED) == 0UL)
            {
                return false;
            }

            if (entry.rowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM)
            {
                if (entry.queueType == KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER ||
                    entry.priorityIndex >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
                    entry.workItemAddress == 0ULL ||
                    entry.threadObject != 0ULL ||
                    entry.threadId != 0UL ||
                    entry.threadCreateTime100ns != 0ULL)
                {
                    return false;
                }
            }
            else if (entry.queueType != KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER ||
                     entry.priorityIndex != std::numeric_limits<unsigned long>::max() ||
                     entry.workItemAddress != 0ULL ||
                     entry.threadObject == 0ULL)
            {
                return false;
            }

            if ((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_PARAMETER_PRESENT) != 0UL &&
                entry.parameterAddress == 0ULL)
            {
                return false;
            }
            if (((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_ROUTINE_PRESENT) != 0UL) !=
                (entry.routineAddress != 0ULL) ||
                ((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_PARAMETER_PRESENT) != 0UL) !=
                (entry.parameterAddress != 0ULL))
            {
                return false;
            }
            if ((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_EXECUTABLE_SECTION) != 0UL &&
                (entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED) == 0UL)
            {
                return false;
            }
            if (((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED) != 0UL) !=
                (entry.moduleBase != 0ULL && entry.moduleSize != 0UL))
            {
                return false;
            }
            const bool threadIdentityPresent =
                entry.threadId != 0UL &&
                entry.threadCreateTime100ns != 0ULL;
            if (((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_IDENTITY_VALID) != 0UL) !=
                    threadIdentityPresent ||
                ((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_IDENTITY_VALID) != 0UL &&
                 (entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_REFERENCED) == 0UL))
            {
                return false;
            }
            if (entry.status == KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK &&
                ((entry.flags &
                  (KSWORD_ARK_WORK_QUEUE_ENTRY_ROUTINE_PRESENT |
                   KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED |
                   KSWORD_ARK_WORK_QUEUE_ENTRY_EXECUTABLE_SECTION)) !=
                 (KSWORD_ARK_WORK_QUEUE_ENTRY_ROUTINE_PRESENT |
                  KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED |
                  KSWORD_ARK_WORK_QUEUE_ENTRY_EXECUTABLE_SECTION)))
            {
                return false;
            }
            return true;
        }
    }

    WorkQueueEnumResult DriverClient::enumerateWorkQueues(
        const unsigned long flags,
        const unsigned long maxEntries) const
    {
        WorkQueueEnumResult result{};
        if (flags == 0UL ||
            (flags & ~KSWORD_ARK_WORK_QUEUE_FLAG_VALID_MASK) != 0UL ||
            maxEntries == 0UL ||
            maxEntries > KSWORD_ARK_WORK_QUEUE_MAX_ENTRIES)
        {
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "invalid work-queue enumeration arguments";
            return result;
        }

        KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_WORK_QUEUE_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxEntries = maxEntries;

        const std::size_t responseBytes =
            kWorkQueueHeaderSize +
            (static_cast<std::size_t>(maxEntries) *
             sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
        std::vector<std::uint8_t> responseBuffer(responseBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.unsupported = isUnsupportedWorkQueueIoctlError(result.io.win32Error);
            result.io.message = result.unsupported
                ? "IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE) failed, error=" +
                    std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < kWorkQueueHeaderSize ||
            result.io.bytesReturned > responseBuffer.size())
        {
            rejectWorkQueueResponse(
                &result,
                "work-queue response length is outside the fixed protocol boundary");
            return result;
        }

        const auto* const header =
            reinterpret_cast<const KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE*>(
                responseBuffer.data());
        if (!workQueueHeaderIsConsistent(*header) ||
            header->returnedCount > maxEntries)
        {
            rejectWorkQueueResponse(
                &result,
                "work-queue response header failed size/version/status/reserved/count validation");
            return result;
        }

        const std::size_t expectedBytes =
            kWorkQueueHeaderSize +
            (static_cast<std::size_t>(header->returnedCount) *
             sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
        if (expectedBytes != result.io.bytesReturned)
        {
            rejectWorkQueueResponse(
                &result,
                "work-queue response byte count does not match returnedCount");
            return result;
        }

        result.version = static_cast<std::uint32_t>(header->version);
        result.queryStatus = static_cast<std::uint32_t>(header->queryStatus);
        result.statusFlags = static_cast<std::uint32_t>(header->statusFlags);
        result.totalCount = static_cast<std::uint32_t>(header->totalCount);
        result.returnedCount = static_cast<std::uint32_t>(header->returnedCount);
        result.nodeCount = static_cast<std::uint32_t>(header->nodeCount);
        result.queuesVisited = static_cast<std::uint32_t>(header->queuesVisited);
        result.corruptListCount = static_cast<std::uint32_t>(header->corruptListCount);
        result.readFailureCount = static_cast<std::uint32_t>(header->readFailureCount);
        result.referenceFailureCount = static_cast<std::uint32_t>(header->referenceFailureCount);
        result.lastStatus = static_cast<long>(header->lastStatus);
        result.io.ntStatus = result.lastStatus;
        result.unsupported =
            result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED ||
            result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT ||
            result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_IDENTITY_MISMATCH;

        result.entries.reserve(header->returnedCount);
        for (std::size_t index = 0U;
             index < static_cast<std::size_t>(header->returnedCount);
             ++index)
        {
            const std::size_t entryOffset =
                kWorkQueueHeaderSize +
                (index * sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
            const auto* const source =
                reinterpret_cast<const KSWORD_ARK_WORK_QUEUE_ENTRY*>(
                    responseBuffer.data() + entryOffset);
            if (!workQueueEntryIsConsistent(*source, header->nodeCount))
            {
                rejectWorkQueueResponse(
                    &result,
                    "work-queue entry failed size/kind/flags/reserved/identity validation");
                return result;
            }

            WorkQueueEntry entry{};
            entry.rowKind = static_cast<std::uint32_t>(source->rowKind);
            entry.queueType = static_cast<std::uint32_t>(source->queueType);
            entry.priorityIndex = static_cast<std::uint32_t>(source->priorityIndex);
            entry.nodeIndex = static_cast<std::uint32_t>(source->nodeIndex);
            entry.flags = static_cast<std::uint32_t>(source->flags);
            entry.status = static_cast<std::uint32_t>(source->status);
            entry.queueAddress = static_cast<std::uint64_t>(source->queueAddress);
            entry.workItemAddress = static_cast<std::uint64_t>(source->workItemAddress);
            entry.routineAddress = static_cast<std::uint64_t>(source->routineAddress);
            entry.parameterAddress = static_cast<std::uint64_t>(source->parameterAddress);
            entry.threadObject = static_cast<std::uint64_t>(source->threadObject);
            entry.threadId = static_cast<std::uint32_t>(source->threadId);
            entry.threadCreateTime100ns =
                static_cast<std::uint64_t>(source->threadCreateTime100ns);
            entry.moduleBase = static_cast<std::uint64_t>(source->moduleBase);
            entry.moduleSize = static_cast<std::uint32_t>(source->moduleSize);
            entry.moduleName =
                boundedWorkQueueAnsi(source->moduleName, sizeof(source->moduleName));
            entry.modulePath =
                boundedWorkQueueAnsi(source->modulePath, sizeof(source->modulePath));
            result.entries.push_back(std::move(entry));
        }

        std::ostringstream stream;
        stream << "version=" << result.version
            << ", queryStatus=" << result.queryStatus
            << ", flags=0x" << std::hex << std::uppercase << result.statusFlags
            << std::dec << ", total=" << result.totalCount
            << ", returned=" << result.returnedCount
            << ", nodes=" << result.nodeCount
            << ", queues=" << result.queuesVisited
            << ", corrupt=" << result.corruptListCount
            << ", readFailures=" << result.readFailureCount
            << ", referenceFailures=" << result.referenceFailureCount
            << ", lastStatus=0x" << std::hex << std::uppercase
            << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }
}
