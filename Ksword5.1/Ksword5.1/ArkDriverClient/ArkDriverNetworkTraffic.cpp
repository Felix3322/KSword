#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        constexpr std::size_t kTrafficResponseBufferBytes = 1024U * 1024U;

        bool isUnsupportedTrafficIoctlError(const unsigned long win32Error)
        {
            return win32Error == ERROR_INVALID_FUNCTION ||
                win32Error == ERROR_NOT_SUPPORTED ||
                win32Error == ERROR_INVALID_PARAMETER;
        }

        void markTrafficIoctlUnavailable(
            NetworkTrafficPacketResult& result,
            const char* const operationName)
        {
            if (result.io.ok)
            {
                return;
            }

            result.unsupported = isUnsupportedTrafficIoctlError(result.io.win32Error);
            std::ostringstream stream;
            stream << "DeviceIoControl(" << operationName << ") failed, error="
                << result.io.win32Error;
            if (result.unsupported)
            {
                stream << ", unsupported=true";
            }
            result.io.message = stream.str();
        }

        void failTrafficProtocol(
            NetworkTrafficPacketResult& result,
            const char* const operationName,
            const std::string& reason)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = std::string(operationName) + " protocol validation failed: " + reason;
            result.entries.clear();
        }
    }

    NetworkTrafficPacketResult DriverClient::queryNetworkTrafficPackets(
        const std::uint64_t afterSequence,
        const unsigned long maxRows) const
    {
        constexpr const char* operationName =
            "IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS";
        constexpr std::size_t headerSize =
            sizeof(KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE) -
            sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW);
        constexpr unsigned long knownResponseFlags =
            KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP |
            KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED |
            KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET;
        constexpr unsigned long knownPacketFlags =
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV4 |
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV6 |
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED |
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_FRAGMENTED;

        NetworkTrafficPacketResult result{};
        KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST request{};
        request.version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.flags = KSWORD_ARK_NETWORK_TRAFFIC_QUERY_FLAG_NONE;
        request.maxRows = maxRows;
        request.afterSequence = afterSequence;

        std::vector<std::uint8_t> responseBuffer(kTrafficResponseBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS,
            &request,
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markTrafficIoctlUnavailable(result, operationName);
            return result;
        }

        if (result.io.bytesReturned < headerSize)
        {
            failTrafficProtocol(
                result,
                operationName,
                "response header truncated, bytesReturned=" + std::to_string(result.io.bytesReturned));
            return result;
        }

        const auto* response =
            reinterpret_cast<const KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE*>(responseBuffer.data());
        if (response->version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ||
            response->entrySize != sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW) ||
            response->size < headerSize ||
            response->size != result.io.bytesReturned ||
            (response->flags & ~knownResponseFlags) != 0UL ||
            response->reserved != 0UL)
        {
            failTrafficProtocol(
                result,
                operationName,
                "response ABI invalid, version=" + std::to_string(response->version) +
                ", entrySize=" + std::to_string(response->entrySize) +
                ", size=" + std::to_string(response->size) +
                ", flags=" + std::to_string(response->flags));
            return result;
        }

        if (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            response->status != KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE &&
            response->status != KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED)
        {
            failTrafficProtocol(
                result,
                operationName,
                "response status invalid, status=" + std::to_string(response->status));
            return result;
        }

        const unsigned long effectiveRequestedRows =
            maxRows == 0UL
            ? KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS
            : std::min<unsigned long>(
                maxRows,
                KSWORD_ARK_NETWORK_TRAFFIC_MAX_REQUESTED_ROWS);
        if (response->capacity == 0UL ||
            response->availablePacketCount > response->capacity ||
            response->returnedPacketCount > response->availablePacketCount ||
            response->returnedPacketCount > effectiveRequestedRows ||
            (((response->flags & KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED) != 0UL) !=
                (response->availablePacketCount > response->returnedPacketCount)) ||
            (((response->flags & KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP) != 0UL) !=
                (response->cursorGapCount != 0ULL)))
        {
            failTrafficProtocol(
                result,
                operationName,
                "response counters/flags invalid, capacity=" + std::to_string(response->capacity) +
                ", available=" + std::to_string(response->availablePacketCount) +
                ", returned=" + std::to_string(response->returnedPacketCount));
            return result;
        }

        if (response->returnedPacketCount >
            (std::numeric_limits<std::size_t>::max() - headerSize) /
            static_cast<std::size_t>(response->entrySize))
        {
            failTrafficProtocol(result, operationName, "row byte multiplication overflow");
            return result;
        }

        const std::size_t requiredBytes =
            headerSize +
            (static_cast<std::size_t>(response->returnedPacketCount) *
                static_cast<std::size_t>(response->entrySize));
        if (requiredBytes != static_cast<std::size_t>(response->size) ||
            requiredBytes > static_cast<std::size_t>(result.io.bytesReturned))
        {
            failTrafficProtocol(
                result,
                operationName,
                "response row bytes invalid, required=" + std::to_string(requiredBytes) +
                ", bytesReturned=" + std::to_string(result.io.bytesReturned));
            return result;
        }

        if ((response->oldestSequence == 0ULL) != (response->newestSequence == 0ULL) ||
            (response->oldestSequence != 0ULL &&
                response->oldestSequence > response->newestSequence) ||
            (response->oldestSequence == 0ULL &&
                (response->availablePacketCount != 0UL ||
                    response->returnedPacketCount != 0UL)))
        {
            failTrafficProtocol(
                result,
                operationName,
                "sequence window invalid, oldest=" + std::to_string(response->oldestSequence) +
                ", newest=" + std::to_string(response->newestSequence));
            return result;
        }

        const bool cursorReset =
            (response->flags & KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET) != 0UL;
        if (cursorReset &&
            (response->newestSequence == 0ULL || afterSequence <= response->newestSequence))
        {
            failTrafficProtocol(
                result,
                operationName,
                "cursor reset inconsistent with afterSequence=" + std::to_string(afterSequence));
            return result;
        }

        std::uint64_t previousSequence = cursorReset ? 0ULL : afterSequence;
        result.entries.reserve(response->returnedPacketCount);
        for (std::uint32_t index = 0U; index < response->returnedPacketCount; ++index)
        {
            const std::size_t offset =
                headerSize +
                (static_cast<std::size_t>(index) *
                    static_cast<std::size_t>(response->entrySize));
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW row{};
            std::memcpy(&row, responseBuffer.data() + offset, sizeof(row));

            const bool hasIpv4Flag =
                (row.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV4) != 0UL;
            const bool hasIpv6Flag =
                (row.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV6) != 0UL;
            const bool truncated =
                (row.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED) != 0UL;
            const bool addressFamilyMatches =
                (row.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4 && hasIpv4Flag && !hasIpv6Flag) ||
                (row.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6 && hasIpv6Flag && !hasIpv4Flag);
            const bool payloadRangeValid =
                row.payloadOffset <= row.totalPacketLength &&
                row.payloadLength <= row.totalPacketLength - row.payloadOffset;
            const bool captureRangeValid =
                row.capturedLength <= KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES &&
                row.capturedLength <= row.totalPacketLength &&
                (truncated == (row.capturedLength < row.totalPacketLength));

            if (row.version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ||
                row.size != sizeof(row) ||
                row.sequence <= previousSequence ||
                row.direction != KSWORD_ARK_NETWORK_DIRECTION_INBOUND &&
                    row.direction != KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND ||
                row.protocol != KSWORD_ARK_NETWORK_PROTOCOL_TCP &&
                    row.protocol != KSWORD_ARK_NETWORK_PROTOCOL_UDP ||
                (row.flags & ~knownPacketFlags) != 0UL ||
                !addressFamilyMatches ||
                !payloadRangeValid ||
                !captureRangeValid ||
                row.reserved0 != 0UL ||
                row.reserved1 != 0UL ||
                response->oldestSequence != 0ULL &&
                    (row.sequence < response->oldestSequence ||
                        row.sequence > response->newestSequence))
            {
                failTrafficProtocol(
                    result,
                    operationName,
                    "row[" + std::to_string(index) +
                    "] invalid, sequence=" + std::to_string(row.sequence) +
                    ", family=" + std::to_string(row.addressFamily) +
                    ", flags=" + std::to_string(row.flags));
                return result;
            }

            previousSequence = row.sequence;
            result.entries.push_back(row);
        }

        const std::uint64_t expectedNextSequence =
            result.entries.empty()
            ? (cursorReset ? 0ULL : afterSequence)
            : result.entries.back().sequence;
        if (response->nextSequence != expectedNextSequence)
        {
            failTrafficProtocol(
                result,
                operationName,
                "nextSequence=" + std::to_string(response->nextSequence) +
                ", expected=" + std::to_string(expectedNextSequence));
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.flags = response->flags;
        result.totalCount = response->availablePacketCount;
        result.returnedCount = response->returnedPacketCount;
        result.entrySize = response->entrySize;
        result.capacity = response->capacity;
        result.oldestSequence = response->oldestSequence;
        result.newestSequence = response->newestSequence;
        result.nextSequence = response->nextSequence;
        result.droppedPacketCount = response->droppedPacketCount;
        result.cursorGapCount = response->cursorGapCount;
        result.lastStatus = response->lastStatus;
        result.io.ntStatus = response->lastStatus;

        std::ostringstream summary;
        summary << operationName
            << " rows=" << result.entries.size()
            << "/" << result.returnedCount
            << ", available=" << result.totalCount
            << ", oldest=" << result.oldestSequence
            << ", newest=" << result.newestSequence
            << ", next=" << result.nextSequence
            << ", dropped=" << result.droppedPacketCount
            << ", cursorGap=" << result.cursorGapCount;
        result.io.message = summary.str();
        return result;
    }
}
