#pragma once

// ============================================================
// ksword/scanner/scanner_internal.h
// Purpose:
// - Share overflow-safe byte reads and bounded result construction among parsers.
// - Keep parser implementation details out of the public scanner contract.
// ============================================================

#include "binary_scanner.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <limits>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ks::scanner::detail
{
    // EndianReader never performs an unaligned typed dereference. Each read first
    // validates the complete byte range and then assembles the requested value.
    class EndianReader
    {
    public:
        EndianReader(std::span<const std::uint8_t> bytes, ByteOrder byteOrder)
            : bytes_(bytes), byteOrder_(byteOrder)
        {
        }

        [[nodiscard]] std::size_t size() const noexcept
        {
            return bytes_.size();
        }

        [[nodiscard]] ByteOrder byteOrder() const noexcept
        {
            return byteOrder_;
        }

        [[nodiscard]] bool contains(std::uint64_t offset, std::uint64_t length) const noexcept
        {
            return offset <= static_cast<std::uint64_t>(bytes_.size()) &&
                length <= static_cast<std::uint64_t>(bytes_.size()) - offset;
        }

        [[nodiscard]] bool readU8(std::uint64_t offset, std::uint8_t& valueOut) const noexcept
        {
            if (!contains(offset, 1))
            {
                return false;
            }
            valueOut = bytes_[static_cast<std::size_t>(offset)];
            return true;
        }

        [[nodiscard]] bool readU16(std::uint64_t offset, std::uint16_t& valueOut) const noexcept
        {
            return readInteger(offset, valueOut);
        }

        [[nodiscard]] bool readU32(std::uint64_t offset, std::uint32_t& valueOut) const noexcept
        {
            return readInteger(offset, valueOut);
        }

        [[nodiscard]] bool readU64(std::uint64_t offset, std::uint64_t& valueOut) const noexcept
        {
            return readInteger(offset, valueOut);
        }

        [[nodiscard]] std::span<const std::uint8_t> slice(
            std::uint64_t offset,
            std::uint64_t length) const noexcept
        {
            if (!contains(offset, length) ||
                length > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return {};
            }
            return bytes_.subspan(
                static_cast<std::size_t>(offset),
                static_cast<std::size_t>(length));
        }

        // fixedString reads a fixed-width name and trims at its first NUL byte.
        [[nodiscard]] std::string fixedString(
            std::uint64_t offset,
            std::size_t fieldBytes,
            std::size_t maxStringBytes) const
        {
            const std::size_t boundedBytes = std::min(fieldBytes, maxStringBytes);
            if (!contains(offset, boundedBytes))
            {
                return {};
            }
            const char* begin = reinterpret_cast<const char*>(
                bytes_.data() + static_cast<std::size_t>(offset));
            std::size_t length = 0;
            while (length < boundedBytes && begin[length] != '\0')
            {
                ++length;
            }
            return SanitizeText(std::string(begin, begin + length));
        }

        // cString reads a NUL-terminated string entirely inside a caller-supplied
        // containing range. Missing termination is represented by a bounded prefix.
        [[nodiscard]] std::string cString(
            std::uint64_t offset,
            std::uint64_t containingEnd,
            std::size_t maxStringBytes,
            bool* terminatedOut = nullptr) const
        {
            if (terminatedOut != nullptr)
            {
                *terminatedOut = false;
            }
            if (offset >= containingEnd ||
                containingEnd > static_cast<std::uint64_t>(bytes_.size()))
            {
                return {};
            }

            const std::uint64_t available = containingEnd - offset;
            const std::size_t limit = static_cast<std::size_t>(std::min<std::uint64_t>(
                available,
                static_cast<std::uint64_t>(maxStringBytes)));
            const char* begin = reinterpret_cast<const char*>(
                bytes_.data() + static_cast<std::size_t>(offset));
            std::size_t length = 0;
            while (length < limit && begin[length] != '\0')
            {
                ++length;
            }
            if (terminatedOut != nullptr && length < limit && begin[length] == '\0')
            {
                *terminatedOut = true;
            }
            return SanitizeText(std::string(begin, begin + length));
        }

        // SanitizeText prevents control bytes in binary string tables from being
        // interpreted as terminal/UI controls. Tab is preserved for readability.
        static std::string SanitizeText(std::string value)
        {
            for (char& character : value)
            {
                const unsigned char byte = static_cast<unsigned char>(character);
                if ((byte < 0x20U && byte != '\t') || byte == 0x7FU)
                {
                    character = '.';
                }
            }
            return value;
        }

    private:
        template <typename TUnsigned>
        [[nodiscard]] bool readInteger(std::uint64_t offset, TUnsigned& valueOut) const noexcept
        {
            static_assert(std::is_unsigned_v<TUnsigned>);
            constexpr std::size_t width = sizeof(TUnsigned);
            if (!contains(offset, width) || byteOrder_ == ByteOrder::Unknown)
            {
                return false;
            }

            TUnsigned value = 0;
            if (byteOrder_ == ByteOrder::LittleEndian)
            {
                for (std::size_t index = 0; index < width; ++index)
                {
                    value |= static_cast<TUnsigned>(
                        static_cast<TUnsigned>(bytes_[static_cast<std::size_t>(offset) + index])
                        << (index * 8U));
                }
            }
            else
            {
                for (std::size_t index = 0; index < width; ++index)
                {
                    value = static_cast<TUnsigned>(
                        (value << 8U) |
                        bytes_[static_cast<std::size_t>(offset) + index]);
                }
            }
            valueOut = value;
            return true;
        }

        std::span<const std::uint8_t> bytes_;
        ByteOrder byteOrder_ = ByteOrder::Unknown;
    };

    // CheckedAdd and CheckedMultiply are used before every untrusted table offset
    // calculation so crafted counts cannot wrap to a small in-bounds address.
    inline bool CheckedAdd(
        std::uint64_t left,
        std::uint64_t right,
        std::uint64_t& valueOut) noexcept
    {
        if (right > std::numeric_limits<std::uint64_t>::max() - left)
        {
            return false;
        }
        valueOut = left + right;
        return true;
    }

    inline bool CheckedMultiply(
        std::uint64_t left,
        std::uint64_t right,
        std::uint64_t& valueOut) noexcept
    {
        if (left != 0 && right > std::numeric_limits<std::uint64_t>::max() / left)
        {
            return false;
        }
        valueOut = left * right;
        return true;
    }

    inline std::string Hex(std::uint64_t value, std::size_t minimumDigits = 0)
    {
        std::ostringstream stream;
        stream << "0x" << std::uppercase << std::hex;
        if (minimumDigits != 0)
        {
            stream << std::setfill('0') << std::setw(static_cast<int>(minimumDigits));
        }
        stream << value;
        return stream.str();
    }

    inline std::string Decimal(std::uint64_t value)
    {
        return std::to_string(value);
    }

    // AddField replaces no existing values; stable ordering is intentional for UI.
    inline void AddField(
        std::vector<BinaryField>& fields,
        std::string name,
        std::string value)
    {
        fields.push_back(BinaryField{ std::move(name), std::move(value) });
    }

    inline void AddDiagnostic(
        BinaryScanResult& result,
        DiagnosticSeverity severity,
        std::string code,
        std::string message)
    {
        result.diagnostics.push_back(BinaryDiagnostic{
            severity,
            std::move(code),
            std::move(message),
            false,
            0
        });
    }

    inline void AddDiagnosticAt(
        BinaryScanResult& result,
        DiagnosticSeverity severity,
        std::string code,
        std::string message,
        std::uint64_t offset)
    {
        result.diagnostics.push_back(BinaryDiagnostic{
            severity,
            std::move(code),
            std::move(message),
            true,
            offset
        });
    }

    // AppendRow normalizes row width and applies the per-table row bound.
    inline bool AppendRow(
        BinaryTable& table,
        std::vector<std::string> row,
        const ScanOptions& options)
    {
        if (table.rows.size() >= options.maxRowsPerTable)
        {
            table.truncated = true;
            return false;
        }
        row.resize(table.columns.size());
        if (row.size() > table.columns.size())
        {
            row.resize(table.columns.size());
        }
        table.rows.push_back(std::move(row));
        return true;
    }

    inline BinaryTable& AddTable(
        BinaryScanResult& result,
        std::string id,
        std::string title,
        std::vector<std::string> columns)
    {
        result.tables.push_back(BinaryTable{
            std::move(id),
            std::move(title),
            std::move(columns),
            {},
            false
        });
        return result.tables.back();
    }

    // Parser entry points are implemented in format-specific translation units.
    bool ParseElf(
        std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result);

    bool ParseMachO(
        std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result);
}
