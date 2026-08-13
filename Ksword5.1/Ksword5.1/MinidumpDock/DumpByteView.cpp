// ============================================================
// DumpByteView.cpp
// 作用：实现转储原始字节的固定宽度十六进制视图。
// ============================================================

#include "DumpByteView.h"

#include <algorithm>

namespace ks::minidump
{
    QString FormatDumpBytes(
        const std::uint64_t baseAddress,
        const unsigned char* const bytes,
        const std::uint64_t byteCount,
        const std::uint64_t omittedBytes)
    {
        if (bytes == nullptr || byteCount == 0)
        {
            return QString();
        }

        constexpr std::uint64_t kBytesPerLine = 16;
        QString text;
        text.reserve(static_cast<qsizetype>(
            std::min<std::uint64_t>(byteCount, 4096) * 4));
        for (std::uint64_t lineOffset = 0; lineOffset < byteCount;
             lineOffset += kBytesPerLine)
        {
            const std::uint64_t lineBytes =
                std::min<std::uint64_t>(kBytesPerLine, byteCount - lineOffset);
            text += QStringLiteral("%1  ")
                .arg(QString::number(baseAddress + lineOffset, 16).toUpper(), 16,
                    QLatin1Char('0'));
            for (std::uint64_t byteIndex = 0; byteIndex < kBytesPerLine; ++byteIndex)
            {
                if (byteIndex < lineBytes)
                {
                    text += QStringLiteral("%1 ")
                        .arg(bytes[lineOffset + byteIndex], 2, 16, QLatin1Char('0'))
                        .toUpper();
                }
                else
                {
                    text += QStringLiteral("   ");
                }
            }
            text += QStringLiteral(" |");
            for (std::uint64_t byteIndex = 0; byteIndex < lineBytes; ++byteIndex)
            {
                const unsigned char value = bytes[lineOffset + byteIndex];
                text += value >= 0x20 && value <= 0x7E
                    ? QChar::fromLatin1(static_cast<char>(value))
                    : QLatin1Char('.');
            }
            text += QStringLiteral("|\n");
        }
        if (omittedBytes != 0)
        {
            text += QStringLiteral("\n… %1 bytes omitted from this preview.\n")
                .arg(omittedBytes);
        }
        return text;
    }
}
