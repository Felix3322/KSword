#pragma once

#include <QString>

#include <cstdint>
#include <vector>

namespace ks::kernel
{
    struct CleanImageBaselineResult
    {
        bool available = false;
        bool identityMatched = false;
        bool differs = false;
        std::uint64_t moduleBase = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t relativeVirtualAddress = 0;
        QString moduleName;
        QString imagePath;
        QString statusText;
        std::vector<std::uint8_t> cleanBytes;
        std::vector<std::uint8_t> observedBytes;
    };

    class KernelCleanImageBaseline final
    {
    public:
        static CleanImageBaselineResult compareAddress(
            std::uint64_t kernelAddress,
            std::uint32_t byteCount,
            const std::vector<std::uint8_t>& observedBytes = {});

        static bool readKernelBytes(
            std::uint64_t kernelAddress,
            std::uint32_t byteCount,
            std::vector<std::uint8_t>& bytesOut,
            QString& errorTextOut);
    };
}
