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
        bool codeIntegrityTrusted = false;
        bool relocationApplied = false;
        bool differs = false;
        std::uint64_t moduleBase = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t relativeVirtualAddress = 0;
        std::uint32_t signingLevel = 0;
        QString moduleName;
        QString imagePath;
        QString imageSha256;
        QString signingThumbprint;
        QString statusText;
        std::vector<std::uint8_t> cleanBytes;
        std::vector<std::uint8_t> observedBytes;
    };

    struct IdtHandlerObservation
    {
        std::uint32_t vector = 0;
        std::uint64_t handler = 0;
    };

    struct TrustedIdtBaselineResult
    {
        bool available = false;
        bool identityMatched = false;
        bool codeIntegrityTrusted = false;
        bool profileHashMatched = false;
        bool handlerMatches = false;
        std::uint32_t vector = 0;
        std::uint32_t expectedCandidateCount = 0;
        std::uint64_t observedHandler = 0;
        std::uint64_t expectedHandler = 0;
        QString imagePath;
        QString imageSha256;
        QString profilePath;
        QString sourceSymbol;
        QString statusText;
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

        static std::vector<TrustedIdtBaselineResult>
        compareIdtHandlers(
            const std::vector<IdtHandlerObservation>& observations);
    };
}
