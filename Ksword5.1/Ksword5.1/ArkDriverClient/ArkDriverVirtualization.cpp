#include "ArkDriverClient.h"

#include <sstream>

static_assert(sizeof(KSWORD_ARK_SLAT_PROBE_ROW) == 96U);
static_assert(sizeof(KSWORD_ARK_IOMMU_ROW) == 80U);
static_assert(sizeof(KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST) == 16U);
static_assert(sizeof(KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE) == 6848U);

namespace ksword::ark
{
    namespace
    {
        bool isUnsupportedVirtualizationAuditError(const unsigned long error)
        {
            return error == ERROR_INVALID_FUNCTION ||
                error == ERROR_NOT_SUPPORTED;
        }
    }

    SlatIommuAuditResult DriverClient::querySlatIommuAudit(
        const bool includeMmio) const
    {
        SlatIommuAuditResult result{};
        KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_SLAT_IOMMU_AUDIT_PROTOCOL_VERSION;
        if (includeMmio)
        {
            request.flags |= KSWORD_ARK_SLAT_IOMMU_QUERY_FLAG_INCLUDE_MMIO;
        }

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        result.unsupported = !result.io.ok &&
            isUnsupportedVirtualizationAuditError(result.io.win32Error);

        if (result.io.ok &&
            (result.io.bytesReturned < sizeof(result.response) ||
             result.response.size != sizeof(result.response) ||
             result.response.version !=
                KSWORD_ARK_SLAT_IOMMU_AUDIT_PROTOCOL_VERSION))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_BAD_LENGTH;
            result.io.ntStatus = static_cast<long>(0xC0000004UL);
        }
        else
        {
            result.io.ntStatus = result.response.queryStatus;
        }

        std::ostringstream stream;
        stream << "SLAT/IOMMU audit status=" << result.response.queryStatus
            << ", fields=0x" << std::hex << result.response.fieldFlags
            << ", risks=0x" << result.response.riskFlags
            << ", features=0x" << result.response.featureFlags
            << ", probes=" << std::dec << result.response.probeCount
            << ", mismatches=" << result.response.mismatchCount
            << ", unstable=" << result.response.unstableCount
            << ", iommuRows=" << result.response.iommuRowCount
            << ", mmio=" << (includeMmio ? "true" : "false");
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }
}
