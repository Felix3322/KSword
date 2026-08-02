/*++

Module Name:

    slat_iommu_audit_ioctl.c

Abstract:

    METHOD_BUFFERED boundary for the read-only SLAT/IOMMU audit.

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

NTSTATUS
KswordARKKernelIoctlQuerySlatIommuAudit(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST* inputBuffer = NULL;
    KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* outputBuffer = NULL;
    KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST requestSnapshot;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = KswordARKRetrieveRequiredInputBuffer(
        Request,
        sizeof(requestSnapshot),
        (PVOID*)&inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        sizeof(*outputBuffer),
        (PVOID*)&outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outputBuffer, sizeof(*outputBuffer));
    *BytesReturned = sizeof(*outputBuffer);
    status = KswordARKSlatIommuAuditQuery(&requestSnapshot, outputBuffer);
    UNREFERENCED_PARAMETER(status);
    return STATUS_SUCCESS;
}
