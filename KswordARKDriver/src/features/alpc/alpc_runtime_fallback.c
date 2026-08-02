/*++

Module Name:

    alpc_runtime_fallback.c

Abstract:

    No-profile ALPC basic-information fallback.  Instead of interpreting the
    private ALPC_PORT layout, it resolves the stable ZwAlpcQueryInformation
    export and queries information class zero while attached to the owning
    process.  Unsupported kernels fail closed without publishing guessed data.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query paths.

--*/

#include "alpc_runtime_fallback.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef NTSTATUS
(NTAPI* KSW_ZW_ALPC_QUERY_INFORMATION_FN)(
    _In_ HANDLE PortHandle,
    _In_ ULONG PortInformationClass,
    _Out_writes_bytes_(Length) PVOID PortInformation,
    _In_ ULONG Length,
    _Out_opt_ PULONG ReturnLength
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID Process,
    _Out_ PVOID ApcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID ApcState
    );

static KSW_ZW_ALPC_QUERY_INFORMATION_FN
KswordARKAlpcResolveQueryInformation(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwAlpcQueryInformation");
    return (KSW_ZW_ALPC_QUERY_INFORMATION_FN)MmGetSystemRoutineAddress(
        &routineName);
}

NTSTATUS
KswordARKAlpcQueryRuntimeBasicInfo(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG64 HandleValue,
    _Out_ KSW_ALPC_RUNTIME_BASIC_INFO* BasicInfoOut
    )
{
    KSW_ZW_ALPC_QUERY_INFORMATION_FN queryInformation = NULL;
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    ULONG returnLength = 0UL;
    BOOLEAN attached = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (ProcessObject == NULL || HandleValue == 0ULL ||
        BasicInfoOut == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(BasicInfoOut, sizeof(*BasicInfoOut));
    queryInformation = KswordARKAlpcResolveQueryInformation();
    if (queryInformation == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    RtlZeroMemory(attachState, sizeof(attachState));
    __try {
        KeStackAttachProcess((PVOID)ProcessObject, attachState);
        attached = TRUE;
        status = queryInformation(
            (HANDLE)(ULONG_PTR)HandleValue,
            0UL,
            BasicInfoOut,
            sizeof(*BasicInfoOut),
            &returnLength);
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (attached) {
            KeUnstackDetachProcess(attachState);
            attached = FALSE;
        }
    }
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(BasicInfoOut, sizeof(*BasicInfoOut));
        return status;
    }
    if (returnLength != 0UL && returnLength < sizeof(*BasicInfoOut)) {
        RtlZeroMemory(BasicInfoOut, sizeof(*BasicInfoOut));
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    return STATUS_SUCCESS;
}
