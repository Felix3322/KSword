/*++

Module Name:

    process_token_privilege.c

Abstract:

    Stable process-token privilege query and adjustment backends.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../platform/pool_compat.h"

NTKERNELAPI
LONGLONG
NTAPI
PsGetProcessCreateTimeQuadPart(
    _In_ PEPROCESS Process
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwAdjustPrivilegesToken(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN DisableAllPrivileges,
    _In_opt_ PTOKEN_PRIVILEGES NewState,
    _In_ ULONG BufferLength,
    _Out_opt_ PTOKEN_PRIVILEGES PreviousState,
    _Out_opt_ PULONG ReturnLength
    );

#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG 'vPsK'
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_QUERY_MAX_BYTES (64UL * 1024UL)

static NTSTATUS
KswordARKDriverOpenStableProcessToken(
    _In_ ULONG ProcessId,
    _In_ ULONG64 ExpectedCreateTime100ns,
    _In_ ACCESS_MASK TokenDesiredAccess,
    _Out_ HANDLE* TokenHandleOut,
    _Out_ ULONG64* ProcessCreateTime100nsOut
    )
/*++

Routine Description:

    Reference one process by PID, bind it to the expected creation timestamp,
    and open its primary token through kernel handles.

Arguments:

    ProcessId - Target process ID.
    ExpectedCreateTime100ns - Optional FILETIME-compatible identity timestamp.
    TokenDesiredAccess - Access requested for the primary token.
    TokenHandleOut - Receives the kernel token handle.
    ProcessCreateTime100nsOut - Receives the observed process creation time.

Return Value:

    NTSTATUS from PID lookup, identity validation, process handle creation, or
    primary-token open.

--*/
{
    PEPROCESS processObject = NULL;
    HANDLE processHandle = NULL;
    HANDLE tokenHandle = NULL;
    ULONG64 processCreateTime100ns = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (TokenHandleOut == NULL || ProcessCreateTime100nsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TokenHandleOut = NULL;
    *ProcessCreateTime100nsOut = 0ULL;

    if (ProcessId == 0UL || ProcessId <= 4UL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    processCreateTime100ns = (ULONG64)PsGetProcessCreateTimeQuadPart(processObject);
    if (ExpectedCreateTime100ns != 0ULL &&
        processCreateTime100ns != ExpectedCreateTime100ns) {
        ObDereferenceObject(processObject);
        return STATUS_INVALID_CID;
    }

    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle);
    ObDereferenceObject(processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwOpenProcessTokenEx(
        processHandle,
        TokenDesiredAccess,
        OBJ_KERNEL_HANDLE,
        &tokenHandle);
    ZwClose(processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *TokenHandleOut = tokenHandle;
    *ProcessCreateTime100nsOut = processCreateTime100ns;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKDriverQueryProcessTokenPrivileges(
    _In_ ULONG ProcessId,
    _In_ ULONG64 ExpectedCreateTime100ns,
    _Out_ KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE* Response
    )
/*++

Routine Description:

    Query a target primary token and copy its privilege LUID/attribute rows into
    the bounded shared response.

Arguments:

    ProcessId - Target process ID.
    ExpectedCreateTime100ns - Optional stable process identity timestamp.
    Response - Fixed response initialized by the IOCTL handler.

Return Value:

    STATUS_SUCCESS, STATUS_BUFFER_OVERFLOW for truncation, or a token query
    failure status.

--*/
{
    HANDLE tokenHandle = NULL;
    PTOKEN_PRIVILEGES tokenPrivileges = NULL;
    ULONG tokenInformationBytes = 0UL;
    ULONG returnedCount = 0UL;
    ULONG entryIndex = 0UL;
    ULONG64 processCreateTime100ns = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKDriverOpenStableProcessToken(
        ProcessId,
        ExpectedCreateTime100ns,
        TOKEN_QUERY,
        &tokenHandle,
        &processCreateTime100ns);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Response->processCreateTime100ns = processCreateTime100ns;

    status = ZwQueryInformationToken(
        tokenHandle,
        TokenPrivileges,
        NULL,
        0UL,
        &tokenInformationBytes);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        ZwClose(tokenHandle);
        return status;
    }
    if (tokenInformationBytes < sizeof(ULONG) ||
        tokenInformationBytes > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_QUERY_MAX_BYTES) {
        ZwClose(tokenHandle);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    tokenPrivileges = (PTOKEN_PRIVILEGES)KswordARKAllocateNonPagedPool(
        tokenInformationBytes,
        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
    if (tokenPrivileges == NULL) {
        ZwClose(tokenHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(tokenPrivileges, tokenInformationBytes);

    status = ZwQueryInformationToken(
        tokenHandle,
        TokenPrivileges,
        tokenPrivileges,
        tokenInformationBytes,
        &tokenInformationBytes);
    ZwClose(tokenHandle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(tokenPrivileges, KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
        return status;
    }

    returnedCount = tokenPrivileges->PrivilegeCount;
    if (returnedCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES) {
        returnedCount = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES;
    }
    for (entryIndex = 0UL; entryIndex < returnedCount; ++entryIndex) {
        Response->entries[entryIndex].luidLowPart =
            tokenPrivileges->Privileges[entryIndex].Luid.LowPart;
        Response->entries[entryIndex].luidHighPart =
            tokenPrivileges->Privileges[entryIndex].Luid.HighPart;
        Response->entries[entryIndex].attributes =
            tokenPrivileges->Privileges[entryIndex].Attributes;
        Response->entries[entryIndex].action =
            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_KEEP;
    }
    Response->entryCount = returnedCount;

    status = tokenPrivileges->PrivilegeCount > returnedCount
        ? STATUS_BUFFER_OVERFLOW
        : STATUS_SUCCESS;
    ExFreePoolWithTag(tokenPrivileges, KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
    return status;
}

NTSTATUS
KswordARKDriverAdjustProcessTokenPrivileges(
    _In_ ULONG ProcessId,
    _In_ ULONG64 ExpectedCreateTime100ns,
    _In_reads_(EntryCount) const KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY* Entries,
    _In_ ULONG EntryCount,
    _Out_ ULONG* AppliedCountOut,
    _Out_ ULONG* FailedIndexOut,
    _Out_ ULONG64* ProcessCreateTime100nsOut
    )
/*++

Routine Description:

    Apply a validated ordered privilege edit list through
    ZwAdjustPrivilegesToken.

Arguments:

    ProcessId - Target process ID.
    ExpectedCreateTime100ns - Stable identity timestamp from the UI snapshot.
    Entries - LUID/action rows validated by the IOCTL handler.
    EntryCount - Number of requested rows.
    AppliedCountOut - Receives the successfully committed prefix length.
    FailedIndexOut - Receives the first failed row or the shared NONE sentinel.
    ProcessCreateTime100nsOut - Receives the observed process creation time.

Return Value:

    STATUS_SUCCESS only when every row was applied; otherwise the first failing
    token API status is returned after preserving partial-progress outputs.

--*/
{
    HANDLE tokenHandle = NULL;
    ULONG entryIndex = 0UL;
    ULONG64 processCreateTime100ns = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Entries == NULL || EntryCount == 0UL ||
        EntryCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES ||
        AppliedCountOut == NULL || FailedIndexOut == NULL ||
        ProcessCreateTime100nsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *AppliedCountOut = 0UL;
    *FailedIndexOut = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE;
    *ProcessCreateTime100nsOut = 0ULL;

    status = KswordARKDriverOpenStableProcessToken(
        ProcessId,
        ExpectedCreateTime100ns,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &tokenHandle,
        &processCreateTime100ns);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    *ProcessCreateTime100nsOut = processCreateTime100ns;

    for (entryIndex = 0UL; entryIndex < EntryCount; ++entryIndex) {
        TOKEN_PRIVILEGES tokenPrivileges;
        RtlZeroMemory(&tokenPrivileges, sizeof(tokenPrivileges));
        tokenPrivileges.PrivilegeCount = 1UL;
        tokenPrivileges.Privileges[0].Luid.LowPart = Entries[entryIndex].luidLowPart;
        tokenPrivileges.Privileges[0].Luid.HighPart = Entries[entryIndex].luidHighPart;

        switch (Entries[entryIndex].action) {
        case KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE:
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            break;
        case KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE:
            tokenPrivileges.Privileges[0].Attributes = 0UL;
            break;
        case KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE:
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            *FailedIndexOut = entryIndex;
            ZwClose(tokenHandle);
            return status;
        }

        status = ZwAdjustPrivilegesToken(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            (ULONG)sizeof(tokenPrivileges),
            NULL,
            NULL);
        if (status != STATUS_SUCCESS) {
            *FailedIndexOut = entryIndex;
            ZwClose(tokenHandle);
            return status;
        }
        *AppliedCountOut = entryIndex + 1UL;
    }

    ZwClose(tokenHandle);
    return STATUS_SUCCESS;
}
