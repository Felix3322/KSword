/*++

Module Name:

    process_privilege.c

Abstract:

    Documented Zw token-privilege query and adjustment helpers.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL.

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"
#include "../../platform/pool_compat.h"

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

NTSYSAPI
NTSTATUS
NTAPI
ZwAdjustPrivilegesToken(
    _In_ HANDLE TokenHandle,
    _In_ BOOLEAN DisableAllPrivileges,
    _In_opt_ PTOKEN_PRIVILEGES NewState,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
    _Out_ _When_(PreviousState == NULL, _Out_opt_) PULONG ReturnLength
    );

// The native TokenPrivileges buffer is bounded to avoid attacker-controlled large allocations.
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_NATIVE_BYTES (64UL * 1024UL)

// A dedicated pool tag makes token-privilege snapshot allocations identifiable in diagnostics.
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG 'vPsK'

// KswordARKDriverOpenProcessTokenByPid opens one kernel process handle and its primary token.
static NTSTATUS
KswordARKDriverOpenProcessTokenByPid(
    _In_ ULONG ProcessId,
    _In_ ACCESS_MASK TokenAccess,
    _Out_ HANDLE* ProcessHandleOut,
    _Out_ HANDLE* TokenHandleOut
    )
{
    // Object attributes force both returned handles into the kernel handle table.
    OBJECT_ATTRIBUTES objectAttributes;
    // ClientId selects the target by PID and does not accept an R3 kernel pointer.
    CLIENT_ID clientId;
    // status carries each documented Zw API result to the caller.
    NTSTATUS status = STATUS_SUCCESS;

    // Reject missing output storage before opening any object.
    if (ProcessHandleOut == NULL || TokenHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    // Initialize outputs so every failure path is safe for the caller.
    *ProcessHandleOut = NULL;
    // Initialize the token output independently for partial-open failures.
    *TokenHandleOut = NULL;
    // Reject System, Idle, and invalid PIDs for this user-facing mutation/query path.
    if (ProcessId == 0U || ProcessId <= 4U) {
        return STATUS_INVALID_PARAMETER;
    }

    // Build kernel-handle object attributes without a name.
    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    // Convert the validated numeric PID to the CLIENT_ID process handle field.
    clientId.UniqueProcess = ULongToHandle(ProcessId);
    // A process open does not require a thread identifier.
    clientId.UniqueThread = NULL;
    // Open only the process access needed to reach the primary token.
    status = ZwOpenProcess(
        ProcessHandleOut,
        PROCESS_QUERY_INFORMATION,
        &objectAttributes,
        &clientId);
    // Stop when the process cannot be opened or is already terminating.
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Open the primary token with the exact access requested by the caller.
    status = ZwOpenProcessTokenEx(
        *ProcessHandleOut,
        TokenAccess,
        OBJ_KERNEL_HANDLE,
        TokenHandleOut);
    // Close the process handle when token open fails, preserving no partial ownership.
    if (!NT_SUCCESS(status)) {
        ZwClose(*ProcessHandleOut);
        // Clear the closed process handle before returning it to the caller.
        *ProcessHandleOut = NULL;
        return status;
    }

    // Both handles are now owned by the caller.
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKDriverQueryProcessTokenPrivilegesByPid(
    _In_ ULONG ProcessId,
    _Out_writes_to_(EntryCapacity, *ReturnedCount) KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY* Entries,
    _In_ ULONG EntryCapacity,
    _Out_ ULONG* TotalCount,
    _Out_ ULONG* ReturnedCount
    )
{
    // processHandle keeps the process object referenced until the token snapshot is complete.
    HANDLE processHandle = NULL;
    // tokenHandle provides documented TokenPrivileges query access.
    HANDLE tokenHandle = NULL;
    // tokenPrivileges receives the variable-length native token buffer.
    TOKEN_PRIVILEGES* tokenPrivileges = NULL;
    // requiredBytes receives the exact ZwQueryInformationToken buffer requirement.
    ULONG requiredBytes = 0UL;
    // copyCount is the bounded number of entries returned to the protocol layer.
    ULONG copyCount = 0UL;
    // privilegeIndex iterates only over the validated native PrivilegeCount.
    ULONG privilegeIndex = 0UL;
    // status carries documented Zw and allocation validation outcomes.
    NTSTATUS status = STATUS_SUCCESS;

    // Require count outputs and require entry storage whenever capacity is nonzero.
    if (TotalCount == NULL || ReturnedCount == NULL ||
        (EntryCapacity != 0U && Entries == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    // Initialize the total count for every early return.
    *TotalCount = 0UL;
    // Initialize the returned count for every early return.
    *ReturnedCount = 0UL;

    // Open the target token through documented process and token APIs.
    status = KswordARKDriverOpenProcessTokenByPid(
        ProcessId,
        TOKEN_QUERY,
        &processHandle,
        &tokenHandle);
    // Propagate process/token open failures unchanged.
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Probe the required variable TokenPrivileges buffer size.
    status = ZwQueryInformationToken(
        tokenHandle,
        TokenPrivileges,
        NULL,
        0UL,
        &requiredBytes);
    // Accept only the documented size-probe statuses.
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        ZwClose(tokenHandle);
        // Release the process reference after the token query probe fails.
        ZwClose(processHandle);
        return status;
    }
    // Reject malformed or unreasonably large native buffer requirements.
    if (requiredBytes < sizeof(ULONG) ||
        requiredBytes > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_NATIVE_BYTES) {
        ZwClose(tokenHandle);
        // Release the process reference after rejecting the size.
        ZwClose(processHandle);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // Allocate nonpaged storage because the shared compatibility allocator is already audited.
    tokenPrivileges = (TOKEN_PRIVILEGES*)KswordARKAllocateNonPagedPool(
        requiredBytes,
        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
    // Report an allocation failure without touching caller output storage.
    if (tokenPrivileges == NULL) {
        ZwClose(tokenHandle);
        // Release the process reference after the allocation failure.
        ZwClose(processHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // Clear the native buffer before the kernel fills it.
    RtlZeroMemory(tokenPrivileges, requiredBytes);

    // Read the complete privilege array through the documented token query API.
    status = ZwQueryInformationToken(
        tokenHandle,
        TokenPrivileges,
        tokenPrivileges,
        requiredBytes,
        &requiredBytes);
    // Close the token handle immediately after the native query completes.
    ZwClose(tokenHandle);
    // Close the process handle immediately after the native query completes.
    ZwClose(processHandle);
    // Free the temporary buffer and return when the native query fails.
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(tokenPrivileges, KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
        return status;
    }

    // Validate that the returned byte count covers every advertised native entry.
    if (requiredBytes < (ULONG)FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) ||
        tokenPrivileges->PrivilegeCount >
            ((requiredBytes - (ULONG)FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges)) /
             sizeof(LUID_AND_ATTRIBUTES))) {
        ExFreePoolWithTag(tokenPrivileges, KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    // Publish the native privilege count for truncation diagnostics.
    *TotalCount = tokenPrivileges->PrivilegeCount;
    // Start with the native count and then clamp it to protocol/caller capacity.
    copyCount = tokenPrivileges->PrivilegeCount;
    // Clamp malicious or future oversized token arrays to the shared protocol maximum.
    if (copyCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES) {
        copyCount = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES;
    }
    // Clamp the copied entries to the output buffer capacity computed by the handler.
    if (copyCount > EntryCapacity) {
        copyCount = EntryCapacity;
    }

    // Copy each LUID and attribute mask into the architecture-stable shared entry.
    for (privilegeIndex = 0UL; privilegeIndex < copyCount; ++privilegeIndex) {
        // Preserve the low LUID half exactly as returned by the token manager.
        Entries[privilegeIndex].luidLowPart =
            tokenPrivileges->Privileges[privilegeIndex].Luid.LowPart;
        // Preserve the signed high LUID half exactly as returned by the token manager.
        Entries[privilegeIndex].luidHighPart =
            tokenPrivileges->Privileges[privilegeIndex].Luid.HighPart;
        // Preserve all documented and future privilege attribute bits for R3 display.
        Entries[privilegeIndex].attributes =
            tokenPrivileges->Privileges[privilegeIndex].Attributes;
        // Keep the reserved protocol field deterministic.
        Entries[privilegeIndex].reserved = 0UL;
    }
    // Publish the number of initialized protocol entries.
    *ReturnedCount = copyCount;
    // Release the temporary native token snapshot.
    ExFreePoolWithTag(tokenPrivileges, KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_POOL_TAG);

    // Distinguish a valid truncated snapshot from a complete snapshot.
    return copyCount < *TotalCount ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

NTSTATUS
KswordARKDriverAdjustProcessTokenPrivilegeByPid(
    _In_ ULONG ProcessId,
    _In_ LUID PrivilegeLuid,
    _In_ BOOLEAN Enable
    )
{
    // processHandle keeps the target process object referenced during adjustment.
    HANDLE processHandle = NULL;
    // tokenHandle provides documented privilege adjustment access.
    HANDLE tokenHandle = NULL;
    // newState describes exactly one LUID and never removes it from the token.
    TOKEN_PRIVILEGES newState;
    // status carries documented token open and adjustment results.
    NTSTATUS status = STATUS_SUCCESS;

    // Open the token with the minimum query/adjust access required by ZwAdjustPrivilegesToken.
    status = KswordARKDriverOpenProcessTokenByPid(
        ProcessId,
        TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
        &processHandle,
        &tokenHandle);
    // Propagate process/token open failures unchanged.
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Clear every field before building the one-entry privilege update.
    RtlZeroMemory(&newState, sizeof(newState));
    // Submit exactly one privilege LUID per IOCTL.
    newState.PrivilegeCount = 1UL;
    // Copy the caller-validated LUID into the documented token structure.
    newState.Privileges[0].Luid = PrivilegeLuid;
    // Enable sets SE_PRIVILEGE_ENABLED; disable clears the enabled bit without removal.
    newState.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0UL;

    // Apply the one-entry change through the documented token manager API.
    status = ZwAdjustPrivilegesToken(
        tokenHandle,
        FALSE,
        &newState,
        sizeof(newState),
        NULL,
        NULL);
    // Close the token handle after the synchronous adjustment returns.
    ZwClose(tokenHandle);
    // Close the process handle after the synchronous adjustment returns.
    ZwClose(processHandle);

    // Return STATUS_NOT_ALL_ASSIGNED and other semantic statuses without masking them.
    return status;
}
