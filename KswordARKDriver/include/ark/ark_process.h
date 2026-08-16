#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkProcessIoctl.h"

EXTERN_C_START

NTSTATUS
KswordARKDriverTerminateProcessByPid(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _In_ NTSTATUS exitStatus
    );

NTSTATUS
KswordARKDriverSuspendProcessByPid(
    _In_ ULONG processId
    );

NTSTATUS
KswordARKDriverSetProcessPplLevelByPid(
    _In_ ULONG processId,
    _In_ UCHAR protectionLevel
    );

/*
 * KswordARKDriverApplyProcessProtectionToObject
 * Inputs:
 * - processObject 是调用方已持有引用的目标 EPROCESS；
 * - protectionLevel 是目标 PS_PROTECTION 字节，0 表示清除保护。
 * Processing:
 * - 与按 PID 的入口共用同一张 signer→签名级别表，但跳过
 *   PsLookupProcessByProcessId：PP 守护在进程创建回调里拿到的就是对象，
 *   而且 PID 可能被 DKOM 改写或已被复用。
 * Return behavior:
 * - 返回签名级别解析或 EPROCESS 写入的 NTSTATUS。
 */
NTSTATUS
KswordARKDriverApplyProcessProtectionToObject(
    _In_ PEPROCESS processObject,
    _In_ UCHAR protectionLevel
    );

/*
 * KswordARKDriverSetProcessIntegrityByPid
 * Inputs:
 * - ProcessId selects the target process by PID.
 * - IntegrityRid is the S-1-16-* mandatory label RID to assign.
 * Processing:
 * - First opens the process primary token through kernel Zw* token APIs and
 *   calls ZwSetInformationToken(TokenIntegrityLevel).
 * - If the documented API rejects the label and current-kernel PDB DynData has
 *   _EPROCESS.Token plus _TOKEN integrity offsets, falls back to in-place
 *   mandatory SID replacement inside the token's UserAndGroups array.
 * Return behavior:
 * - Returns STATUS_SUCCESS when either path applies the label; otherwise
 *   returns the relevant API, DynData, validation, or guarded-access status.
 */
NTSTATUS
KswordARKDriverSetProcessIntegrityByPid(
    _In_ ULONG ProcessId,
    _In_ ULONG IntegrityRid
    );

/*
 * KswordARKDriverQueryProcessTokenPrivilegesByPid
 * Inputs:
 * - ProcessId selects the target process through ZwOpenProcess.
 * - Entries/EntryCapacity describe caller-owned protocol entry storage.
 * Processing:
 * - Opens the primary token with TOKEN_QUERY and reads TokenPrivileges through
 *   ZwQueryInformationToken; no private TOKEN layout is accessed.
 * Return behavior:
 * - TotalCount receives the native token count, ReturnedCount receives copied
 *   entries, and STATUS_BUFFER_OVERFLOW denotes a valid truncated snapshot.
 */
NTSTATUS
KswordARKDriverQueryProcessTokenPrivilegesByPid(
    _In_ ULONG ProcessId,
    _Out_writes_to_(EntryCapacity, *ReturnedCount) KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY* Entries,
    _In_ ULONG EntryCapacity,
    _Out_ ULONG* TotalCount,
    _Out_ ULONG* ReturnedCount
    );

/*
 * KswordARKDriverAdjustProcessTokenPrivilegeByPid
 * Inputs:
 * - ProcessId selects the target process.
 * - PrivilegeLuid identifies one token privilege; Enable selects enabled or disabled.
 * Processing:
 * - Opens the primary token with TOKEN_ADJUST_PRIVILEGES and calls
 *   ZwAdjustPrivilegesToken for exactly one LUID.
 * Return behavior:
 * - Returns the documented Zw* API status without private offsets or fallback writes.
 */
NTSTATUS
KswordARKDriverAdjustProcessTokenPrivilegeByPid(
    _In_ ULONG ProcessId,
    _In_ LUID PrivilegeLuid,
    _In_ BOOLEAN Enable
    );

/*
 * KswordARKDriverDescribeLastProcessIntegrityAttempt
 * Inputs:
 * - Buffer/BufferBytes provide caller-owned ANSI storage for a diagnostic line.
 * Processing:
 * - Copies the last process-integrity API/fallback status snapshot captured in
 *   this driver instance; the data is best-effort and intended for logs.
 * Return behavior:
 * - Returns STATUS_SUCCESS when text was copied; otherwise returns a buffer or
 *   parameter status. The routine does not modify process or token state.
 */
NTSTATUS
KswordARKDriverDescribeLastProcessIntegrityAttempt(
    _Out_writes_bytes_(BufferBytes) CHAR* Buffer,
    _In_ SIZE_T BufferBytes
    );

/*
 * KswordARKDriverQueryProcessTokenPrivileges
 * Inputs:
 * - ProcessId selects the target process and ExpectedCreateTime100ns optionally
 *   binds that PID to the process instance observed by R3.
 * Processing:
 * - Opens the primary token through kernel handles and queries TokenPrivileges.
 * - Copies bounded LUID/attribute rows into the shared fixed response.
 * Return behavior:
 * - Returns STATUS_SUCCESS for a complete snapshot, STATUS_BUFFER_OVERFLOW for
 *   a usable truncated snapshot, or the process/token query status on failure.
 */
NTSTATUS
KswordARKDriverQueryProcessTokenPrivileges(
    _In_ ULONG ProcessId,
    _In_ ULONG64 ExpectedCreateTime100ns,
    _Out_ KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE* Response
    );

/*
 * KswordARKDriverAdjustProcessTokenPrivileges
 * Inputs:
 * - ProcessId/ExpectedCreateTime100ns identify one stable process instance.
 * - Entries contains validated LUID plus enable/disable/remove actions.
 * Processing:
 * - Opens the primary token with TOKEN_ADJUST_PRIVILEGES and applies entries in
 *   request order through ZwAdjustPrivilegesToken.
 * Return behavior:
 * - AppliedCountOut reports the committed prefix. FailedIndexOut identifies the
 *   first rejected row, making partial mutation explicit to R3.
 */
NTSTATUS
KswordARKDriverAdjustProcessTokenPrivileges(
    _In_ ULONG ProcessId,
    _In_ ULONG64 ExpectedCreateTime100ns,
    _In_reads_(EntryCount) const KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY* Entries,
    _In_ ULONG EntryCount,
    _Out_ ULONG* AppliedCountOut,
    _Out_ ULONG* FailedIndexOut,
    _Out_ ULONG64* ProcessCreateTime100nsOut
    );

NTSTATUS
KswordARKDriverEnumerateProcesses(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_PROCESS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
KswordARKDriverSetProcessVisibility(
    _In_ ULONG ProcessId,
    _In_ ULONG Action,
    _In_ ULONG Flags,
    _Out_ ULONG* StatusOut,
    _Out_ ULONG* HiddenCountOut
    );

NTSTATUS
KswordARKDriverSetProcessSpecialFlags(
    _In_ ULONG ProcessId,
    _In_ ULONG Action,
    _In_ ULONG Flags,
    _Out_ ULONG* OperationStatusOut,
    _Out_ ULONG* AppliedFlagsOut,
    _Out_ ULONG* TouchedThreadCountOut
    );

NTSTATUS
KswordARKDriverDkomProcess(
    _In_ ULONG ProcessId,
    _In_ ULONG Action,
    _In_ ULONG Flags,
    _Out_ ULONG* OperationStatusOut,
    _Out_ ULONG* RemovedEntriesOut,
    _Out_ ULONG64* PspCidTableAddressOut,
    _Out_ ULONG64* ProcessObjectAddressOut
    );

NTSTATUS
KswordARKDriverInjectProcess(
    _Out_writes_bytes_(OutputBufferLength) KSWORD_ARK_INJECT_PROCESS_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_reads_bytes_(InputBufferLength) const KSWORD_ARK_INJECT_PROCESS_REQUEST* Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKProcessIoctlInjectProcess(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

/*
 * KswordARKDriverQueryProcessCrossView
 * Inputs:
 * - OutputBuffer/OutputBufferLength describe the caller-owned METHOD_BUFFERED
 *   response storage.
 * - Request optionally selects read-only evidence sources and PID bounds.
 * Processing:
 * - Collects process evidence from public enumeration, ActiveProcessLinks, and
 *   PspCidTable without modifying process objects or kernel tables.
 * Return behavior:
 * - Returns an NTSTATUS for request-level validation/allocation. Per-source
 *   read/capability results are reported in the response header and rows.
 */
NTSTATUS
KswordARKDriverQueryProcessCrossView(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

/*
 * KswordARKDriverQueryProcessDetail
 * Inputs:
 * - Response/OutputBufferLength describe a fixed METHOD_BUFFERED response.
 * - Request supplies a PID and read-only field groups; no R3 kernel pointer is
 *   trusted.
 * Processing:
 * - References EPROCESS by PID and samples PDB/DynData-backed fields with guarded
 *   reads.
 * Return behavior:
 * - Returns STATUS_SUCCESS when the response packet is valid; response.status
 *   carries lookup/capability/read completeness.
 */
NTSTATUS
KswordARKDriverQueryProcessDetail(
    _Out_writes_bytes_(OutputBufferLength) KSWORD_ARK_PROCESS_DETAIL_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_PROCESS_DETAIL_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

/*
 * KswordARKProcessIoctlQueryCrossView
 * Inputs:
 * - Device and Request are the WDF dispatch objects for the unregistered
 *   process cross-view IOCTL.
 * - InputBufferLength/OutputBufferLength are validated through WDF helpers.
 * Processing:
 * - Retrieves an optional fixed request plus required output buffer, then calls
 *   the read-only backend. It never accepts R3-provided EPROCESS addresses.
 * Return behavior:
 * - Returns the WDF buffer retrieval status or backend status and writes the
 *   byte count through BytesReturned.
 */
NTSTATUS
KswordARKProcessIoctlQueryCrossView(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

/*
 * KswordARKProcessIoctlQueryDetail
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL.
 * Processing:
 * - Retrieves fixed request/response buffers and forwards to the feature backend.
 * Return behavior:
 * - Returns WDF retrieval status or backend status; BytesReturned is fixed
 *   response size on success.
 */
NTSTATUS
KswordARKProcessIoctlQueryDetail(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

/*
 * KswordARKDriverQueryProcessRuntimeFields
 * Inputs:
 * - OutputBuffer/OutputBufferLength describe a variable METHOD_BUFFERED response.
 * - Request/InputBufferLength describe PID plus PDB runtime field sample items.
 * Processing:
 * - References EPROCESS by PID and reads only bounded small fields from that object.
 * Return behavior:
 * - Returns STATUS_SUCCESS when the response header is valid; per-row statuses
 *   describe rejected offsets, rejected sizes, and read failures.
 */
NTSTATUS
KswordARKDriverQueryProcessRuntimeFields(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_reads_bytes_(InputBufferLength) const KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST* Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

/*
 * KswordARKProcessIoctlQueryRuntimeFields
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS.
 * Processing:
 * - Retrieves variable input/output buffers and forwards to the read-only backend.
 * Return behavior:
 * - Returns validation/backend NTSTATUS and writes the actual response byte count.
 */
NTSTATUS
KswordARKProcessIoctlQueryRuntimeFields(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

EXTERN_C_END
