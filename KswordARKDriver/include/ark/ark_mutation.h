#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkMutationIoctl.h"

EXTERN_C_START

/*
 * Inputs: none. Processing: initialize the mutation transaction lock, counters,
 * and rings if they have not already been initialized. Return: none.
 */
VOID
KswordARKMutationInitialize(
    VOID
    );

/*
 * Inputs: none. Processing: release every process-object reference owned by a
 * live global transaction slot during driver unload. Return: none.
 */
VOID
KswordARKMutationUninitialize(
    VOID
    );

/*
 * Inputs: WDF device for optional logging, borrowed requestor PID/process
 * identity, shared PREPARE request, and output response buffer. Processing:
 * validate target, snapshot before bytes, bind the transaction to a referenced
 * process object, allocate transactionId, and append audit without writing
 * target memory. Return: NTSTATUS plus KSWORD_ARK_MUTATION_RESPONSE bytes.
 */
NTSTATUS
KswordARKMutationPrepare(
    _In_opt_ WDFDEVICE Device,
    _In_ ULONG RequestorProcessId,
    _In_ PEPROCESS RequestorProcessObject,
    _In_ const KSWORD_ARK_MUTATION_PREPARE_REQUEST* Request,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

/*
 * Inputs: WDF device for optional safety logging, borrowed requestor identity,
 * transactionId request, and output response buffer. Processing: require the
 * same stable process object, dry-run without FORCE; with FORCE, require target
 * revalidation, before-byte match, safety allow, supported write, and
 * verification. Return: NTSTATUS plus KSWORD_ARK_MUTATION_RESPONSE bytes.
 */
NTSTATUS
KswordARKMutationCommit(
    _In_opt_ WDFDEVICE Device,
    _In_ ULONG RequestorProcessId,
    _In_ PEPROCESS RequestorProcessObject,
    _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* Request,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

/*
 * Inputs: WDF device for optional safety logging, borrowed requestor identity,
 * transactionId request, and output response buffer. Processing: require the
 * same stable process object, dry-run without FORCE; with FORCE, restore before
 * snapshot when supported and report idempotent success if already restored.
 * Return: NTSTATUS plus KSWORD_ARK_MUTATION_RESPONSE bytes.
 */
NTSTATUS
KswordARKMutationRollback(
    _In_opt_ WDFDEVICE Device,
    _In_ ULONG RequestorProcessId,
    _In_ PEPROCESS RequestorProcessObject,
    _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* Request,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

/*
 * Inputs: output response buffer and optional audit query request. Processing:
 * copy recent audit ring entries and redact byteData unless explicitly requested.
 * Return: NTSTATUS plus KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE bytes.
 */
NTSTATUS
KswordARKMutationQueryAudit(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

EXTERN_C_END
