#pragma once

#include <ntddk.h>

#include "driver/KswordArkRxPfIoctl.h"

EXTERN_C_START

#define KSW_RXPF_EVENT_RING_CAPACITY 128UL

typedef struct _KSW_RXPF_EVENT_SLOT
{
    DECLSPEC_ALIGN(8) volatile LONG64 Sequence;
    KSWORD_ARK_RXPF_EVENT_ROW Row;
} KSW_RXPF_EVENT_SLOT, *PKSW_RXPF_EVENT_SLOT;

typedef struct _KSW_RXPF_EVENT_RING
{
    volatile LONG Head;
    KSW_RXPF_EVENT_SLOT Slots[KSW_RXPF_EVENT_RING_CAPACITY];
} KSW_RXPF_EVENT_RING, *PKSW_RXPF_EVENT_RING;

NTSTATUS
KswRxpfDiagnosticsInitialize(
    _In_ ULONG MaximumProcessorCount
    );

VOID
KswRxpfDiagnosticsUninitialize(
    VOID
    );

VOID
KswRxpfDiagnosticsEnterHandler(
    VOID
    );

VOID
KswRxpfDiagnosticsLeaveHandler(
    VOID
    );

LONG
KswRxpfDiagnosticsActiveHandlers(
    VOID
    );

NTSTATUS
KswRxpfDiagnosticsWaitForHandlers(
    _In_ ULONG TimeoutMilliseconds
    );

VOID
KswRxpfDiagnosticsRecord(
    _In_ ULONG ProcessorIndex,
    _In_ ULONGLONG Cr2,
    _In_ ULONGLONG Rip,
    _In_ ULONGLONG ErrorCode,
    _In_ ULONGLONG RecordId,
    _In_ ULONG DecodedInstruction,
    _In_ ULONG EmulationResult,
    _In_ ULONGLONG NewRip,
    _In_ NTSTATUS Status
    );

VOID
KswRxpfDiagnosticsCountTotalFault(
    VOID
    );

VOID
KswRxpfDiagnosticsCountManagedFault(
    VOID
    );

VOID
KswRxpfDiagnosticsCountEmulatedInstruction(
    VOID
    );

VOID
KswRxpfDiagnosticsCountChainedFault(
    VOID
    );

VOID
KswRxpfDiagnosticsCountRecursiveFault(
    VOID
    );

VOID
KswRxpfDiagnosticsCountUnsupportedInstruction(
    VOID
    );

VOID
KswRxpfDiagnosticsSetLastStatus(
    _In_ NTSTATUS Status
    );

VOID
KswRxpfDiagnosticsQueryStats(
    _In_ ULONG Generation,
    _In_ ULONG RegisteredPages,
    _In_ ULONG EnabledPages,
    _In_ ULONG IdtInstalled,
    _In_ ULONG ProcessorCount,
    _Out_ KSWORD_ARK_RXPF_STATS_RESPONSE* Response
    );

VOID
KswRxpfDiagnosticsDrain(
    _In_ const KSWORD_ARK_RXPF_DRAIN_EVENTS_REQUEST* Request,
    _Out_ KSWORD_ARK_RXPF_DRAIN_EVENTS_RESPONSE* Response
    );

EXTERN_C_END
