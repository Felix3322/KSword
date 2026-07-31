#pragma once

#include "ark/ark_driver.h"

typedef NTSTATUS(NTAPI* KSWORD_PS_SUSPEND_PROCESS_FN)(
    _In_ PEPROCESS Process
    );

typedef BOOLEAN(NTAPI* KSWORD_PS_IS_PROTECTED_PROCESS_FN)(
    _In_ PEPROCESS Process
    );

typedef BOOLEAN(NTAPI* KSWORD_PS_IS_PROTECTED_PROCESS_LIGHT_FN)(
    _In_ PEPROCESS Process
    );

typedef NTSTATUS(NTAPI* KSWORD_ZW_OR_NT_SUSPEND_PROCESS_FN)(
    _In_ HANDLE ProcessHandle
    );

typedef NTSTATUS(NTAPI* KSWORD_ZW_SET_INFORMATION_PROCESS_FN)(
    _In_ HANDLE ProcessHandle,
    _In_ ULONG ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
    );

// KSWORD_RUNTIME_DYNDATA_OFFSETS carries only offsets recovered from exported
// read-only accessors and validated against live process/thread objects.
// A negative member is unavailable; callers must preserve stronger SI/PDB data.
typedef struct _KSWORD_RUNTIME_DYNDATA_OFFSETS
{
    LONG EpUniqueProcessId;
    LONG EpActiveProcessLinks;
    LONG EpImageFileName;
    LONG EpCreateTime;
    LONG EpExitStatus;
    LONG EpPeb;
    LONG EpWin32Process;
    LONG EpWow64Process;
    LONG EpInheritedFromUniqueProcessId;
    LONG EpSectionBaseAddress;
    LONG EtCid;
    LONG EtStartAddress;
    LONG EtWin32StartAddress;
    LONG KtProcess;
} KSWORD_RUNTIME_DYNDATA_OFFSETS, *PKSWORD_RUNTIME_DYNDATA_OFFSETS;

KSWORD_PS_SUSPEND_PROCESS_FN
KswordARKDriverResolvePsSuspendProcess(
    VOID
    );

KSWORD_ZW_OR_NT_SUSPEND_PROCESS_FN
KswordARKDriverResolveZwOrNtSuspendProcess(
    VOID
    );

KSWORD_PS_IS_PROTECTED_PROCESS_FN
KswordARKDriverResolvePsIsProtectedProcess(
    VOID
    );

KSWORD_PS_IS_PROTECTED_PROCESS_LIGHT_FN
KswordARKDriverResolvePsIsProtectedProcessLight(
    VOID
    );

LONG
KswordARKDriverResolveProcessProtectionOffset(
    VOID
    );

LONG
KswordARKDriverResolveProcessSignatureLevelOffset(
    VOID
    );

LONG
KswordARKDriverResolveProcessSectionSignatureLevelOffset(
    VOID
    );

VOID
KswordARKDriverResolveReadOnlyDynDataOffsets(
    _Out_ PKSWORD_RUNTIME_DYNDATA_OFFSETS Offsets
    );

KSWORD_ZW_SET_INFORMATION_PROCESS_FN
KswordARKDriverResolveZwSetInformationProcess(
    VOID
    );
