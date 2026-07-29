#pragma once

#include "callback_internal.h"

EXTERN_C_START

PVOID
KswordArkCallbackExtendedGetSystemRoutine(
    _In_z_ PCWSTR RoutineName
    );

BOOLEAN
KswordArkCallbackExtendedResolveRipRelative(
    _In_ ULONG64 InstructionAddress,
    _In_ ULONG DisplacementOffset,
    _In_ ULONG InstructionLength,
    _Out_ ULONG64* TargetAddressOut
    );

BOOLEAN
KswordArkCallbackExtendedReadPointer(
    _In_ ULONG64 Address,
    _Out_ ULONG64* ValueOut
    );

BOOLEAN
KswordArkCallbackExtendedReadListEntry(
    _In_ ULONG64 Address,
    _Out_ LIST_ENTRY* EntryOut
    );

VOID
KswordArkCallbackExtendedAddRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_opt_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG CallbackClass,
    _In_ ULONG Source,
    _In_ ULONG Status,
    _In_ NTSTATUS LastStatus,
    _In_ ULONG RegistrationType,
    _In_ ULONG OperationMask,
    _In_ ULONG ObjectTypeMask,
    _In_ ULONG64 CallbackAddress,
    _In_ ULONG64 ContextAddress,
    _In_ ULONG64 RegistrationAddress,
    _In_ ULONG ExtraFieldFlags,
    _In_opt_z_ PCWSTR NameText,
    _In_opt_z_ PCWSTR DetailText
    );

EXTERN_C_END
