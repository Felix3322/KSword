#pragma once

#include <ntddk.h>

typedef struct _KSW_KEYBOARD_HOTKEY_RUNTIME
{
    PVOID Win32kfullBase;
    ULONG Win32kfullSize;
    PVOID Win32kbaseBase;
    ULONG Win32kbaseSize;
    ULONG_PTR IsHotKeyAddress;
    ULONG_PTR SessionGlobals;
    ULONG_PTR TableBase;
    ULONG TableOffset;
    ULONG NextOffset;
    ULONG ModifiersOffset;
    ULONG VkOffset;
    ULONG IdOffset;
} KSW_KEYBOARD_HOTKEY_RUNTIME, *PKSW_KEYBOARD_HOTKEY_RUNTIME;

NTSTATUS
KswordARKKeyboardResolveHotkeyRuntime(
    _Out_ KSW_KEYBOARD_HOTKEY_RUNTIME* RuntimeOut
    );

ULONG64
KswordARKKeyboardHashHotkeyObject(
    _In_reads_bytes_(ObjectBytes) const UCHAR* Object,
    _In_ SIZE_T ObjectBytes
    );
