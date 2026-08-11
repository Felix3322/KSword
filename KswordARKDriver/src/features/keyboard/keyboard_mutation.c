/*++

Module Name:

    keyboard_mutation.c

Abstract:

    Exact-build, snapshot-guarded editing and deletion of ordinary win32k
    RegisterHotKey entries.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL, original caller context.

--*/

#include "ark/ark_driver.h"
#include "keyboard_internal.h"
#include "../../dispatch/ioctl_validation.h"
#include "../kernel/hook_scan_support.h"

#include <ntimage.h>

#define KSW_HOTKEY_BUCKET_COUNT 0x80UL
#define KSW_HOTKEY_CHAIN_LIMIT 512UL
#define KSW_HOTKEY_OBJECT_SIZE 0x48UL
#define KSW_HOTKEY_OWNER_OFFSET 0x00UL
#define KSW_HOTKEY_CALLBACK_OFFSET 0x08UL
#define KSW_HOTKEY_WINDOW_OFFSET 0x10UL
#define KSW_HOTKEY_DESTINATION_OFFSET 0x18UL
#define KSW_HOTKEY_MODIFIERS_OFFSET 0x20UL
#define KSW_HOTKEY_FLAGS_OFFSET 0x22UL
#define KSW_HOTKEY_VK_OFFSET 0x24UL
#define KSW_HOTKEY_ID_OFFSET 0x28UL
#define KSW_HOTKEY_NEXT_OFFSET 0x30UL
#define KSW_HOTKEY_CHILD_OFFSET 0x38UL
#define KSW_HOTKEY_TABLE_OFFSET 0x3290UL
#define KSW_HOTKEY_SESSION_CACHE_OFFSET 0x36A8UL
#define KSW_HOTKEY_REMOVE_MATCHING_RVA 0x1C8108UL
#define KSW_HOTKEY_EXPECTED_TIMESTAMP 0x5CD0A4AFUL
#define KSW_HOTKEY_EXPECTED_IMAGE_SIZE 0x00428000UL
#define KSW_HOTKEY_EXPECTED_PDB_AGE 1UL
#define KSW_HOTKEY_RSDS_SIGNATURE 0x53445352UL
#define KSW_HOTKEY_QUERY_OWNER_WINDOW_ID 3UL
#define KSW_HOTKEY_ALLOWED_MODIFIERS 0x0000400FUL

typedef VOID(NTAPI* KSW_ENTER_CRIT_FN)(VOID);
typedef VOID(NTAPI* KSW_LEAVE_CRIT_FN)(VOID);
typedef PVOID(NTAPI* KSW_VALIDATE_HWND_FN)(_In_ PVOID WindowHandle);
typedef PVOID(NTAPI* KSW_PS_GET_THREAD_WIN32_THREAD_FN)(_In_ PETHREAD Thread);
typedef BOOLEAN(*KSW_REMOVE_MATCHING_HOTKEYS_FN)(
    _In_ PVOID ThreadInfo,
    _In_opt_ PVOID WindowObject,
    _In_ ULONG HotkeyId,
    _In_ ULONG QueryType
    );

typedef struct _KSW_HOTKEY_RSDS_HEADER
{
    ULONG Signature;
    GUID Guid;
    ULONG Age;
} KSW_HOTKEY_RSDS_HEADER;

typedef struct _KSW_HOTKEY_VIEW
{
    UCHAR Bytes[KSW_HOTKEY_OBJECT_SIZE];
    ULONG_PTR OwnerThreadInfo;
    ULONG_PTR CallbackAddress;
    ULONG_PTR WindowHandle;
    ULONG_PTR DestinationHandle;
    USHORT Modifiers;
    USHORT Flags;
    ULONG VirtualKey;
    ULONG HotkeyId;
    ULONG_PTR NextHotkey;
    ULONG_PTR ChildFlink;
    ULONG_PTR ChildBlink;
    ULONG64 SnapshotHash;
} KSW_HOTKEY_VIEW;

typedef struct _KSW_HOTKEY_EXACT_RUNTIME
{
    KSW_KEYBOARD_HOTKEY_RUNTIME Layout;
    KSW_ENTER_CRIT_FN EnterCrit;
    KSW_LEAVE_CRIT_FN LeaveCrit;
    KSW_VALIDATE_HWND_FN ValidateHwnd;
    KSW_REMOVE_MATCHING_HOTKEYS_FN RemoveMatchingHotkeys;
    KSW_PS_GET_THREAD_WIN32_THREAD_FN PsGetThreadWin32Thread;
    ULONG TimeDateStamp;
    ULONG ImageSize;
    ULONG PdbAge;
} KSW_HOTKEY_EXACT_RUNTIME;

static const GUID g_KswHotkeyExpectedPdbGuid = {
    0x80DB0813UL,
    0x4711U,
    0x330DU,
    { 0xD7U, 0x06U, 0x8DU, 0x82U, 0x6FU, 0xF8U, 0xE1U, 0xB0U }
};

static const UCHAR g_KswHotkeyRemoveMatchingPrologue[] = {
    0x48U, 0x89U, 0x5CU, 0x24U, 0x08U, 0x48U, 0x89U, 0x6CU,
    0x24U, 0x10U, 0x48U, 0x89U, 0x74U, 0x24U, 0x18U, 0x57U,
    0x41U, 0x54U, 0x41U, 0x55U, 0x41U, 0x56U, 0x41U, 0x57U,
    0x48U, 0x83U, 0xECU, 0x30U, 0x40U, 0x32U, 0xEDU, 0x45U
};

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,
    _In_z_ PCSTR RoutineName
    );

static BOOLEAN
KswHotkeyPointerInImage(
    _In_ PVOID Address,
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize
    )
{
    const ULONG_PTR addressValue = (ULONG_PTR)Address;
    const ULONG_PTR imageBaseValue = (ULONG_PTR)ImageBase;

    return Address != NULL && ImageBase != NULL && ImageSize != 0UL &&
        addressValue >= imageBaseValue &&
        addressValue < (imageBaseValue + (ULONG_PTR)ImageSize);
}

static BOOLEAN
KswHotkeyReadLoadedRsds(
    _In_ PVOID ImageBase,
    _In_ ULONG ImageSize,
    _Out_ ULONG* TimeDateStampOut,
    _Out_ ULONG* SizeOfImageOut,
    _Out_ GUID* PdbGuidOut,
    _Out_ ULONG* PdbAgeOut
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    IMAGE_DATA_DIRECTORY debugDirectory;
    ULONG debugIndex = 0UL;
    ULONG debugCount = 0UL;

    if (ImageBase == NULL || TimeDateStampOut == NULL || SizeOfImageOut == NULL ||
        PdbGuidOut == NULL || PdbAgeOut == NULL || ImageSize < sizeof(ntHeaders)) {
        return FALSE;
    }
    *TimeDateStampOut = 0UL;
    *SizeOfImageOut = 0UL;
    RtlZeroMemory(PdbGuidOut, sizeof(*PdbGuidOut));
    *PdbAgeOut = 0UL;
    if (!KswordARKHookReadMemorySafe(ImageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0 ||
        (ULONG)dosHeader.e_lfanew > ImageSize - sizeof(ntHeaders) ||
        !KswordARKHookReadMemorySafe(
            (const UCHAR*)ImageBase + (ULONG)dosHeader.e_lfanew,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.OptionalHeader.SizeOfImage != ImageSize) {
        return FALSE;
    }

    *TimeDateStampOut = ntHeaders.FileHeader.TimeDateStamp;
    *SizeOfImageOut = ntHeaders.OptionalHeader.SizeOfImage;
    debugDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debugDirectory.VirtualAddress == 0UL ||
        debugDirectory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        debugDirectory.VirtualAddress > ImageSize ||
        debugDirectory.Size > ImageSize - debugDirectory.VirtualAddress) {
        return FALSE;
    }
    debugCount = debugDirectory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    if (debugCount == 0UL || debugCount > 64UL) {
        return FALSE;
    }

    for (debugIndex = 0UL; debugIndex < debugCount; ++debugIndex) {
        IMAGE_DEBUG_DIRECTORY debugEntry;
        KSW_HOTKEY_RSDS_HEADER rsdsHeader;
        const ULONG debugEntryRva = debugDirectory.VirtualAddress +
            (debugIndex * sizeof(IMAGE_DEBUG_DIRECTORY));

        if (!KswordARKHookReadMemorySafe(
                (const UCHAR*)ImageBase + debugEntryRva,
                &debugEntry,
                sizeof(debugEntry)) ||
            debugEntry.Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
            debugEntry.AddressOfRawData == 0UL ||
            debugEntry.SizeOfData < sizeof(rsdsHeader) ||
            debugEntry.AddressOfRawData > ImageSize ||
            sizeof(rsdsHeader) > ImageSize - debugEntry.AddressOfRawData ||
            !KswordARKHookReadMemorySafe(
                (const UCHAR*)ImageBase + debugEntry.AddressOfRawData,
                &rsdsHeader,
                sizeof(rsdsHeader)) ||
            rsdsHeader.Signature != KSW_HOTKEY_RSDS_SIGNATURE) {
            continue;
        }
        *PdbGuidOut = rsdsHeader.Guid;
        *PdbAgeOut = rsdsHeader.Age;
        return TRUE;
    }
    return FALSE;
}

static NTSTATUS
KswHotkeyResolveExactRuntime(
    _Out_ KSW_HOTKEY_EXACT_RUNTIME* RuntimeOut
    )
{
    GUID pdbGuid;
    UCHAR prologue[sizeof(g_KswHotkeyRemoveMatchingPrologue)] = { 0 };
    UNICODE_STRING routineName;
    NTSTATUS status = STATUS_SUCCESS;

    if (RuntimeOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(RuntimeOut, sizeof(*RuntimeOut));
    RtlZeroMemory(&pdbGuid, sizeof(pdbGuid));
    status = KswordARKKeyboardResolveHotkeyRuntime(&RuntimeOut->Layout);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (RuntimeOut->Layout.TableBase != 0U ||
        RuntimeOut->Layout.TableOffset != KSW_HOTKEY_TABLE_OFFSET ||
        RuntimeOut->Layout.NextOffset != KSW_HOTKEY_NEXT_OFFSET ||
        RuntimeOut->Layout.ModifiersOffset != KSW_HOTKEY_MODIFIERS_OFFSET ||
        RuntimeOut->Layout.VkOffset != KSW_HOTKEY_VK_OFFSET ||
        RuntimeOut->Layout.IdOffset != KSW_HOTKEY_ID_OFFSET ||
        !KswHotkeyReadLoadedRsds(
            RuntimeOut->Layout.Win32kfullBase,
            RuntimeOut->Layout.Win32kfullSize,
            &RuntimeOut->TimeDateStamp,
            &RuntimeOut->ImageSize,
            &pdbGuid,
            &RuntimeOut->PdbAge) ||
        RuntimeOut->TimeDateStamp != KSW_HOTKEY_EXPECTED_TIMESTAMP ||
        RuntimeOut->ImageSize != KSW_HOTKEY_EXPECTED_IMAGE_SIZE ||
        RuntimeOut->PdbAge != KSW_HOTKEY_EXPECTED_PDB_AGE ||
        RtlCompareMemory(&pdbGuid, &g_KswHotkeyExpectedPdbGuid, sizeof(GUID)) != sizeof(GUID)) {
        return STATUS_REVISION_MISMATCH;
    }

    RuntimeOut->EnterCrit = (KSW_ENTER_CRIT_FN)RtlFindExportedRoutineByName(
        RuntimeOut->Layout.Win32kbaseBase,
        "EnterCrit");
    RuntimeOut->LeaveCrit = (KSW_LEAVE_CRIT_FN)RtlFindExportedRoutineByName(
        RuntimeOut->Layout.Win32kbaseBase,
        "UserSessionSwitchLeaveCrit");
    RuntimeOut->ValidateHwnd = (KSW_VALIDATE_HWND_FN)RtlFindExportedRoutineByName(
        RuntimeOut->Layout.Win32kbaseBase,
        "ValidateHwnd");
    RuntimeOut->RemoveMatchingHotkeys = (KSW_REMOVE_MATCHING_HOTKEYS_FN)(
        (UCHAR*)RuntimeOut->Layout.Win32kfullBase + KSW_HOTKEY_REMOVE_MATCHING_RVA);
    RtlInitUnicodeString(&routineName, L"PsGetThreadWin32Thread");
    RuntimeOut->PsGetThreadWin32Thread =
        (KSW_PS_GET_THREAD_WIN32_THREAD_FN)MmGetSystemRoutineAddress(&routineName);
    if (!KswHotkeyPointerInImage(
            (PVOID)RuntimeOut->EnterCrit,
            RuntimeOut->Layout.Win32kbaseBase,
            RuntimeOut->Layout.Win32kbaseSize) ||
        !KswHotkeyPointerInImage(
            (PVOID)RuntimeOut->LeaveCrit,
            RuntimeOut->Layout.Win32kbaseBase,
            RuntimeOut->Layout.Win32kbaseSize) ||
        !KswHotkeyPointerInImage(
            (PVOID)RuntimeOut->ValidateHwnd,
            RuntimeOut->Layout.Win32kbaseBase,
            RuntimeOut->Layout.Win32kbaseSize) ||
        RuntimeOut->PsGetThreadWin32Thread == NULL ||
        !KswHotkeyPointerInImage(
            (PVOID)RuntimeOut->RemoveMatchingHotkeys,
            RuntimeOut->Layout.Win32kfullBase,
            RuntimeOut->Layout.Win32kfullSize) ||
        !KswordARKHookReadMemorySafe(
            (const VOID*)RuntimeOut->RemoveMatchingHotkeys,
            prologue,
            sizeof(prologue)) ||
        RtlCompareMemory(
            prologue,
            g_KswHotkeyRemoveMatchingPrologue,
            sizeof(prologue)) != sizeof(prologue)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
KswHotkeyReadView(
    _In_ ULONG_PTR HotkeyObject,
    _Out_ KSW_HOTKEY_VIEW* ViewOut
    )
{
    if (HotkeyObject == 0U || ViewOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(ViewOut, sizeof(*ViewOut));
    if (!KswordARKHookReadMemorySafe(
            (const VOID*)HotkeyObject,
            ViewOut->Bytes,
            sizeof(ViewOut->Bytes))) {
        return FALSE;
    }
    RtlCopyMemory(&ViewOut->OwnerThreadInfo, ViewOut->Bytes + KSW_HOTKEY_OWNER_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&ViewOut->CallbackAddress, ViewOut->Bytes + KSW_HOTKEY_CALLBACK_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&ViewOut->WindowHandle, ViewOut->Bytes + KSW_HOTKEY_WINDOW_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&ViewOut->DestinationHandle, ViewOut->Bytes + KSW_HOTKEY_DESTINATION_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&ViewOut->Modifiers, ViewOut->Bytes + KSW_HOTKEY_MODIFIERS_OFFSET, sizeof(USHORT));
    RtlCopyMemory(&ViewOut->Flags, ViewOut->Bytes + KSW_HOTKEY_FLAGS_OFFSET, sizeof(USHORT));
    RtlCopyMemory(&ViewOut->VirtualKey, ViewOut->Bytes + KSW_HOTKEY_VK_OFFSET, sizeof(ULONG));
    RtlCopyMemory(&ViewOut->HotkeyId, ViewOut->Bytes + KSW_HOTKEY_ID_OFFSET, sizeof(ULONG));
    RtlCopyMemory(&ViewOut->NextHotkey, ViewOut->Bytes + KSW_HOTKEY_NEXT_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&ViewOut->ChildFlink, ViewOut->Bytes + KSW_HOTKEY_CHILD_OFFSET, sizeof(PVOID));
    RtlCopyMemory(&ViewOut->ChildBlink, ViewOut->Bytes + KSW_HOTKEY_CHILD_OFFSET + sizeof(PVOID), sizeof(PVOID));
    ViewOut->SnapshotHash = KswordARKKeyboardHashHotkeyObject(ViewOut->Bytes, sizeof(ViewOut->Bytes));
    return TRUE;
}

static BOOLEAN
KswHotkeyViewMatchesRequest(
    _In_ const KSW_HOTKEY_VIEW* View,
    _In_ const KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST* Request
    )
{
    return View != NULL && Request != NULL &&
        View->OwnerThreadInfo == (ULONG_PTR)Request->expectedThreadInfo &&
        View->WindowHandle == (ULONG_PTR)Request->expectedWindowHandle &&
        View->DestinationHandle == (ULONG_PTR)Request->expectedDestinationHandle &&
        View->CallbackAddress == (ULONG_PTR)Request->expectedCallbackAddress &&
        View->NextHotkey == (ULONG_PTR)Request->expectedNextHotkeyObject &&
        View->ChildFlink == (ULONG_PTR)Request->expectedChildListFlink &&
        View->ChildBlink == (ULONG_PTR)Request->expectedChildListBlink &&
        View->Modifiers == (USHORT)Request->expectedModifiers &&
        View->Flags == (USHORT)Request->expectedModifierFlags2 &&
        View->VirtualKey == Request->expectedVirtualKey &&
        View->HotkeyId == Request->expectedHotkeyId &&
        View->SnapshotHash == Request->expectedSnapshotHash;
}

static BOOLEAN
KswHotkeyViewIsOrdinaryStandalone(
    _In_ ULONG_PTR HotkeyObject,
    _In_ const KSW_HOTKEY_VIEW* View
    )
{
    const ULONG_PTR childHead = HotkeyObject + KSW_HOTKEY_CHILD_OFFSET;

    return View != NULL && View->OwnerThreadInfo != 0U &&
        View->CallbackAddress == 0U && View->Flags == 0U &&
        View->VirtualKey != 0UL && View->VirtualKey <= 0xFFUL &&
        View->ChildFlink == childHead && View->ChildBlink == childHead;
}

static NTSTATUS
KswHotkeyFindObjectLink(
    _In_ ULONG_PTR TableAddress,
    _In_ ULONG BucketIndex,
    _In_ ULONG_PTR HotkeyObject,
    _Out_ ULONG_PTR* LinkAddressOut,
    _Out_ ULONG_PTR* NextHotkeyOut
    )
{
    ULONG_PTR linkAddress = TableAddress + ((ULONG_PTR)BucketIndex * sizeof(PVOID));
    ULONG_PTR currentObject = 0U;
    ULONG depth = 0UL;

    if (LinkAddressOut == NULL || NextHotkeyOut == NULL || BucketIndex >= KSW_HOTKEY_BUCKET_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }
    *LinkAddressOut = 0U;
    *NextHotkeyOut = 0U;
    while (depth < KSW_HOTKEY_CHAIN_LIMIT) {
        if (!KswordARKHookReadMemorySafe((const VOID*)linkAddress, &currentObject, sizeof(currentObject))) {
            return STATUS_PARTIAL_COPY;
        }
        if (currentObject == 0U) {
            return STATUS_NOT_FOUND;
        }
        if (currentObject == HotkeyObject) {
            KSW_HOTKEY_VIEW view;

            if (!KswHotkeyReadView(currentObject, &view)) {
                return STATUS_PARTIAL_COPY;
            }
            *LinkAddressOut = linkAddress;
            *NextHotkeyOut = view.NextHotkey;
            return STATUS_SUCCESS;
        }
        linkAddress = currentObject + KSW_HOTKEY_NEXT_OFFSET;
        ++depth;
    }
    return STATUS_DATA_ERROR;
}

static NTSTATUS
KswHotkeyFindConflict(
    _In_ ULONG_PTR TableAddress,
    _In_ ULONG_PTR TargetObject,
    _In_ USHORT Modifiers,
    _In_ ULONG VirtualKey
    )
{
    ULONG bucketIndex = 0UL;

    for (bucketIndex = 0UL; bucketIndex < KSW_HOTKEY_BUCKET_COUNT; ++bucketIndex) {
        ULONG_PTR currentObject = 0U;
        ULONG depth = 0UL;
        const ULONG_PTR headAddress = TableAddress + ((ULONG_PTR)bucketIndex * sizeof(PVOID));

        if (!KswordARKHookReadMemorySafe((const VOID*)headAddress, &currentObject, sizeof(currentObject))) {
            return STATUS_PARTIAL_COPY;
        }
        while (currentObject != 0U && depth < KSW_HOTKEY_CHAIN_LIMIT) {
            KSW_HOTKEY_VIEW view;

            if (!KswHotkeyReadView(currentObject, &view)) {
                return STATUS_PARTIAL_COPY;
            }
            if (currentObject != TargetObject &&
                view.Modifiers == Modifiers && view.VirtualKey == VirtualKey) {
                return STATUS_OBJECT_NAME_COLLISION;
            }
            if (view.NextHotkey == currentObject) {
                return STATUS_DATA_ERROR;
            }
            currentObject = view.NextHotkey;
            ++depth;
        }
        if (currentObject != 0U) {
            return STATUS_DATA_ERROR;
        }
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
KswHotkeyOtherBytesUnchanged(
    _In_ const KSW_HOTKEY_VIEW* Before,
    _In_ const KSW_HOTKEY_VIEW* After
    )
{
    ULONG byteIndex = 0UL;

    if (Before == NULL || After == NULL) {
        return FALSE;
    }
    for (byteIndex = 0UL; byteIndex < KSW_HOTKEY_OBJECT_SIZE; ++byteIndex) {
        const BOOLEAN mutableByte =
            (byteIndex >= KSW_HOTKEY_MODIFIERS_OFFSET && byteIndex < KSW_HOTKEY_FLAGS_OFFSET) ||
            (byteIndex >= KSW_HOTKEY_VK_OFFSET && byteIndex < KSW_HOTKEY_VK_OFFSET + sizeof(ULONG)) ||
            (byteIndex >= KSW_HOTKEY_NEXT_OFFSET && byteIndex < KSW_HOTKEY_NEXT_OFFSET + sizeof(PVOID));

        if (!mutableByte && Before->Bytes[byteIndex] != After->Bytes[byteIndex]) {
            return FALSE;
        }
    }
    return TRUE;
}

static NTSTATUS
KswHotkeyWriteEdit(
    _In_ ULONG_PTR TableAddress,
    _In_ ULONG_PTR OldLinkAddress,
    _In_ ULONG OldBucketIndex,
    _In_ ULONG NewBucketIndex,
    _In_ ULONG_PTR HotkeyObject,
    _In_ const KSW_HOTKEY_VIEW* Before,
    _In_ USHORT NewModifiers,
    _In_ ULONG NewVirtualKey,
    _Out_ KSW_HOTKEY_VIEW* AfterOut,
    _Out_ BOOLEAN* RolledBackOut
    )
{
    ULONG_PTR newHeadAddress = 0U;
    ULONG_PTR newHeadObject = 0U;
    ULONG_PTR verifyPointer = 0U;
    BOOLEAN rebucket = FALSE;
    BOOLEAN writeStarted = FALSE;
    BOOLEAN validPostState = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (Before == NULL || AfterOut == NULL || RolledBackOut == NULL ||
        OldBucketIndex >= KSW_HOTKEY_BUCKET_COUNT || NewBucketIndex >= KSW_HOTKEY_BUCKET_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(AfterOut, sizeof(*AfterOut));
    *RolledBackOut = FALSE;
    rebucket = OldBucketIndex != NewBucketIndex;
    newHeadAddress = TableAddress + ((ULONG_PTR)NewBucketIndex * sizeof(PVOID));
    if (rebucket && !KswordARKHookReadMemorySafe(
            (const VOID*)newHeadAddress,
            &newHeadObject,
            sizeof(newHeadObject))) {
        return STATUS_PARTIAL_COPY;
    }

    __try {
        writeStarted = TRUE;
        if (rebucket) {
            *(volatile ULONG_PTR*)OldLinkAddress = Before->NextHotkey;
            *(volatile ULONG_PTR*)(HotkeyObject + KSW_HOTKEY_NEXT_OFFSET) = newHeadObject;
            *(volatile ULONG_PTR*)newHeadAddress = HotkeyObject;
        }
        *(volatile USHORT*)(HotkeyObject + KSW_HOTKEY_MODIFIERS_OFFSET) = NewModifiers;
        *(volatile ULONG*)(HotkeyObject + KSW_HOTKEY_VK_OFFSET) = NewVirtualKey;
        KeMemoryBarrier();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (NT_SUCCESS(status) && KswHotkeyReadView(HotkeyObject, AfterOut)) {
        validPostState = AfterOut->Modifiers == NewModifiers &&
            AfterOut->VirtualKey == NewVirtualKey &&
            AfterOut->NextHotkey == (rebucket ? newHeadObject : Before->NextHotkey) &&
            KswHotkeyOtherBytesUnchanged(Before, AfterOut);
        if (validPostState && KswordARKHookReadMemorySafe(
                (const VOID*)(rebucket ? newHeadAddress : OldLinkAddress),
                &verifyPointer,
                sizeof(verifyPointer))) {
            validPostState = verifyPointer == HotkeyObject;
        }
        else {
            validPostState = FALSE;
        }
        if (validPostState && rebucket && KswordARKHookReadMemorySafe(
                (const VOID*)OldLinkAddress,
                &verifyPointer,
                sizeof(verifyPointer))) {
            validPostState = verifyPointer == Before->NextHotkey;
        }
        else if (validPostState && rebucket) {
            validPostState = FALSE;
        }
    }
    if (validPostState) {
        return STATUS_SUCCESS;
    }
    if (NT_SUCCESS(status)) {
        status = STATUS_DATA_ERROR;
    }

    if (writeStarted) {
        KSW_HOTKEY_VIEW rollbackView;
        BOOLEAN rollbackValid = FALSE;

        RtlZeroMemory(&rollbackView, sizeof(rollbackView));
        __try {
            *(volatile USHORT*)(HotkeyObject + KSW_HOTKEY_MODIFIERS_OFFSET) = Before->Modifiers;
            *(volatile ULONG*)(HotkeyObject + KSW_HOTKEY_VK_OFFSET) = Before->VirtualKey;
            if (rebucket) {
                *(volatile ULONG_PTR*)newHeadAddress = newHeadObject;
                *(volatile ULONG_PTR*)(HotkeyObject + KSW_HOTKEY_NEXT_OFFSET) = Before->NextHotkey;
                *(volatile ULONG_PTR*)OldLinkAddress = HotkeyObject;
            }
            KeMemoryBarrier();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            rollbackValid = FALSE;
        }
        if (KswHotkeyReadView(HotkeyObject, &rollbackView) &&
            rollbackView.SnapshotHash == Before->SnapshotHash &&
            KswordARKHookReadMemorySafe(
                (const VOID*)OldLinkAddress,
                &verifyPointer,
                sizeof(verifyPointer)) &&
            verifyPointer == HotkeyObject) {
            rollbackValid = TRUE;
            if (rebucket && (!KswordARKHookReadMemorySafe(
                    (const VOID*)newHeadAddress,
                    &verifyPointer,
                    sizeof(verifyPointer)) || verifyPointer != newHeadObject)) {
                rollbackValid = FALSE;
            }
        }
        *RolledBackOut = rollbackValid;
    }
    return status;
}

static VOID
KswHotkeyInitializeResponse(
    _Out_ KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_RESPONSE* Response,
    _In_opt_ const KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST* Request
    )
{
    RtlZeroMemory(Response, sizeof(*Response));
    Response->size = sizeof(*Response);
    Response->version = KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
    Response->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_INVALID_REQUEST;
    if (Request != NULL) {
        Response->operation = Request->operation;
        Response->previousBucketIndex = Request->expectedBucketIndex;
        Response->currentBucketIndex = Request->expectedBucketIndex;
        Response->previousModifiers = Request->expectedModifiers;
        Response->currentModifiers = Request->expectedModifiers;
        Response->previousVirtualKey = Request->expectedVirtualKey;
        Response->currentVirtualKey = Request->expectedVirtualKey;
        Response->hotkeyObject = Request->hotkeyObject;
        Response->sessionGlobals = Request->sessionGlobals;
        Response->previousSnapshotHash = Request->expectedSnapshotHash;
        Response->currentSnapshotHash = Request->expectedSnapshotHash;
    }
}

static BOOLEAN
KswHotkeyRequestShapeValid(
    _In_ const KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST* Request
    )
{
    if (Request == NULL || Request->size != sizeof(*Request) ||
        Request->version != KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION ||
        (Request->flags & ~KSWORD_ARK_KEYBOARD_MUTATION_FLAG_UI_CONFIRMED) != 0UL ||
        (Request->flags & KSWORD_ARK_KEYBOARD_MUTATION_FLAG_UI_CONFIRMED) == 0UL ||
        Request->confirmationToken != KSWORD_ARK_KEYBOARD_MUTATION_CONFIRMATION_TOKEN ||
        Request->hotkeyObject == 0ULL || Request->sessionGlobals == 0ULL ||
        Request->expectedThreadInfo == 0ULL || Request->expectedSnapshotHash == 0ULL ||
        Request->expectedBucketIndex >= KSW_HOTKEY_BUCKET_COUNT ||
        Request->expectedModifiers > 0xFFFFUL || Request->expectedModifierFlags2 > 0xFFFFUL ||
        Request->expectedVirtualKey == 0UL || Request->expectedVirtualKey > 0xFFUL ||
        Request->expectedBucketIndex != (Request->expectedVirtualKey & (KSW_HOTKEY_BUCKET_COUNT - 1UL))) {
        return FALSE;
    }
    if (Request->operation == KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_EDIT) {
        return Request->newModifiers <= 0xFFFFUL &&
            (Request->newModifiers & ~KSW_HOTKEY_ALLOWED_MODIFIERS) == 0UL &&
            Request->newVirtualKey != 0UL && Request->newVirtualKey <= 0xFFUL;
    }
    if (Request->operation == KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_DELETE) {
        return Request->newModifiers == 0UL && Request->newVirtualKey == 0UL;
    }
    return FALSE;
}

static NTSTATUS
KswHotkeyCountOwnerWindowIdMatches(
    _In_ ULONG_PTR TableAddress,
    _In_ const KSW_HOTKEY_VIEW* TargetView,
    _Out_ ULONG* MatchCountOut
    )
{
    ULONG bucketIndex = 0UL;
    ULONG matchCount = 0UL;

    if (TargetView == NULL || MatchCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *MatchCountOut = 0UL;
    for (bucketIndex = 0UL; bucketIndex < KSW_HOTKEY_BUCKET_COUNT; ++bucketIndex) {
        ULONG_PTR currentObject = 0U;
        ULONG depth = 0UL;
        const ULONG_PTR headAddress = TableAddress + ((ULONG_PTR)bucketIndex * sizeof(PVOID));

        if (!KswordARKHookReadMemorySafe((const VOID*)headAddress, &currentObject, sizeof(currentObject))) {
            return STATUS_PARTIAL_COPY;
        }
        while (currentObject != 0U && depth < KSW_HOTKEY_CHAIN_LIMIT) {
            KSW_HOTKEY_VIEW view;

            if (!KswHotkeyReadView(currentObject, &view)) {
                return STATUS_PARTIAL_COPY;
            }
            if (view.OwnerThreadInfo == TargetView->OwnerThreadInfo &&
                view.WindowHandle == TargetView->WindowHandle &&
                view.HotkeyId == TargetView->HotkeyId) {
                ++matchCount;
                if (matchCount > 1UL) {
                    *MatchCountOut = matchCount;
                    return STATUS_SUCCESS;
                }
            }
            if (view.NextHotkey == currentObject) {
                return STATUS_DATA_ERROR;
            }
            currentObject = view.NextHotkey;
            ++depth;
        }
        if (currentObject != 0U) {
            return STATUS_DATA_ERROR;
        }
    }
    *MatchCountOut = matchCount;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKeyboardIoctlMutateHotkey(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST* inputBuffer = NULL;
    KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_RESPONSE* outputBuffer = NULL;
    KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_REQUEST requestSnapshot;
    KSWORD_ARK_SAFETY_CONTEXT safetyContext;
    KSW_HOTKEY_EXACT_RUNTIME runtime;
    KSW_HOTKEY_VIEW beforeView;
    KSW_HOTKEY_VIEW afterView;
    PVOID windowObject = NULL;
    PVOID callerThreadInfo = NULL;
    ULONG_PTR tableAddress = 0U;
    ULONG_PTR oldLinkAddress = 0U;
    ULONG_PTR oldNextObject = 0U;
    ULONG matchCount = 0UL;
    ULONG newBucketIndex = 0UL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN critEntered = FALSE;
    BOOLEAN operationChanged = FALSE;
    BOOLEAN rolledBack = FALSE;
    static const WCHAR targetText[] = L"win32k RegisterHotKey table";

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    if (!NT_SUCCESS(status)) {
        return status;
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
    KswHotkeyInitializeResponse(outputBuffer, &requestSnapshot);
    *BytesReturned = sizeof(*outputBuffer);
    if (!KswHotkeyRequestShapeValid(&requestSnapshot)) {
        outputBuffer->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.Operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
    safetyContext.ContextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
    safetyContext.TargetText = targetText;
    safetyContext.TargetTextChars = (USHORT)(RTL_NUMBER_OF(targetText) - 1U);
    status = KswordARKSafetyEvaluate(Device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_SAFETY_DENIED;
        outputBuffer->lastStatus = status;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&runtime, sizeof(runtime));
    status = KswHotkeyResolveExactRuntime(&runtime);
    if (!NT_SUCCESS(status)) {
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSUPPORTED_BUILD;
        outputBuffer->lastStatus = status;
        return STATUS_SUCCESS;
    }
    outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_IDENTITY_VALIDATED;
    outputBuffer->imageTimeDateStamp = runtime.TimeDateStamp;
    outputBuffer->imageSize = runtime.ImageSize;
    outputBuffer->pdbAge = runtime.PdbAge;

    callerThreadInfo = runtime.PsGetThreadWin32Thread(PsGetCurrentThread());
    if (callerThreadInfo == NULL || runtime.Layout.SessionGlobals == 0U ||
        runtime.Layout.SessionGlobals != (ULONG_PTR)requestSnapshot.sessionGlobals) {
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CALLER_CONTEXT_REQUIRED;
        outputBuffer->lastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_SUCCESS;
    }
    outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CALLER_VALIDATED;
    tableAddress = runtime.Layout.SessionGlobals + KSW_HOTKEY_TABLE_OFFSET;

    __try {
        runtime.EnterCrit();
        critEntered = TRUE;
        if (runtime.Layout.SessionGlobals != (ULONG_PTR)requestSnapshot.sessionGlobals) {
            status = STATUS_REVISION_MISMATCH;
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_STALE_SNAPSHOT;
            __leave;
        }
        status = KswHotkeyFindObjectLink(
            tableAddress,
            requestSnapshot.expectedBucketIndex,
            (ULONG_PTR)requestSnapshot.hotkeyObject,
            &oldLinkAddress,
            &oldNextObject);
        if (!NT_SUCCESS(status) || !KswHotkeyReadView(
                (ULONG_PTR)requestSnapshot.hotkeyObject,
                &beforeView) ||
            oldNextObject != beforeView.NextHotkey ||
            !KswHotkeyViewMatchesRequest(&beforeView, &requestSnapshot)) {
            if (NT_SUCCESS(status)) {
                status = STATUS_REVISION_MISMATCH;
            }
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_STALE_SNAPSHOT;
            __leave;
        }
        if (!KswHotkeyViewIsOrdinaryStandalone(
                (ULONG_PTR)requestSnapshot.hotkeyObject,
                &beforeView)) {
            status = STATUS_NOT_SUPPORTED;
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSAFE_TARGET;
            __leave;
        }
        outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_SNAPSHOT_VALIDATED;
        outputBuffer->previousSnapshotHash = beforeView.SnapshotHash;
        outputBuffer->currentSnapshotHash = beforeView.SnapshotHash;

        if (beforeView.WindowHandle != 0U) {
            windowObject = runtime.ValidateHwnd((PVOID)beforeView.WindowHandle);
            if (windowObject == NULL) {
                status = STATUS_INVALID_HANDLE;
                outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_STALE_SNAPSHOT;
                __leave;
            }
        }

        if (requestSnapshot.operation == KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_DELETE) {
            BOOLEAN removed = FALSE;
            NTSTATUS verifyStatus = STATUS_SUCCESS;

            status = KswHotkeyCountOwnerWindowIdMatches(tableAddress, &beforeView, &matchCount);
            if (!NT_SUCCESS(status) || matchCount != 1UL) {
                if (NT_SUCCESS(status)) {
                    status = STATUS_OBJECT_NAME_COLLISION;
                }
                outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSAFE_TARGET;
                __leave;
            }
            removed = runtime.RemoveMatchingHotkeys(
                (PVOID)beforeView.OwnerThreadInfo,
                windowObject,
                beforeView.HotkeyId,
                KSW_HOTKEY_QUERY_OWNER_WINDOW_ID);
            verifyStatus = KswHotkeyFindObjectLink(
                tableAddress,
                requestSnapshot.expectedBucketIndex,
                (ULONG_PTR)requestSnapshot.hotkeyObject,
                &oldLinkAddress,
                &oldNextObject);
            if (!removed || verifyStatus != STATUS_NOT_FOUND) {
                status = !removed ? STATUS_UNSUCCESSFUL : verifyStatus;
                outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
                __leave;
            }
            *(volatile ULONG_PTR*)(runtime.Layout.SessionGlobals + KSW_HOTKEY_SESSION_CACHE_OFFSET) = 0U;
            KeMemoryBarrier();
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK;
            outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED;
            outputBuffer->currentModifiers = 0UL;
            outputBuffer->currentVirtualKey = 0UL;
            outputBuffer->currentSnapshotHash = 0ULL;
            operationChanged = TRUE;
            status = STATUS_SUCCESS;
            __leave;
        }

        newBucketIndex = requestSnapshot.newVirtualKey & (KSW_HOTKEY_BUCKET_COUNT - 1UL);
        status = KswHotkeyFindConflict(
            tableAddress,
            (ULONG_PTR)requestSnapshot.hotkeyObject,
            (USHORT)requestSnapshot.newModifiers,
            requestSnapshot.newVirtualKey);
        if (!NT_SUCCESS(status)) {
            outputBuffer->status = status == STATUS_OBJECT_NAME_COLLISION ?
                KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CONFLICT :
                KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
            __leave;
        }
        if (beforeView.Modifiers == (USHORT)requestSnapshot.newModifiers &&
            beforeView.VirtualKey == requestSnapshot.newVirtualKey) {
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK;
            outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_OTHER_BYTES_SAME;
            status = STATUS_SUCCESS;
            __leave;
        }

        RtlZeroMemory(&afterView, sizeof(afterView));
        status = KswHotkeyWriteEdit(
            tableAddress,
            oldLinkAddress,
            requestSnapshot.expectedBucketIndex,
            newBucketIndex,
            (ULONG_PTR)requestSnapshot.hotkeyObject,
            &beforeView,
            (USHORT)requestSnapshot.newModifiers,
            requestSnapshot.newVirtualKey,
            &afterView,
            &rolledBack);
        if (!NT_SUCCESS(status)) {
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
            if (rolledBack) {
                outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_ROLLED_BACK;
            }
            __leave;
        }
        *(volatile ULONG_PTR*)(runtime.Layout.SessionGlobals + KSW_HOTKEY_SESSION_CACHE_OFFSET) = 0U;
        KeMemoryBarrier();
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK;
        outputBuffer->responseFlags |=
            KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED |
            KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_OTHER_BYTES_SAME;
        if (newBucketIndex != requestSnapshot.expectedBucketIndex) {
            outputBuffer->responseFlags |= KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_REBUCKETED;
        }
        outputBuffer->currentBucketIndex = newBucketIndex;
        outputBuffer->currentModifiers = afterView.Modifiers;
        outputBuffer->currentVirtualKey = afterView.VirtualKey;
        outputBuffer->currentSnapshotHash = afterView.SnapshotHash;
        operationChanged = TRUE;
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
    }

    if (critEntered) {
        __try {
            runtime.LeaveCrit();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            outputBuffer->status = KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED;
        }
    }
    if (!operationChanged && outputBuffer->status == KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK) {
        outputBuffer->currentBucketIndex = requestSnapshot.expectedBucketIndex;
    }
    outputBuffer->lastStatus = status;
    return STATUS_SUCCESS;
}
