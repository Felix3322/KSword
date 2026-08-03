/*++

Module Name:

    callback_extended_special.c

Abstract:

    Enumerates power-setting, coalescing, priority, debug-print, EMP, and
    Plug-and-Play callback registrations. Stable exports are used only as
    bounded anchors; every recovered global and record is validated against
    live list topology and executable loaded-module ranges before publication.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL read-only query path.

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"
#include "ark/ark_dyndata.h"
#include "../../platform/pool_compat.h"
#include "../../platform/runtime_signature_scan.h"

#define KSW_SPECIAL_MAX_REFERENCES 96UL
#define KSW_SPECIAL_MAX_RECORDS 128UL
#define KSW_SPECIAL_ROUTINE_SCAN_BYTES 0x600UL
#define KSW_SPECIAL_MAX_CALL_DEPTH 2UL
#define KSW_SPECIAL_RECORD_BACK_BYTES 0x40UL
#define KSW_SPECIAL_RECORD_FORWARD_BYTES 0xA0UL
#define KSW_SPECIAL_INDIRECT_SCAN_BYTES 0x60UL
#define KSW_SPECIAL_PRIORITY_SLOT_COUNT 8UL
#define KSW_SPECIAL_PNP_LIST_COUNT 13UL
#define KSW_SPECIAL_WORKSPACE_POOL_TAG 'wSsK'

typedef struct _KSW_SPECIAL_RECORD
{
    ULONG64 CallbackAddress;
    ULONG64 ContextAddress;
    ULONG64 RegistrationAddress;
} KSW_SPECIAL_RECORD, *PKSW_SPECIAL_RECORD;

typedef struct _KSW_SPECIAL_CAPTURE
{
    ULONG64 GlobalAddress;
    ULONG Count;
    BOOLEAN Valid;
    KSW_SPECIAL_RECORD Records[KSW_SPECIAL_MAX_RECORDS];
} KSW_SPECIAL_CAPTURE, *PKSW_SPECIAL_CAPTURE;

/*
 * Candidate captures are about 3 KiB each.  Keeping the references, strongest
 * candidate, and scratch candidate in one reusable pool block prevents the
 * nested signature-scan call chain from exhausting the small kernel stack.
 * 同一非分页工作区也保存 DynData、PE 视图和遍历记录，确保嵌套验证函数
 * 不再把这些大对象压入有限的内核栈。
 */
typedef struct _KSW_SPECIAL_WORKSPACE
{
    KSW_DYN_STATE DynState;
    KSW_RUNTIME_IMAGE_VIEW NtosView;
    KSW_RUNTIME_IMAGE_VIEW ModuleView;
    KSW_RUNTIME_DATA_REFERENCE References[KSW_SPECIAL_MAX_REFERENCES];
    KSW_SPECIAL_CAPTURE Best;
    KSW_SPECIAL_CAPTURE Candidate;
    KSW_SPECIAL_CAPTURE ListScratch;
    ULONG_PTR Visited[KSW_SPECIAL_MAX_RECORDS];
} KSW_SPECIAL_WORKSPACE, *PKSW_SPECIAL_WORKSPACE;

typedef enum _KSW_SPECIAL_CAPTURE_KIND
{
    KswSpecialCaptureDoubleList = 1,
    KswSpecialCaptureDoubleListIndirect = 2,
    KswSpecialCaptureSingleList = 3,
    KswSpecialCapturePriorityArray = 4,
    KswSpecialCapturePnpLists = 5
} KSW_SPECIAL_CAPTURE_KIND;

static BOOLEAN
KswordArkSpecialIsKernelPointer(
    _In_ ULONG_PTR Address
    )
/*++

Routine Description:

    Rejects user addresses, non-canonical x64 values, and unaligned objects.

Return Value:

    TRUE only for an aligned system-range pointer.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address >> 48U) == 0xFFFFU &&
        (Address & (sizeof(PVOID) - 1U)) == 0U;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address & (sizeof(PVOID) - 1U)) == 0U;
#endif
}

static BOOLEAN
KswordArkSpecialInitializeNtosView(
    _Out_ KSW_RUNTIME_IMAGE_VIEW* ViewOut,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace
    )
/*++

Routine Description:

    Builds a bounded PE view from the active ntoskrnl identity already captured
    by the central DynData loader.

Return Value:

    TRUE when the loaded image identity and PE headers are usable.

--*/
{
    KSW_DYN_STATE* state = NULL;

    if (ViewOut == NULL || Workspace == NULL) {
        return FALSE;
    }
    state = &Workspace->DynState;
    RtlZeroMemory(state, sizeof(*state));
    KswordARKDynDataSnapshot(state);
    if (state->Ntoskrnl.present == 0UL ||
        state->Ntoskrnl.imageBase == 0ULL ||
        state->Ntoskrnl.sizeOfImage == 0UL) {
        return FALSE;
    }
    return KswordARKRuntimeInitializeImageView(
        (PVOID)(ULONG_PTR)state->Ntoskrnl.imageBase,
        state->Ntoskrnl.sizeOfImage,
        ViewOut);
}

static BOOLEAN
KswordArkSpecialAddressIsExecutable(
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_ ULONG64 Address
    )
/*++

Routine Description:

    Requires a callback candidate to fall inside an executable PE section of
    one currently loaded kernel module.

Return Value:

    TRUE only when the complete pointer resolves to executable image memory.

--*/
{
    ULONG index = 0UL;

    if (ModuleCache == NULL || ModuleCache->ModuleInfo == NULL ||
        Workspace == NULL || Address == 0ULL) {
        return FALSE;
    }
    for (index = 0UL; index < ModuleCache->ModuleInfo->NumberOfModules; ++index) {
        const KSWORD_ARK_CALLBACK_MODULE_ENTRY* module =
            &ModuleCache->ModuleInfo->Modules[index];
        const ULONG64 moduleBase = (ULONG64)(ULONG_PTR)module->ImageBase;
        KSW_RUNTIME_IMAGE_VIEW* view = &Workspace->ModuleView;

        if (moduleBase == 0ULL || module->ImageSize == 0UL ||
            Address < moduleBase || Address - moduleBase >= module->ImageSize) {
            continue;
        }
        RtlZeroMemory(view, sizeof(*view));
        if (!KswordARKRuntimeInitializeImageView(
                module->ImageBase,
                module->ImageSize,
                view)) {
            return FALSE;
        }
        return KswordARKRuntimeAddressIsExecutable(
            view,
            (ULONG_PTR)Address,
            1U);
    }
    return FALSE;
}

static BOOLEAN
KswordArkSpecialAddUniqueExecutable(
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_ ULONG64 Candidate,
    _Inout_ ULONG64* UniqueAddress,
    _Inout_ ULONG* UniqueCount
    )
/*++

Routine Description:

    Adds one executable candidate to a per-record uniqueness test.

Return Value:

    TRUE when the candidate is absent or does not introduce ambiguity.

--*/
{
    if (UniqueAddress == NULL || UniqueCount == NULL ||
        !KswordArkSpecialAddressIsExecutable(ModuleCache, Workspace, Candidate)) {
        return TRUE;
    }
    if (*UniqueCount == 0UL) {
        *UniqueAddress = Candidate;
        *UniqueCount = 1UL;
        return TRUE;
    }
    if (*UniqueAddress == Candidate) {
        return TRUE;
    }
    *UniqueCount += 1UL;
    return FALSE;
}

static BOOLEAN
KswordArkSpecialFindExecutableAround(
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_ ULONG_PTR CenterAddress,
    _In_ BOOLEAN DecodeShiftedValues,
    _Out_ ULONG64* CallbackAddressOut
    )
/*++

Routine Description:

    Infers a callback member without a build-specific record offset. Pointer-
    aligned fields around the validated registration node are sampled, and the
    record is accepted only when exactly one executable address survives.

Return Value:

    TRUE when one unique executable callback was recovered.

--*/
{
    LONG offset = 0L;
    ULONG uniqueCount = 0UL;
    ULONG64 uniqueAddress = 0ULL;

    if (ModuleCache == NULL || Workspace == NULL || CallbackAddressOut == NULL ||
        !KswordArkSpecialIsKernelPointer(CenterAddress)) {
        return FALSE;
    }
    *CallbackAddressOut = 0ULL;
    for (offset = -(LONG)KSW_SPECIAL_RECORD_BACK_BYTES;
         offset <= (LONG)KSW_SPECIAL_RECORD_FORWARD_BYTES;
         offset += (LONG)sizeof(PVOID)) {
        ULONG_PTR fieldAddress = 0U;
        ULONG_PTR rawValue = 0U;
        ULONG64 decodedValue = 0ULL;

        if (offset < 0) {
            const ULONG_PTR magnitude = (ULONG_PTR)(-(LONGLONG)offset);
            if (CenterAddress < magnitude) {
                continue;
            }
            fieldAddress = CenterAddress - magnitude;
        }
        else {
            if (CenterAddress > MAXULONG_PTR - (ULONG_PTR)offset) {
                continue;
            }
            fieldAddress = CenterAddress + (ULONG_PTR)offset;
        }
        if (!KswordARKRuntimeReadMemory(
                (const VOID*)fieldAddress,
                &rawValue,
                sizeof(rawValue))) {
            continue;
        }
        if (!KswordArkSpecialAddUniqueExecutable(
                ModuleCache,
                Workspace,
                (ULONG64)rawValue,
                &uniqueAddress,
                &uniqueCount)) {
            return FALSE;
        }
#if defined(_M_AMD64) || defined(_M_X64)
        if (DecodeShiftedValues && rawValue != 0U) {
            decodedValue = ((ULONG64)rawValue >> 8U) | 0xFFFF000000000000ULL;
            if (!KswordArkSpecialAddUniqueExecutable(
                    ModuleCache,
                    Workspace,
                    decodedValue,
                    &uniqueAddress,
                    &uniqueCount)) {
                return FALSE;
            }
        }
#else
        UNREFERENCED_PARAMETER(DecodeShiftedValues);
#endif
    }
    if (uniqueCount != 1UL) {
        return FALSE;
    }
    *CallbackAddressOut = uniqueAddress;
    return TRUE;
}

static BOOLEAN
KswordArkSpecialFindExecutableIndirect(
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_ ULONG_PTR NodeAddress,
    _Out_ ULONG64* CallbackAddressOut,
    _Out_ ULONG64* ContextAddressOut
    )
/*++

Routine Description:

    Handles registrations whose list node references a separate owner record.
    Direct record fields are preferred; otherwise each nearby kernel pointer is
    tested as a second bounded record, again requiring one unique callback.

Return Value:

    TRUE when direct or single-indirection structural inference is unique.

--*/
{
    ULONG offset = 0UL;
    ULONG64 callbackAddress = 0ULL;
    ULONG64 uniqueCallback = 0ULL;
    ULONG64 uniqueContext = 0ULL;
    ULONG uniqueCount = 0UL;

    if (Workspace == NULL || CallbackAddressOut == NULL || ContextAddressOut == NULL) {
        return FALSE;
    }
    *CallbackAddressOut = 0ULL;
    *ContextAddressOut = 0ULL;
    if (KswordArkSpecialFindExecutableAround(
            ModuleCache,
            Workspace,
            NodeAddress,
            FALSE,
            &callbackAddress)) {
        *CallbackAddressOut = callbackAddress;
        return TRUE;
    }
    for (offset = 0UL; offset <= KSW_SPECIAL_INDIRECT_SCAN_BYTES;
         offset += (ULONG)sizeof(PVOID)) {
        ULONG_PTR ownerAddress = 0U;

        if (NodeAddress > MAXULONG_PTR - offset ||
            !KswordARKRuntimeReadMemory(
                (const VOID*)(NodeAddress + offset),
                &ownerAddress,
                sizeof(ownerAddress))) {
            continue;
        }
        ownerAddress &= ~((ULONG_PTR)0x0FU);
        if (!KswordArkSpecialIsKernelPointer(ownerAddress) ||
            !KswordArkSpecialFindExecutableAround(
                ModuleCache,
                Workspace,
                ownerAddress,
                FALSE,
                &callbackAddress)) {
            continue;
        }
        if (uniqueCount == 0UL) {
            uniqueCallback = callbackAddress;
            uniqueContext = (ULONG64)ownerAddress;
            uniqueCount = 1UL;
        }
        else if (uniqueCallback != callbackAddress ||
            uniqueContext != (ULONG64)ownerAddress) {
            return FALSE;
        }
    }
    if (uniqueCount != 1UL) {
        return FALSE;
    }
    *CallbackAddressOut = uniqueCallback;
    *ContextAddressOut = uniqueContext;
    return TRUE;
}

static BOOLEAN
KswordArkSpecialReadValidatedListHead(
    _In_ ULONG_PTR HeadAddress,
    _Out_ LIST_ENTRY* HeadOut
    )
/*++

Routine Description:

    Reads a circular list head and validates reciprocal first/last links.

Return Value:

    TRUE for a structurally valid empty or non-empty list.

--*/
{
    LIST_ENTRY head;
    LIST_ENTRY first;
    LIST_ENTRY last;

    if (HeadOut == NULL || !KswordArkSpecialIsKernelPointer(HeadAddress) ||
        !KswordARKRuntimeReadMemory((const VOID*)HeadAddress, &head, sizeof(head))) {
        return FALSE;
    }
    if ((ULONG_PTR)head.Flink == HeadAddress &&
        (ULONG_PTR)head.Blink == HeadAddress) {
        *HeadOut = head;
        return TRUE;
    }
    if (!KswordArkSpecialIsKernelPointer((ULONG_PTR)head.Flink) ||
        !KswordArkSpecialIsKernelPointer((ULONG_PTR)head.Blink) ||
        !KswordARKRuntimeReadMemory(head.Flink, &first, sizeof(first)) ||
        !KswordARKRuntimeReadMemory(head.Blink, &last, sizeof(last)) ||
        (ULONG_PTR)first.Blink != HeadAddress ||
        (ULONG_PTR)last.Flink != HeadAddress) {
        return FALSE;
    }
    *HeadOut = head;
    return TRUE;
}

static BOOLEAN
KswordArkSpecialCaptureDoubleList(
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_ ULONG_PTR HeadAddress,
    _In_ BOOLEAN AllowIndirect,
    _Inout_ KSW_SPECIAL_CAPTURE* Capture
    )
/*++

Routine Description:

    Traverses one validated circular registration list with loop, reciprocal-
    link, record-count, and executable-callback bounds.

Return Value:

    TRUE when the complete observed topology is self-consistent.

--*/
{
    LIST_ENTRY head;
    ULONG_PTR currentAddress = 0U;
    ULONG_PTR previousAddress = HeadAddress;
    ULONG visitCount = 0UL;

    if (Capture == NULL || Workspace == NULL ||
        !KswordArkSpecialReadValidatedListHead(HeadAddress, &head)) {
        return FALSE;
    }
    currentAddress = (ULONG_PTR)head.Flink;
    while (currentAddress != HeadAddress) {
        LIST_ENTRY current;
        ULONG64 callbackAddress = 0ULL;
        ULONG64 contextAddress = 0ULL;

        if (visitCount >= KSW_SPECIAL_MAX_RECORDS ||
            !KswordArkSpecialIsKernelPointer(currentAddress) ||
            !KswordARKRuntimeReadMemory(
                (const VOID*)currentAddress,
                &current,
                sizeof(current)) ||
            (ULONG_PTR)current.Blink != previousAddress) {
            return FALSE;
        }
        if (AllowIndirect) {
            if (!KswordArkSpecialFindExecutableIndirect(
                    ModuleCache,
                    Workspace,
                    currentAddress,
                    &callbackAddress,
                    &contextAddress)) {
                return FALSE;
            }
        }
        else if (!KswordArkSpecialFindExecutableAround(
                ModuleCache,
                Workspace,
                currentAddress,
                FALSE,
                &callbackAddress)) {
            return FALSE;
        }
        Capture->Records[Capture->Count].CallbackAddress = callbackAddress;
        Capture->Records[Capture->Count].ContextAddress = contextAddress;
        Capture->Records[Capture->Count].RegistrationAddress =
            (ULONG64)currentAddress;
        Capture->Count += 1UL;
        visitCount += 1UL;
        previousAddress = currentAddress;
        currentAddress = (ULONG_PTR)current.Flink;
    }
    if (previousAddress != (ULONG_PTR)head.Blink) {
        return FALSE;
    }
    Capture->GlobalAddress = (ULONG64)HeadAddress;
    Capture->Valid = TRUE;
    return TRUE;
}

static BOOLEAN
KswordArkSpecialCaptureSingleList(
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_ ULONG_PTR HeadAddress,
    _Inout_ KSW_SPECIAL_CAPTURE* Capture
    )
/*++

Routine Description:

    Traverses an EMP-style singly linked registration list with cycle and
    executable-owner validation.

Return Value:

    TRUE for a complete bounded list, including an empty list.

--*/
{
    SINGLE_LIST_ENTRY head;
    ULONG_PTR currentAddress = 0U;
    ULONG_PTR* visited = NULL;
    ULONG visitCount = 0UL;

    if (Capture == NULL || Workspace == NULL ||
        !KswordArkSpecialIsKernelPointer(HeadAddress) ||
        !KswordARKRuntimeReadMemory((const VOID*)HeadAddress, &head, sizeof(head))) {
        return FALSE;
    }
    visited = Workspace->Visited;
    RtlZeroMemory(visited, sizeof(Workspace->Visited));
    currentAddress = (ULONG_PTR)head.Next;
    while (currentAddress != 0U) {
        SINGLE_LIST_ENTRY current;
        ULONG index = 0UL;
        ULONG64 callbackAddress = 0ULL;

        if (visitCount >= KSW_SPECIAL_MAX_RECORDS ||
            !KswordArkSpecialIsKernelPointer(currentAddress)) {
            return FALSE;
        }
        for (index = 0UL; index < visitCount; ++index) {
            if (visited[index] == currentAddress) {
                return FALSE;
            }
        }
        if (!KswordARKRuntimeReadMemory(
                (const VOID*)currentAddress,
                &current,
                sizeof(current)) ||
            !KswordArkSpecialFindExecutableAround(
                ModuleCache,
                Workspace,
                currentAddress,
                FALSE,
                &callbackAddress)) {
            return FALSE;
        }
        visited[visitCount] = currentAddress;
        Capture->Records[Capture->Count].CallbackAddress = callbackAddress;
        Capture->Records[Capture->Count].RegistrationAddress =
            (ULONG64)currentAddress;
        Capture->Count += 1UL;
        visitCount += 1UL;
        currentAddress = (ULONG_PTR)current.Next;
    }
    Capture->GlobalAddress = (ULONG64)HeadAddress;
    Capture->Valid = TRUE;
    return TRUE;
}

static BOOLEAN
KswordArkSpecialCapturePriorityArray(
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_ ULONG_PTR ArrayAddress,
    _Inout_ KSW_SPECIAL_CAPTURE* Capture
    )
/*++

Routine Description:

    Validates the fixed public API priority-slot count and decodes the tagged
    record representation by executable-address shape rather than member offset.

Return Value:

    TRUE when every populated slot yields one callback.

--*/
{
    ULONG slot = 0UL;

    if (Capture == NULL || Workspace == NULL ||
        !KswordArkSpecialIsKernelPointer(ArrayAddress)) {
        return FALSE;
    }
    for (slot = 0UL; slot < KSW_SPECIAL_PRIORITY_SLOT_COUNT; ++slot) {
        ULONG_PTR recordAddress = 0U;
        ULONG64 callbackAddress = 0ULL;

        if (!KswordARKRuntimeReadMemory(
                (const VOID*)(ArrayAddress + ((ULONG_PTR)slot * sizeof(PVOID))),
                &recordAddress,
                sizeof(recordAddress))) {
            return FALSE;
        }
        if (recordAddress == 0U) {
            continue;
        }
        if (!KswordArkSpecialIsKernelPointer(recordAddress) ||
            !KswordArkSpecialFindExecutableAround(
                ModuleCache,
                Workspace,
                recordAddress,
                TRUE,
                &callbackAddress)) {
            return FALSE;
        }
        Capture->Records[Capture->Count].CallbackAddress = callbackAddress;
        Capture->Records[Capture->Count].ContextAddress = slot;
        Capture->Records[Capture->Count].RegistrationAddress =
            (ULONG64)recordAddress;
        Capture->Count += 1UL;
    }
    Capture->GlobalAddress = (ULONG64)ArrayAddress;
    Capture->Valid = TRUE;
    return TRUE;
}

static BOOLEAN
KswordArkSpecialCapturePnpLists(
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_ ULONG_PTR ArrayAddress,
    _Inout_ KSW_SPECIAL_CAPTURE* Capture,
    _Inout_ KSW_SPECIAL_CAPTURE* ListScratch
    )
/*++

Routine Description:

    Validates the thirteen Plug-and-Play notification class heads and combines
    their bounded registration rows into one snapshot.

Return Value:

    TRUE only when all list heads are structurally valid.

--*/
{
    ULONG listIndex = 0UL;

    if (Workspace == NULL || Capture == NULL || ListScratch == NULL ||
        Capture == ListScratch || !KswordArkSpecialIsKernelPointer(ArrayAddress)) {
        return FALSE;
    }
    for (listIndex = 0UL; listIndex < KSW_SPECIAL_PNP_LIST_COUNT; ++listIndex) {
        const ULONG_PTR headAddress = ArrayAddress +
            ((ULONG_PTR)listIndex * sizeof(LIST_ENTRY));
        ULONG rowIndex = 0UL;

        // Reuse the pool-backed list scratch for every PnP class; keeping this
        // 3 KiB capture off the stack is required even though lists are serial.
        RtlZeroMemory(ListScratch, sizeof(*ListScratch));
        if (!KswordArkSpecialCaptureDoubleList(
                ModuleCache,
                Workspace,
                headAddress,
                FALSE,
                ListScratch) ||
            Capture->Count > KSW_SPECIAL_MAX_RECORDS - ListScratch->Count) {
            return FALSE;
        }
        for (rowIndex = 0UL; rowIndex < ListScratch->Count; ++rowIndex) {
            Capture->Records[Capture->Count] = ListScratch->Records[rowIndex];
            Capture->Records[Capture->Count].ContextAddress = listIndex;
            Capture->Count += 1UL;
        }
    }
    Capture->GlobalAddress = (ULONG64)ArrayAddress;
    Capture->Valid = TRUE;
    return TRUE;
}

static BOOLEAN
KswordArkSpecialTryCapture(
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_ KSW_SPECIAL_CAPTURE_KIND Kind,
    _In_ ULONG_PTR CandidateAddress,
    _Out_ KSW_SPECIAL_CAPTURE* CaptureOut,
    _Inout_ KSW_SPECIAL_CAPTURE* ListScratch
    )
/*++

Routine Description:

    Dispatches one feature-specific structural validator.

Return Value:

    TRUE when the candidate is a complete registration container.

--*/
{
    if (CaptureOut == NULL || Workspace == NULL) {
        return FALSE;
    }
    RtlZeroMemory(CaptureOut, sizeof(*CaptureOut));
    switch (Kind) {
    case KswSpecialCaptureDoubleList:
        return KswordArkSpecialCaptureDoubleList(
            ModuleCache,
            Workspace,
            CandidateAddress,
            FALSE,
            CaptureOut);
    case KswSpecialCaptureDoubleListIndirect:
        return KswordArkSpecialCaptureDoubleList(
            ModuleCache,
            Workspace,
            CandidateAddress,
            TRUE,
            CaptureOut);
    case KswSpecialCaptureSingleList:
        return KswordArkSpecialCaptureSingleList(
            ModuleCache,
            Workspace,
            CandidateAddress,
            CaptureOut);
    case KswSpecialCapturePriorityArray:
        return KswordArkSpecialCapturePriorityArray(
            ModuleCache,
            Workspace,
            CandidateAddress,
            CaptureOut);
    case KswSpecialCapturePnpLists:
        return KswordArkSpecialCapturePnpLists(
            ModuleCache,
            Workspace,
            CandidateAddress,
            CaptureOut,
            ListScratch);
    default:
        return FALSE;
    }
}

static BOOLEAN
KswordArkSpecialCaptureBetter(
    _In_ const KSW_SPECIAL_CAPTURE* Candidate,
    _In_ const KSW_SPECIAL_CAPTURE* Current
    )
/*++

Routine Description:

    Orders validated candidates by live registration evidence.

Return Value:

    TRUE when Candidate has a strictly stronger record count.

--*/
{
    return Candidate != NULL && Candidate->Valid &&
        (Current == NULL || !Current->Valid || Candidate->Count > Current->Count);
}

static BOOLEAN
KswordArkSpecialFindBestCapture(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* NtosView,
    _In_ const KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_reads_(AnchorCount) PCSTR const* AnchorNames,
    _In_ ULONG AnchorCount,
    _In_ KSW_SPECIAL_CAPTURE_KIND Kind,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _Out_ BOOLEAN* AmbiguousOut
    )
/*++

Routine Description:

    Collects writable data references reachable from stable exports, validates
    both direct globals and pointer globals, and rejects tied best candidates.

Return Value:

    TRUE when one strongest structural candidate exists.

--*/
{
    ULONG referenceCount = 0UL;
    ULONG referenceIndex = 0UL;
    BOOLEAN ambiguous = FALSE;

    if (Workspace == NULL || AmbiguousOut == NULL) {
        return FALSE;
    }
    // Preserve NtosView and DynState while resetting only reusable search data.
    RtlZeroMemory(Workspace->References, sizeof(Workspace->References));
    RtlZeroMemory(&Workspace->Best, sizeof(Workspace->Best));
    RtlZeroMemory(&Workspace->Candidate, sizeof(Workspace->Candidate));
    RtlZeroMemory(&Workspace->ListScratch, sizeof(Workspace->ListScratch));
    RtlZeroMemory(Workspace->Visited, sizeof(Workspace->Visited));
    *AmbiguousOut = FALSE;
    referenceCount = KswordARKRuntimeCollectAnchoredDataReferences(
        NtosView,
        AnchorNames,
        AnchorCount,
        KSW_SPECIAL_MAX_CALL_DEPTH,
        KSW_SPECIAL_ROUTINE_SCAN_BYTES,
        Workspace->References,
        RTL_NUMBER_OF(Workspace->References));
    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        ULONG_PTR candidates[2];
        ULONG candidateIndex = 0UL;

        RtlZeroMemory(candidates, sizeof(candidates));
        candidates[0] = Workspace->References[referenceIndex].Address;
        (VOID)KswordARKRuntimeReadMemory(
            (const VOID*)Workspace->References[referenceIndex].Address,
            &candidates[1],
            sizeof(candidates[1]));
        for (candidateIndex = 0UL; candidateIndex < RTL_NUMBER_OF(candidates);
             ++candidateIndex) {
            KSW_SPECIAL_CAPTURE* candidate = &Workspace->Candidate;

            if (!KswordArkSpecialIsKernelPointer(candidates[candidateIndex]) ||
                (candidateIndex != 0UL && candidates[1] == candidates[0])) {
                continue;
            }
            RtlZeroMemory(candidate, sizeof(*candidate));
            if (!KswordArkSpecialTryCapture(
                    ModuleCache,
                    Workspace,
                    Kind,
                    candidates[candidateIndex],
                    candidate,
                    &Workspace->ListScratch)) {
                continue;
            }
            if (KswordArkSpecialCaptureBetter(candidate, &Workspace->Best)) {
                Workspace->Best = *candidate;
                ambiguous = FALSE;
            }
            else if (Workspace->Best.Valid &&
                candidate->Count == Workspace->Best.Count &&
                candidate->GlobalAddress != Workspace->Best.GlobalAddress) {
                ambiguous = TRUE;
            }
        }
    }
    if (!Workspace->Best.Valid || ambiguous) {
        *AmbiguousOut = ambiguous;
        return FALSE;
    }
    return TRUE;
}

static VOID
KswordArkSpecialPublishCapture(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ const KSW_SPECIAL_CAPTURE* Capture,
    _In_ ULONG CallbackClass,
    _In_ ULONG RegistrationType,
    _In_z_ PCWSTR NameText
    )
/*++

Routine Description:

    Publishes validated callback rows without enabling removal semantics.

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    if (Capture == NULL || !Capture->Valid) {
        return;
    }
    if (Capture->Count == 0UL) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            NULL,
            CallbackClass,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_SPECIAL_CALLBACK,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED,
            STATUS_SUCCESS,
            RegistrationType,
            0UL,
            0UL,
            0ULL,
            Capture->GlobalAddress,
            Capture->GlobalAddress,
            0UL,
            NameText,
            L"已唯一定位并验证注册容器；当前快照为空。");
        return;
    }
    for (index = 0UL; index < Capture->Count; ++index) {
        const KSW_SPECIAL_RECORD* record = &Capture->Records[index];

        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            CallbackClass,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_SPECIAL_CALLBACK,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
            STATUS_SUCCESS,
            RegistrationType,
            0UL,
            0UL,
            record->CallbackAddress,
            record->ContextAddress,
            record->RegistrationAddress,
            KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE,
            NameText,
            L"稳定导出锚点、有界数据引用、实时拓扑和可执行模块归属均已验证；只读展示。");
    }
}

static VOID
KswordArkSpecialEnumerateOne(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ const KSW_RUNTIME_IMAGE_VIEW* NtosView,
    _Inout_ KSW_SPECIAL_WORKSPACE* Workspace,
    _In_reads_(AnchorCount) PCSTR const* AnchorNames,
    _In_ ULONG AnchorCount,
    _In_ KSW_SPECIAL_CAPTURE_KIND Kind,
    _In_ ULONG CallbackClass,
    _In_ ULONG RegistrationType,
    _In_z_ PCWSTR NameText
    )
/*++

Routine Description:

    Resolves and publishes one special callback family with an explicit
    unsupported row when validation cannot establish a unique container.

Return Value:

    None.

--*/
{
    BOOLEAN ambiguous = FALSE;

    if (!KswordArkSpecialFindBestCapture(
            NtosView,
            ModuleCache,
            AnchorNames,
            AnchorCount,
            Kind,
            Workspace,
            &ambiguous)) {
        KswordArkCallbackEnumAddUnsupportedRow(
            Builder,
            CallbackClass,
            NameText,
            ambiguous
                ? L"锚点产生多个同强度候选，已按 fail-closed 策略拒绝猜测。"
                : L"未从稳定导出锚点恢复出唯一且结构完整的注册容器。");
        return;
    }
    KswordArkSpecialPublishCapture(
        Builder,
        ModuleCache,
        &Workspace->Best,
        CallbackClass,
        RegistrationType,
        NameText);
}

VOID
KswordArkCallbackExtendedAddSpecialCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    Adds the six callback families missing from the original KSword inventory.

Return Value:

    None. Every family contributes validated rows or one explicit diagnostic.

--*/
{
    static PCSTR const powerAnchors[] = {
        "PoRegisterPowerSettingCallback",
        "PoUnregisterPowerSettingCallback"
    };
    static PCSTR const coalescingAnchors[] = {
        "PoRegisterCoalescingCallback",
        "PoUnregisterCoalescingCallback"
    };
    static PCSTR const priorityAnchors[] = {
        "IoRegisterPriorityCallback"
    };
    static PCSTR const debugPrintAnchors[] = {
        "DbgSetDebugPrintCallback"
    };
    static PCSTR const empAnchors[] = {
        "EmpProviderRegister",
        "EmpProviderDeregister"
    };
    static PCSTR const plugPlayAnchors[] = {
        "IoRegisterPlugPlayNotification",
        "IoUnregisterPlugPlayNotification"
    };
    KSWORD_ARK_CALLBACK_MODULE_CACHE moduleCache;
    KSW_SPECIAL_WORKSPACE* workspace = NULL;
    NTSTATUS moduleStatus = STATUS_SUCCESS;

    if (Builder == NULL) {
        return;
    }
    KswordArkCallbackEnumInitModuleCache(&moduleCache);
    moduleStatus = KswordArkCallbackEnumEnsureModuleCache(&moduleCache);
    // One bounded nonpaged block is reused serially by all family searches;
    // no callback data escapes after it is published into the response builder.
    workspace = (KSW_SPECIAL_WORKSPACE*)KswordARKAllocateNonPagedPool(
        sizeof(*workspace),
        KSW_SPECIAL_WORKSPACE_POOL_TAG);
    if (workspace != NULL) {
        RtlZeroMemory(workspace, sizeof(*workspace));
    }
    if (!NT_SUCCESS(moduleStatus) ||
        workspace == NULL ||
        !KswordArkSpecialInitializeNtosView(&workspace->NtosView, workspace)) {
        const ULONG classes[] = {
            KSWORD_ARK_CALLBACK_ENUM_CLASS_POWER_SETTING,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_COALESCING,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_PRIORITY,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_DEBUG_PRINT,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_EMP,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_PLUG_PLAY
        };
        static PCWSTR const names[] = {
            L"Power Setting Callback",
            L"Coalescing Callback",
            L"Priority Callback",
            L"Debug Print Callback",
            L"EMP Callback",
            L"Plug and Play Notification"
        };
        ULONG index = 0UL;

        for (index = 0UL; index < RTL_NUMBER_OF(classes); ++index) {
            KswordArkCallbackEnumAddUnsupportedRow(
                Builder,
                classes[index],
                names[index],
                L"ntoskrnl 映像视图或已加载模块快照不可用。");
        }
        if (workspace != NULL) {
            ExFreePoolWithTag(workspace, KSW_SPECIAL_WORKSPACE_POOL_TAG);
            workspace = NULL;
        }
        KswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return;
    }

    KswordArkSpecialEnumerateOne(
        Builder,
        &moduleCache,
        &workspace->NtosView,
        workspace,
        powerAnchors,
        RTL_NUMBER_OF(powerAnchors),
        KswSpecialCaptureDoubleList,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_POWER_SETTING,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_POWER_SETTING,
        L"Power Setting Callback");
    KswordArkSpecialEnumerateOne(
        Builder,
        &moduleCache,
        &workspace->NtosView,
        workspace,
        coalescingAnchors,
        RTL_NUMBER_OF(coalescingAnchors),
        KswSpecialCaptureDoubleListIndirect,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_COALESCING,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_COALESCING,
        L"Coalescing Callback");
    KswordArkSpecialEnumerateOne(
        Builder,
        &moduleCache,
        &workspace->NtosView,
        workspace,
        priorityAnchors,
        RTL_NUMBER_OF(priorityAnchors),
        KswSpecialCapturePriorityArray,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_PRIORITY,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PRIORITY,
        L"Priority Callback");
    KswordArkSpecialEnumerateOne(
        Builder,
        &moduleCache,
        &workspace->NtosView,
        workspace,
        debugPrintAnchors,
        RTL_NUMBER_OF(debugPrintAnchors),
        KswSpecialCaptureDoubleList,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_DEBUG_PRINT,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DEBUG_PRINT,
        L"Debug Print Callback");
    KswordArkSpecialEnumerateOne(
        Builder,
        &moduleCache,
        &workspace->NtosView,
        workspace,
        empAnchors,
        RTL_NUMBER_OF(empAnchors),
        KswSpecialCaptureSingleList,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_EMP,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_EMP,
        L"EMP Callback");
    KswordArkSpecialEnumerateOne(
        Builder,
        &moduleCache,
        &workspace->NtosView,
        workspace,
        plugPlayAnchors,
        RTL_NUMBER_OF(plugPlayAnchors),
        KswSpecialCapturePnpLists,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_PLUG_PLAY,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PLUG_PLAY,
        L"Plug and Play Notification");
    ExFreePoolWithTag(workspace, KSW_SPECIAL_WORKSPACE_POOL_TAG);
    workspace = NULL;
    KswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
