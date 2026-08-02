/*++

Module Name:

    ci_hash_fallback.c

Abstract:

    Runtime-signature fallback for the CI kernel hash cache.  Stable exported
    CI entry points seed a bounded direct-call scan.  Candidate list globals,
    entry layouts, and ERESOURCE objects are accepted only after unique live
    chain/name validation and a non-blocking locked revalidation.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query path.

--*/

#include "ci_hash_fallback.h"
#include "hook_scan_support.h"
#include "../../platform/runtime_signature_scan.h"
#include "../../platform/pool_compat.h"

#define KSW_CI_HASH_FALLBACK_TAG 'hCsK'
#define KSW_CI_HASH_MAX_REFERENCES 768UL
#define KSW_CI_HASH_ROUTINE_SCAN_BYTES 0x0800UL
#define KSW_CI_HASH_FULL_SCAN_BUDGET 0x00400000UL
#define KSW_CI_HASH_MAX_ENTRY_BYTES 0x0100UL
#define KSW_CI_HASH_MAX_CHAIN 64UL
#define KSW_CI_HASH_MAX_SAMPLES 16UL
#define KSW_CI_HASH_MAX_NAME_BYTES 520U

typedef struct _KSW_CI_HASH_CANDIDATE
{
    ULONG_PTR ListGlobal;
    ULONG_PTR ReferenceRoutine;
    ULONG_PTR ReferenceInstruction;
    ULONG NextOffset;
    ULONG NameOffset;
    ULONG ChainLength;
    PVOID Samples[KSW_CI_HASH_MAX_SAMPLES];
    ULONG SampleCount;
} KSW_CI_HASH_CANDIDATE, *PKSW_CI_HASH_CANDIDATE;

static BOOLEAN
KswordARKCiHashIsKernelAddress(
    _In_ ULONG_PTR Address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG_PTR)MmSystemRangeStart &&
        (Address >> 48U) == 0xFFFFU;
#else
    return Address >= (ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
KswordARKCiHashNameIsDriver(
    _In_ const UCHAR* Entry,
    _In_ ULONG Offset
    )
{
    UNICODE_STRING name;
    UNICODE_STRING expected;
    UNICODE_STRING tailString;
    WCHAR tail[5];
    SIZE_T suffixBytes = 0U;
    BOOLEAN matched = FALSE;

    if (Entry == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&name, sizeof(name));
    RtlZeroMemory(tail, sizeof(tail));
    if (!KswordARKRuntimeReadMemory(
            Entry + Offset,
            &name,
            sizeof(name)) ||
        name.Buffer == NULL ||
        !KswordARKCiHashIsKernelAddress((ULONG_PTR)name.Buffer) ||
        name.Length == 0U || name.Length > KSW_CI_HASH_MAX_NAME_BYTES ||
        name.Length > name.MaximumLength ||
        (name.Length & (sizeof(WCHAR) - 1U)) != 0U) {
        return FALSE;
    }

    RtlInitUnicodeString(&expected, L".sys");
    suffixBytes = expected.Length;
    if (name.Length >= suffixBytes &&
        KswordARKRuntimeReadMemory(
            (const UCHAR*)name.Buffer + name.Length - suffixBytes,
            tail,
            suffixBytes)) {
        tailString.Buffer = tail;
        tailString.Length = (USHORT)suffixBytes;
        tailString.MaximumLength = (USHORT)suffixBytes;
        matched = RtlEqualUnicodeString(&tailString, &expected, TRUE);
    }
    if (matched) {
        return TRUE;
    }

    RtlZeroMemory(tail, sizeof(tail));
    RtlInitUnicodeString(&expected, L".dll");
    suffixBytes = expected.Length;
    if (name.Length < suffixBytes ||
        !KswordARKRuntimeReadMemory(
            (const UCHAR*)name.Buffer + name.Length - suffixBytes,
            tail,
            suffixBytes)) {
        return FALSE;
    }
    tailString.Buffer = tail;
    tailString.Length = (USHORT)suffixBytes;
    tailString.MaximumLength = (USHORT)suffixBytes;
    return RtlEqualUnicodeString(&tailString, &expected, TRUE);
}

static BOOLEAN
KswordARKCiHashWalkCandidate(
    _In_ ULONG_PTR ListGlobal,
    _In_ ULONG NextOffset,
    _In_ ULONG NameOffset,
    _Out_opt_ KSW_CI_HASH_CANDIDATE* CandidateOut
    )
{
    ULONG_PTR current = 0U;
    ULONG_PTR seen[KSW_CI_HASH_MAX_CHAIN];
    ULONG count = 0UL;
    KSW_CI_HASH_CANDIDATE candidate;

    RtlZeroMemory(seen, sizeof(seen));
    RtlZeroMemory(&candidate, sizeof(candidate));
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)ListGlobal,
            &current,
            sizeof(current)) ||
        !KswordARKCiHashIsKernelAddress(current)) {
        return FALSE;
    }
    while (current != 0U && count < KSW_CI_HASH_MAX_CHAIN) {
        ULONG_PTR next = 0U;
        ULONG seenIndex = 0UL;

        for (seenIndex = 0UL; seenIndex < count; ++seenIndex) {
            if (seen[seenIndex] == current) {
                return FALSE;
            }
        }
        if (!KswordARKCiHashNameIsDriver(
                (const UCHAR*)current,
                NameOffset) ||
            !KswordARKRuntimeReadMemory(
                (const UCHAR*)current + NextOffset,
                &next,
                sizeof(next)) ||
            (next != 0U && !KswordARKCiHashIsKernelAddress(next))) {
            return FALSE;
        }
        seen[count] = current;
        if (count < KSW_CI_HASH_MAX_SAMPLES) {
            candidate.Samples[count] = (PVOID)current;
            candidate.SampleCount += 1UL;
        }
        count += 1UL;
        current = next;
    }
    if (count < 2UL || current != 0U) {
        return FALSE;
    }
    candidate.ListGlobal = ListGlobal;
    candidate.NextOffset = NextOffset;
    candidate.NameOffset = NameOffset;
    candidate.ChainLength = count;
    if (CandidateOut != NULL) {
        *CandidateOut = candidate;
    }
    return TRUE;
}

static BOOLEAN
KswordARKCiHashInferListCandidate(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ const KSW_RUNTIME_DATA_REFERENCE* Reference,
    _Out_ KSW_CI_HASH_CANDIDATE* CandidateOut
    )
{
    KSW_CI_HASH_CANDIDATE best;
    ULONG bestLength = 0UL;
    BOOLEAN ambiguous = FALSE;
    ULONG nextOffset = 0UL;

    if (View == NULL || Reference == NULL || CandidateOut == NULL ||
        !KswordARKRuntimeAddressIsWritableData(
            View,
            Reference->Address,
            sizeof(PVOID))) {
        return FALSE;
    }
    RtlZeroMemory(&best, sizeof(best));
    for (nextOffset = 0UL;
         nextOffset + sizeof(PVOID) <= KSW_CI_HASH_MAX_ENTRY_BYTES;
         nextOffset += sizeof(PVOID)) {
        ULONG nameOffset = 0UL;

        for (nameOffset = 0UL;
             nameOffset + sizeof(UNICODE_STRING) <= KSW_CI_HASH_MAX_ENTRY_BYTES;
             nameOffset += sizeof(PVOID)) {
            KSW_CI_HASH_CANDIDATE candidate;

            if (nameOffset == nextOffset) {
                continue;
            }
            RtlZeroMemory(&candidate, sizeof(candidate));
            if (!KswordARKCiHashWalkCandidate(
                    Reference->Address,
                    nextOffset,
                    nameOffset,
                    &candidate) ||
                candidate.ChainLength < bestLength) {
                continue;
            }
            if (candidate.ChainLength == bestLength && bestLength != 0UL) {
                ambiguous = TRUE;
                continue;
            }
            best = candidate;
            bestLength = candidate.ChainLength;
            ambiguous = FALSE;
        }
    }
    if (bestLength < 2UL || ambiguous) {
        return FALSE;
    }
    best.ReferenceRoutine = Reference->RoutineAddress;
    best.ReferenceInstruction = Reference->InstructionAddress;
    *CandidateOut = best;
    return TRUE;
}

static BOOLEAN
KswordARKCiHashResourceIsPlausible(
    _In_ const KSW_RUNTIME_IMAGE_VIEW* View,
    _In_ ULONG_PTR Address
    )
{
    ERESOURCE resource;
    LIST_ENTRY forward;
    LIST_ENTRY backward;

    RtlZeroMemory(&resource, sizeof(resource));
    RtlZeroMemory(&forward, sizeof(forward));
    RtlZeroMemory(&backward, sizeof(backward));
    if ((Address & (sizeof(PVOID) - 1U)) != 0U ||
        !KswordARKRuntimeAddressIsWritableData(View, Address, sizeof(resource)) ||
        !KswordARKRuntimeReadMemory((const VOID*)Address, &resource, sizeof(resource)) ||
        resource.SystemResourcesList.Flink == NULL ||
        resource.SystemResourcesList.Blink == NULL ||
        resource.NumberOfSharedWaiters > 0x10000UL ||
        resource.NumberOfExclusiveWaiters > 0x10000UL ||
        (resource.OwnerTable != NULL &&
         !KswordARKCiHashIsKernelAddress((ULONG_PTR)resource.OwnerTable)) ||
        !KswordARKRuntimeReadMemory(
            resource.SystemResourcesList.Flink,
            &forward,
            sizeof(forward)) ||
        !KswordARKRuntimeReadMemory(
            resource.SystemResourcesList.Blink,
            &backward,
            sizeof(backward)) ||
        forward.Blink != (PLIST_ENTRY)Address ||
        backward.Flink != (PLIST_ENTRY)Address) {
        return FALSE;
    }
    return TRUE;
}

static ULONG
KswordARKCiHashPairScore(
    _In_ const KSW_CI_HASH_CANDIDATE* ListCandidate,
    _In_ const KSW_RUNTIME_DATA_REFERENCE* LockReference
    )
{
    ULONG_PTR distance = ListCandidate->ReferenceInstruction >
            LockReference->InstructionAddress
        ? ListCandidate->ReferenceInstruction - LockReference->InstructionAddress
        : LockReference->InstructionAddress - ListCandidate->ReferenceInstruction;
    ULONG score = 0UL;

    if (ListCandidate->ReferenceRoutine == LockReference->RoutineAddress) {
        score += 8UL;
    }
    if (distance <= 0x100UL) {
        score += 4UL;
    }
    else if (distance <= 0x800UL) {
        score += 2UL;
    }
    else if (distance <= 0x2000UL) {
        score += 1UL;
    }
    return score;
}

static BOOLEAN
KswordARKCiHashFindModule(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* Modules,
    _Out_ const KSW_HOOK_SYSTEM_MODULE_ENTRY** ModuleOut
    )
{
    ULONG index = 0UL;

    if (Modules == NULL || ModuleOut == NULL) {
        return FALSE;
    }
    *ModuleOut = NULL;
    for (index = 0UL; index < Modules->NumberOfModules; ++index) {
        const UCHAR* fileName = NULL;
        ULONG fileNameBytes = 0UL;

        KswordARKHookGetModuleFileName(
            &Modules->Modules[index],
            &fileName,
            &fileNameBytes);
        if (KswordARKHookBoundedAnsiEqualsInsensitive(
                fileName,
                fileNameBytes,
                "ci.dll") ||
            KswordARKHookBoundedAnsiEqualsInsensitive(
                fileName,
                fileNameBytes,
                "ci.sys")) {
            *ModuleOut = &Modules->Modules[index];
            return TRUE;
        }
    }
    return FALSE;
}

static VOID
KswordARKCiHashInferOptionalFields(
    _In_ const KSW_CI_HASH_CANDIDATE* Candidate,
    _Inout_ KSW_DYN_V4_CI_KERNEL_HASH_LAYOUT* Layout
    )
{
    ULONG pairOffset = 0UL;
    ULONG bestPairMatches = 0UL;
    LONG bestPairOffset = -1;
    BOOLEAN pairTied = FALSE;
    ULONG imageOffset = 0UL;
    ULONG bestImageMatches = 0UL;
    LONG bestImageOffset = -1;
    BOOLEAN imageTied = FALSE;

    for (pairOffset = 0UL;
         pairOffset + (2UL * sizeof(ULONG)) <= KSW_CI_HASH_MAX_ENTRY_BYTES;
         pairOffset += sizeof(ULONG)) {
        ULONG sampleIndex = 0UL;
        ULONG matches = 0UL;

        if (pairOffset == Candidate->NextOffset ||
            pairOffset == Candidate->NameOffset) {
            continue;
        }
        for (sampleIndex = 0UL;
             sampleIndex < Candidate->SampleCount;
             ++sampleIndex) {
            ULONG timestamp = 0UL;
            NTSTATUS loadStatus = STATUS_SUCCESS;

            if (KswordARKRuntimeReadMemory(
                    (const UCHAR*)Candidate->Samples[sampleIndex] + pairOffset,
                    &timestamp,
                    sizeof(timestamp)) &&
                KswordARKRuntimeReadMemory(
                    (const UCHAR*)Candidate->Samples[sampleIndex] + pairOffset +
                        sizeof(ULONG),
                    &loadStatus,
                    sizeof(loadStatus)) &&
                timestamp >= 0x20000000UL &&
                (loadStatus == STATUS_SUCCESS ||
                 (((ULONG)loadStatus & 0xC0000000UL) == 0xC0000000UL) ||
                 (((ULONG)loadStatus & 0xC0000000UL) == 0x80000000UL))) {
                matches += 1UL;
            }
        }
        if (matches < 2UL || matches < bestPairMatches) {
            continue;
        }
        if (matches == bestPairMatches && bestPairMatches != 0UL) {
            pairTied = TRUE;
            continue;
        }
        bestPairMatches = matches;
        bestPairOffset = (LONG)pairOffset;
        pairTied = FALSE;
    }
    if (bestPairOffset >= 0 && !pairTied) {
        Layout->EntryTimeDateStamp = (ULONG)bestPairOffset;
        Layout->EntryLoadStatus = (ULONG)bestPairOffset + sizeof(ULONG);
    }

    for (imageOffset = 0UL;
         imageOffset + sizeof(PVOID) + sizeof(ULONG) <=
             KSW_CI_HASH_MAX_ENTRY_BYTES;
         imageOffset += sizeof(PVOID)) {
        ULONG sampleIndex = 0UL;
        ULONG matches = 0UL;

        for (sampleIndex = 0UL;
             sampleIndex < Candidate->SampleCount;
             ++sampleIndex) {
            ULONG_PTR imageBase = 0U;
            ULONG imageSize = 0UL;

            if (KswordARKRuntimeReadMemory(
                    (const UCHAR*)Candidate->Samples[sampleIndex] + imageOffset,
                    &imageBase,
                    sizeof(imageBase)) &&
                KswordARKRuntimeReadMemory(
                    (const UCHAR*)Candidate->Samples[sampleIndex] + imageOffset +
                        sizeof(PVOID),
                    &imageSize,
                    sizeof(imageSize)) &&
                KswordARKCiHashIsKernelAddress(imageBase) &&
                imageSize >= PAGE_SIZE && imageSize <= 0x40000000UL) {
                matches += 1UL;
            }
        }
        if (matches < 2UL || matches < bestImageMatches) {
            continue;
        }
        if (matches == bestImageMatches && bestImageMatches != 0UL) {
            imageTied = TRUE;
            continue;
        }
        bestImageMatches = matches;
        bestImageOffset = (LONG)imageOffset;
        imageTied = FALSE;
    }
    if (bestImageOffset >= 0 && !imageTied) {
        Layout->EntryImageBase = (ULONG)bestImageOffset;
        Layout->EntryImageSize = (ULONG)bestImageOffset + sizeof(PVOID);
    }
}

NTSTATUS
KswordARKCiHashResolveRuntimeLayout(
    _Out_ KSW_DYN_V4_CI_KERNEL_HASH_LAYOUT* LayoutOut
    )
{
    static PCSTR const anchors[] = {
        "CiInitialize",
        "CiValidateFileObject",
        "CiCheckSignedFile",
        "CiVerifyHashInCatalog"
    };
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* modules = NULL;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* ciModule = NULL;
    ULONG moduleBytes = 0UL;
    KSW_RUNTIME_IMAGE_VIEW view;
    KSW_RUNTIME_DATA_REFERENCE* references = NULL;
    ULONG referenceCount = 0UL;
    KSW_CI_HASH_CANDIDATE bestList;
    const KSW_RUNTIME_DATA_REFERENCE* bestLock = NULL;
    ULONG bestChainLength = 0UL;
    ULONG bestPairScore = 0UL;
    BOOLEAN listAmbiguous = FALSE;
    BOOLEAN pairAmbiguous = FALSE;
    ULONG referenceIndex = 0UL;
    BOOLEAN lockAcquired = FALSE;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (LayoutOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(LayoutOut, sizeof(*LayoutOut));
    LayoutOut->EntryTimeDateStamp = KSW_DYN_OFFSET_UNAVAILABLE;
    LayoutOut->EntryLoadStatus = KSW_DYN_OFFSET_UNAVAILABLE;
    LayoutOut->EntryImageBase = KSW_DYN_OFFSET_UNAVAILABLE;
    LayoutOut->EntryImageSize = KSW_DYN_OFFSET_UNAVAILABLE;
    RtlZeroMemory(&view, sizeof(view));
    RtlZeroMemory(&bestList, sizeof(bestList));
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    status = KswordARKHookBuildModuleSnapshot(&modules, &moduleBytes);
    if (!NT_SUCCESS(status) || !KswordARKCiHashFindModule(modules, &ciModule) ||
        !KswordARKRuntimeInitializeImageView(
            ciModule->ImageBase,
            ciModule->ImageSize,
            &view)) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    references = (KSW_RUNTIME_DATA_REFERENCE*)KswordARKAllocateNonPagedPool(
        KSW_CI_HASH_MAX_REFERENCES * sizeof(*references),
        KSW_CI_HASH_FALLBACK_TAG);
    if (references == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    referenceCount = KswordARKRuntimeCollectAnchoredDataReferences(
        &view,
        anchors,
        RTL_NUMBER_OF(anchors),
        4UL,
        KSW_CI_HASH_ROUTINE_SCAN_BYTES,
        references,
        KSW_CI_HASH_MAX_REFERENCES);
    if (referenceCount == 0UL) {
        referenceCount = KswordARKRuntimeCollectExecutableDataReferences(
            &view,
            min(view.Size, KSW_CI_HASH_FULL_SCAN_BUDGET),
            references,
            KSW_CI_HASH_MAX_REFERENCES);
    }

    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        KSW_CI_HASH_CANDIDATE candidate;

        RtlZeroMemory(&candidate, sizeof(candidate));
        if (!KswordARKCiHashInferListCandidate(
                &view,
                &references[referenceIndex],
                &candidate) ||
            candidate.ChainLength < bestChainLength) {
            continue;
        }
        if (candidate.ChainLength == bestChainLength &&
            bestChainLength != 0UL &&
            (candidate.ListGlobal != bestList.ListGlobal ||
             candidate.NextOffset != bestList.NextOffset ||
             candidate.NameOffset != bestList.NameOffset)) {
            listAmbiguous = TRUE;
            continue;
        }
        bestList = candidate;
        bestChainLength = candidate.ChainLength;
        listAmbiguous = FALSE;
    }
    if (bestChainLength < 2UL || listAmbiguous) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        ULONG pairScore = 0UL;

        if (references[referenceIndex].Address == bestList.ListGlobal ||
            !KswordARKCiHashResourceIsPlausible(
                &view,
                references[referenceIndex].Address)) {
            continue;
        }
        pairScore = KswordARKCiHashPairScore(
            &bestList,
            &references[referenceIndex]);
        if (pairScore == 0UL || pairScore < bestPairScore) {
            continue;
        }
        if (pairScore == bestPairScore && bestPairScore != 0UL &&
            bestLock != NULL &&
            bestLock->Address != references[referenceIndex].Address) {
            pairAmbiguous = TRUE;
            continue;
        }
        bestLock = &references[referenceIndex];
        bestPairScore = pairScore;
        pairAmbiguous = FALSE;
    }
    if (bestLock == NULL || bestPairScore < 2UL || pairAmbiguous) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    KeEnterCriticalRegion();
    lockAcquired = ExAcquireResourceSharedLite(
        (PERESOURCE)bestLock->Address,
        FALSE);
    if (lockAcquired) {
        KSW_CI_HASH_CANDIDATE lockedCandidate;

        RtlZeroMemory(&lockedCandidate, sizeof(lockedCandidate));
        if (KswordARKCiHashWalkCandidate(
                bestList.ListGlobal,
                bestList.NextOffset,
                bestList.NameOffset,
                &lockedCandidate) &&
            lockedCandidate.ChainLength == bestList.ChainLength &&
            bestList.ListGlobal >= view.Base &&
            bestLock->Address >= view.Base &&
            bestList.ListGlobal - view.Base <= MAXULONG &&
            bestLock->Address - view.Base <= MAXULONG) {
            LayoutOut->ModuleBase = view.Base;
            LayoutOut->ModuleSize = view.Size;
            LayoutOut->KernelHashBucketListRva =
                (ULONG)(bestList.ListGlobal - view.Base);
            LayoutOut->HashCacheLockRva =
                (ULONG)(bestLock->Address - view.Base);
            LayoutOut->EntryNext = bestList.NextOffset;
            LayoutOut->EntryDriverName = bestList.NameOffset;
            KswordARKCiHashInferOptionalFields(&lockedCandidate, LayoutOut);
            LayoutOut->EntryTypeSize = max(
                LayoutOut->EntryNext + (ULONG)sizeof(PVOID),
                LayoutOut->EntryDriverName + (ULONG)sizeof(UNICODE_STRING));
            if (LayoutOut->EntryTimeDateStamp != KSW_DYN_OFFSET_UNAVAILABLE) {
                LayoutOut->EntryTypeSize = max(
                    LayoutOut->EntryTypeSize,
                    LayoutOut->EntryLoadStatus + (ULONG)sizeof(NTSTATUS));
            }
            if (LayoutOut->EntryImageBase != KSW_DYN_OFFSET_UNAVAILABLE) {
                LayoutOut->EntryTypeSize = max(
                    LayoutOut->EntryTypeSize,
                    LayoutOut->EntryImageSize + (ULONG)sizeof(ULONG));
            }
            LayoutOut->EntryTypeSize =
                (LayoutOut->EntryTypeSize + (sizeof(PVOID) - 1UL)) &
                ~(sizeof(PVOID) - 1UL);
            status = STATUS_SUCCESS;
        }
        ExReleaseResourceLite((PERESOURCE)bestLock->Address);
    }
    KeLeaveCriticalRegion();

Exit:
    if (references != NULL) {
        ExFreePoolWithTag(references, KSW_CI_HASH_FALLBACK_TAG);
    }
    if (modules != NULL) {
        ExFreePoolWithTag(modules, KSW_HOOK_SCAN_TAG);
    }
    UNREFERENCED_PARAMETER(moduleBytes);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(LayoutOut, sizeof(*LayoutOut));
    }
    return status;
}
