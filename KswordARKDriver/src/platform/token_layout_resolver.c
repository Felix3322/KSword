/*++

Module Name:

    token_layout_resolver.c

Abstract:

    Live-validated EPROCESS.Token and TOKEN layout recovery used when an exact
    PDB profile is unavailable.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "token_layout_resolver.h"

#define KSW_RUNTIME_PROCESS_SCAN_BYTES 0x1000U
#define KSW_RUNTIME_TOKEN_SCAN_BYTES 0x0400U
#define KSW_RUNTIME_TOKEN_FIELD_WINDOW 0x0080U
#define KSW_RUNTIME_TOKEN_MAX_GROUPS 0x0100U

static BOOLEAN
KswordARKDriverReadPointerGuarded(
    _In_ const VOID* Address,
    _Out_ ULONG_PTR* ValueOut
    )
{
    if (Address == NULL || ValueOut == NULL) {
        return FALSE;
    }
    *ValueOut = 0U;
    __try {
        *ValueOut = *(volatile const ULONG_PTR*)Address;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}
static BOOLEAN
KswordARKDriverEqualSidGuarded(
    _In_ PSID Left,
    _In_ PSID Right
    )
/*++

Routine Description:

    Compare two SID pointers obtained from private token memory under an exception boundary.

Arguments:

    Left - First candidate SID.
    Right - Second trusted or candidate SID.

Return Value:

    TRUE only when both SIDs are valid and equal.

--*/
{
    BOOLEAN equal = FALSE;

    if (Left == NULL || Right == NULL) {
        return FALSE;
    }
    __try {
        equal = (RtlValidSid(Left) && RtlValidSid(Right) && RtlEqualSid(Left, Right))
            ? TRUE
            : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        equal = FALSE;
    }
    return equal;
}

static BOOLEAN
KswordARKDriverReadSidAndAttributesGuarded(
    _In_ const SID_AND_ATTRIBUTES* Source,
    _Out_ SID_AND_ATTRIBUTES* ValueOut
    )
/*++

Routine Description:

    Copy one private token group entry while containing faults raised by a
    stale or malformed candidate array.  Callers must not dereference a
    candidate SID_AND_ATTRIBUTES entry before it has passed this boundary.

Arguments:

    Source - Candidate entry inside the token's private group array.
    ValueOut - Receives a stable local copy.

Return Value:

    TRUE when the entry was readable; otherwise FALSE.

--*/
{
    if (Source == NULL || ValueOut == NULL) {
        return FALSE;
    }

    __try {
        *ValueOut = *Source;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(ValueOut, sizeof(*ValueOut));
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKDriverTokenGroupArrayMatches(
    _In_reads_(ExpectedCount) const SID_AND_ATTRIBUTES* Candidate,
    _In_ ULONG ExpectedCount,
    _In_ const TOKEN_USER* TokenUser,
    _In_ const TOKEN_GROUPS* TokenGroups
    )
/*++

Routine Description:

    Match a private TOKEN.UserAndGroups array against documented token-query output.

Arguments:

    Candidate - Candidate internal SID_AND_ATTRIBUTES array.
    ExpectedCount - Expected user-plus-groups element count.
    TokenUser - Documented TokenUser query output.
    TokenGroups - Documented TokenGroups query output.

Return Value:

    TRUE when the user and every group SID match in order.

--*/
{
    ULONG index = 0UL;
    SID_AND_ATTRIBUTES candidateEntry;

    if (Candidate == NULL || TokenUser == NULL || TokenGroups == NULL ||
        ExpectedCount == 0UL || ExpectedCount != TokenGroups->GroupCount + 1UL) {
        return FALSE;
    }
    RtlZeroMemory(&candidateEntry, sizeof(candidateEntry));
    if (!KswordARKDriverReadSidAndAttributesGuarded(&Candidate[0], &candidateEntry) ||
        !KswordARKDriverEqualSidGuarded(candidateEntry.Sid, TokenUser->User.Sid)) {
        return FALSE;
    }

    for (index = 0UL; index < TokenGroups->GroupCount; ++index) {
        RtlZeroMemory(&candidateEntry, sizeof(candidateEntry));
        if (!KswordARKDriverReadSidAndAttributesGuarded(
                &Candidate[index + 1UL],
                &candidateEntry) ||
            !KswordARKDriverEqualSidGuarded(
                candidateEntry.Sid,
                TokenGroups->Groups[index].Sid)) {
            return FALSE;
        }
    }
    return TRUE;
}

LONG
KswordARKDriverResolveProcessTokenOffset(
    _In_ PEPROCESS Process,
    _In_ PACCESS_TOKEN Token
    )
/*++

Routine Description:

    Locate the unique EPROCESS EX_FAST_REF whose decoded pointer equals the
    documented primary-token reference returned for the same live process.

Arguments:

    Process - Live process object being scanned.
    Token - Referenced primary token for Process.

Return Value:

    Non-negative EPROCESS.Token offset when unique; otherwise -1.

--*/
{
    const ULONG_PTR fastRefMask = (sizeof(PVOID) == sizeof(ULONG64)) ? 0x0FU : 0x07U;
    ULONG offset = 0UL;
    LONG foundOffset = -1;

    if (Process == NULL || Token == NULL) {
        return -1;
    }
    for (offset = 0UL;
         offset + sizeof(ULONG_PTR) <= KSW_RUNTIME_PROCESS_SCAN_BYTES;
         offset += (ULONG)sizeof(PVOID)) {
        ULONG_PTR candidate = 0U;

        if (!KswordARKDriverReadPointerGuarded((const UCHAR*)Process + offset, &candidate) ||
            (candidate & ~fastRefMask) != (ULONG_PTR)Token) {
            continue;
        }
        if (foundOffset >= 0) {
            return -1;
        }
        foundOffset = (LONG)offset;
    }
    return foundOffset;
}

VOID
KswordARKDriverResolveTokenLayoutOffsets(
    _In_ PACCESS_TOKEN Token,
    _Out_ LONG* UserAndGroupCountOffsetOut,
    _Out_ LONG* UserAndGroupsOffsetOut,
    _Out_ LONG* IntegrityLevelIndexOffsetOut,
    _Out_ LONG* MandatoryPolicyOffsetOut
    )
/*++

Routine Description:

    Recover the four token integrity fields by comparing a bounded token-body
    scan with TokenUser, TokenGroups, TokenIntegrityLevel, and
    TokenMandatoryPolicy query results. A field set is accepted only when the
    internal SID array is an exact ordered match and every scalar candidate is
    unique inside its structural window.

Arguments:

    Token - Referenced primary token object.
    UserAndGroupCountOffsetOut - Receives TOKEN.UserAndGroupCount.
    UserAndGroupsOffsetOut - Receives TOKEN.UserAndGroups.
    IntegrityLevelIndexOffsetOut - Receives TOKEN.IntegrityLevelIndex.
    MandatoryPolicyOffsetOut - Receives TOKEN.MandatoryPolicy.

Return Value:

    None. All outputs remain unavailable unless the complete layout validates.

--*/
{
    PTOKEN_USER tokenUser = NULL;
    PTOKEN_GROUPS tokenGroups = NULL;
    PTOKEN_MANDATORY_LABEL integrityLabel = NULL;
    PTOKEN_MANDATORY_POLICY mandatoryPolicy = NULL;
    ULONG expectedCount = 0UL;
    ULONG groupsOffset = 0UL;
    LONG foundGroupsOffset = -1;
    LONG foundCountOffset = -1;
    LONG foundPairOffset = -1;
    ULONG integrityIndex = MAXULONG;
    NTSTATUS status = STATUS_SUCCESS;

    if (UserAndGroupCountOffsetOut == NULL || UserAndGroupsOffsetOut == NULL ||
        IntegrityLevelIndexOffsetOut == NULL || MandatoryPolicyOffsetOut == NULL) {
        return;
    }
    *UserAndGroupCountOffsetOut = -1;
    *UserAndGroupsOffsetOut = -1;
    *IntegrityLevelIndexOffsetOut = -1;
    *MandatoryPolicyOffsetOut = -1;
    // SeQueryInformationToken allocates token-information buffers at PASSIVE_LEVEL.
    if (Token == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    status = SeQueryInformationToken(Token, TokenUser, (PVOID*)&tokenUser);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = SeQueryInformationToken(Token, TokenGroups, (PVOID*)&tokenGroups);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = SeQueryInformationToken(Token, TokenIntegrityLevel, (PVOID*)&integrityLabel);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = SeQueryInformationToken(Token, TokenMandatoryPolicy, (PVOID*)&mandatoryPolicy);
    if (!NT_SUCCESS(status) || tokenGroups->GroupCount >= KSW_RUNTIME_TOKEN_MAX_GROUPS) {
        goto Exit;
    }
    expectedCount = tokenGroups->GroupCount + 1UL;

    for (groupsOffset = 0UL;
         groupsOffset + sizeof(PVOID) <= KSW_RUNTIME_TOKEN_SCAN_BYTES;
         groupsOffset += (ULONG)sizeof(PVOID)) {
        ULONG_PTR candidateAddress = 0U;

        if (!KswordARKDriverReadPointerGuarded((const UCHAR*)Token + groupsOffset, &candidateAddress) ||
            candidateAddress == 0U ||
            !KswordARKDriverTokenGroupArrayMatches(
                (const SID_AND_ATTRIBUTES*)candidateAddress,
                expectedCount,
                tokenUser,
                tokenGroups)) {
            continue;
        }
        if (foundGroupsOffset >= 0) {
            goto Exit;
        }
        foundGroupsOffset = (LONG)groupsOffset;
    }
    if (foundGroupsOffset < 0) {
        goto Exit;
    }

    {
        ULONG_PTR groupArrayAddress = 0U;
        const SID_AND_ATTRIBUTES* groupArray = NULL;
        ULONG index = 0UL;
        ULONG matchCount = 0UL;

        if (!KswordARKDriverReadPointerGuarded(
                (const UCHAR*)Token + foundGroupsOffset,
                &groupArrayAddress)) {
            goto Exit;
        }
        groupArray = (const SID_AND_ATTRIBUTES*)groupArrayAddress;
        for (index = 0UL; index < expectedCount; ++index) {
            SID_AND_ATTRIBUTES groupEntry;

            RtlZeroMemory(&groupEntry, sizeof(groupEntry));
            if (!KswordARKDriverReadSidAndAttributesGuarded(
                    &groupArray[index],
                    &groupEntry)) {
                goto Exit;
            }
            if (KswordARKDriverEqualSidGuarded(
                    groupEntry.Sid,
                    integrityLabel->Label.Sid)) {
                integrityIndex = index;
                matchCount += 1UL;
            }
        }
        if (matchCount != 1UL || integrityIndex == MAXULONG) {
            goto Exit;
        }
    }

    {
        ULONG searchStart = ((ULONG)foundGroupsOffset > KSW_RUNTIME_TOKEN_FIELD_WINDOW)
            ? (ULONG)foundGroupsOffset - KSW_RUNTIME_TOKEN_FIELD_WINDOW
            : 0UL;
        ULONG offset = 0UL;

        for (offset = searchStart; offset < (ULONG)foundGroupsOffset; offset += sizeof(ULONG)) {
            ULONG value = 0UL;

            __try {
                value = *(volatile const ULONG*)((const UCHAR*)Token + offset);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                goto Exit;
            }
            if (value != expectedCount) {
                continue;
            }
            if (foundCountOffset >= 0) {
                goto Exit;
            }
            foundCountOffset = (LONG)offset;
        }
    }
    if (foundCountOffset < 0) {
        goto Exit;
    }

    {
        ULONG pairSearchEnd = (ULONG)foundGroupsOffset + KSW_RUNTIME_TOKEN_FIELD_WINDOW;
        ULONG offset = 0UL;

        if (pairSearchEnd > KSW_RUNTIME_TOKEN_SCAN_BYTES - (2UL * sizeof(ULONG))) {
            pairSearchEnd = KSW_RUNTIME_TOKEN_SCAN_BYTES - (2UL * sizeof(ULONG));
        }
        for (offset = (ULONG)foundGroupsOffset;
             offset <= pairSearchEnd;
             offset += sizeof(ULONG)) {
            ULONG indexValue = 0UL;
            ULONG policyValue = 0UL;

            __try {
                indexValue = *(volatile const ULONG*)((const UCHAR*)Token + offset);
                policyValue = *(volatile const ULONG*)((const UCHAR*)Token + offset + sizeof(ULONG));
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                goto Exit;
            }
            if (indexValue != integrityIndex || policyValue != mandatoryPolicy->Policy) {
                continue;
            }
            if (foundPairOffset >= 0) {
                goto Exit;
            }
            foundPairOffset = (LONG)offset;
        }
    }
    if (foundPairOffset < 0) {
        goto Exit;
    }

    *UserAndGroupCountOffsetOut = foundCountOffset;
    *UserAndGroupsOffsetOut = foundGroupsOffset;
    *IntegrityLevelIndexOffsetOut = foundPairOffset;
    *MandatoryPolicyOffsetOut = foundPairOffset + (LONG)sizeof(ULONG);

Exit:
    if (mandatoryPolicy != NULL) {
        ExFreePool(mandatoryPolicy);
    }
    if (integrityLabel != NULL) {
        ExFreePool(integrityLabel);
    }
    if (tokenGroups != NULL) {
        ExFreePool(tokenGroups);
    }
    if (tokenUser != NULL) {
        ExFreePool(tokenUser);
    }
}
