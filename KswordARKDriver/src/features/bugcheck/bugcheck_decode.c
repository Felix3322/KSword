/*++

Module Name:

    bugcheck_decode.c

Abstract:

    Crash-safe decoding of documented BugCheck address parameters. The helper
    is kept independent of module lookup so it can be replayed in user mode.

--*/

#include "bugcheck_decode.h"

#include <ntstrsafe.h>

static BOOLEAN
KswordARKBugcheckDecodeVerifierAddress(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _Out_ PULONG_PTR Address,
    _Out_ PULONG ParameterIndex,
    _Out_ PCSTR* Meaning
    )
{
    if (Diagnostics->BugCheckCode == 0x000000C4) {
        switch (Diagnostics->Parameter1) {
        case 0xDA:
            *Address = Diagnostics->Parameter3;
            *ParameterIndex = 3;
            *Meaning = "WMI callback address inside unloading driver";
            return TRUE;
        case 0xDD:
        case 0xE3:
        case 0xE4:
        case 0xE6:
        case 0xFC:
        case 0x110:
        case 0x111:
        case 0x2000:
        case 0x2001:
        case 0x2002:
            *Address = Diagnostics->Parameter2;
            *ParameterIndex = 2;
            *Meaning = "documented address inside the verified driver";
            return TRUE;
        case 0xF6:
            *Address = Diagnostics->Parameter4;
            *ParameterIndex = 4;
            *Meaning = "driver address that referenced the handle";
            return TRUE;
        case 0xFA:
        case 0xFB:
            *Address = Diagnostics->Parameter2;
            *ParameterIndex = 2;
            *Meaning = "driver completion routine address";
            return TRUE;
        default:
            return FALSE;
        }
    }

    if (Diagnostics->BugCheckCode == 0x000000C9) {
        switch (Diagnostics->Parameter1) {
        case 0x07:
            *Address = Diagnostics->Parameter2;
            *ParameterIndex = 2;
            *Meaning = "driver cancel routine address";
            return TRUE;
        case 0x11:
        case 0x12:
            *Address = Diagnostics->Parameter2;
            *ParameterIndex = 2;
            *Meaning = "driver dispatch routine address";
            return TRUE;
        default:
            return FALSE;
        }
    }
    return FALSE;
}

BOOLEAN
KswordARKBugcheckDecodePrimaryAddress(
    _Inout_ PKSWORD_ARK_BUGCHECK_DIAGNOSTICS Diagnostics,
    _Out_ PULONG_PTR Address,
    _Out_ PULONG ParameterIndex,
    _Out_ PULONG Confidence
    )
{
    PCSTR meaning;

    if (Diagnostics == NULL || Address == NULL || ParameterIndex == NULL ||
        Confidence == NULL) {
        return FALSE;
    }

    meaning = "stop code has no direct instruction address";
    *Address = 0;
    *ParameterIndex = 0;
    *Confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE;

    switch (Diagnostics->BugCheckCode) {
    case 0x0000000A:
    case 0x000000D1:
        *Address = Diagnostics->Parameter4;
        *ParameterIndex = 4;
        *Confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        meaning = "instruction address that referenced memory";
        break;
    case 0x0000001E:
    case 0x0000003B:
    case 0x0000007E:
        *Address = Diagnostics->Parameter2;
        *ParameterIndex = 2;
        *Confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        meaning = "exception instruction address";
        break;
    case 0x00000050:
        *Address = Diagnostics->Parameter3;
        *ParameterIndex = 3;
        *Confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_MEDIUM;
        meaning = "instruction address that referenced memory";
        break;
    case 0x000000C5:
        *Address = Diagnostics->Parameter4;
        *ParameterIndex = 4;
        *Confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        meaning = "instruction address that referenced memory";
        break;
    case 0x000000D5:
        *Address = Diagnostics->Parameter3;
        *ParameterIndex = 3;
        *Confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_MEDIUM;
        meaning = "instruction address that referenced memory";
        break;
    case 0x00000116:
    case 0x00000117:
        *Address = Diagnostics->Parameter2;
        *ParameterIndex = 2;
        *Confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        meaning = "pointer inside responsible display module";
        break;
    case 0x000000C4:
    case 0x000000C9:
        if (KswordARKBugcheckDecodeVerifierAddress(
                Diagnostics,
                Address,
                ParameterIndex,
                &meaning)) {
            *Confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        }
        break;
    default:
        break;
    }

    Diagnostics->FaultAddress = *Address;
    Diagnostics->FaultParameter = *ParameterIndex;
    (VOID)RtlStringCbCopyA(
        Diagnostics->FaultMeaning,
        sizeof(Diagnostics->FaultMeaning),
        meaning);
    return (*Address != 0 && *Confidence != KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE)
        ? TRUE
        : FALSE;
}

static PCSTR
KswordARKBugcheckDecodePowerRole(
    _In_ ULONG_PTR Subtype,
    _In_ ULONG ParameterIndex
    )
{
    if (ParameterIndex == 1) {
        return "VIOLATION TYPE";
    }
    switch (Subtype) {
    case 0x1:
        return ParameterIndex == 2 ? "DEVICE OBJECT" : "RESERVED";
    case 0x2:
        if (ParameterIndex == 2) return "TARGET DEVICE";
        if (ParameterIndex == 3) return "DEVICE OBJECT";
        return "DRIVER OBJECT";
    case 0x3:
        if (ParameterIndex == 2) return "PHYSICAL DEVICE";
        if (ParameterIndex == 3) return "POWER TRIAGE";
        return "BLOCKED IRP";
    case 0x4:
        if (ParameterIndex == 2) return "TIMEOUT SECONDS";
        if (ParameterIndex == 3) return "PNP LOCK THREAD";
        return "PNP TRIAGE";
    case 0x5:
        if (ParameterIndex == 2) return "PHYSICAL DEVICE";
        if (ParameterIndex == 3) return "POWER DEVICE";
        return "RESERVED";
    case 0x6:
        if (ParameterIndex == 2) return "POWER DEVICE";
        if (ParameterIndex == 3) return "POWER DIRECTION";
        return "RESERVED";
    case 0x500:
        if (ParameterIndex == 2) return "RESERVED";
        if (ParameterIndex == 3) return "TARGET DEVICE";
        return "DEVICE OBJECT";
    default:
        return "SUBTYPE DATA";
    }
}

static PCSTR
KswordARKBugcheckDecodeVerifierRole(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG ParameterIndex
    )
{
    const ULONG_PTR subtype = Diagnostics->Parameter1;

    if (ParameterIndex == 1) {
        return "VIOLATION CODE";
    }
    if (Diagnostics->BugCheckCode == 0x000000C9) {
        if (subtype == 0x07) {
            return ParameterIndex == 2 ? "CANCEL ROUTINE" :
                (ParameterIndex == 3 ? "IRP" : "RESERVED");
        }
        if (subtype == 0x11 || subtype == 0x12) {
            return ParameterIndex == 2 ? "DRIVER ROUTINE" :
                (ParameterIndex == 3 ? "IRQL BEFORE" : "CURRENT IRQL");
        }
        return "VIOLATION DATA";
    }

    switch (subtype) {
    case 0xDA:
        return ParameterIndex == 2 ? "DRIVER BASE" :
            (ParameterIndex == 3 ? "WMI CALLBACK" : "RESERVED");
    case 0xDD:
        return ParameterIndex == 2 ? "REGISTER CALL" :
            (ParameterIndex == 3 ? "DRIVER BASE" : "REG HANDLE");
    case 0xE3:
    case 0xE4:
        return ParameterIndex == 2 ? "CALL ADDRESS" :
            (ParameterIndex == 3 ? "BAD ARGUMENT" : "RESERVED");
    case 0xE6:
        return ParameterIndex == 2 ? "DRIVER ADDRESS" :
            (ParameterIndex == 3 ? "CURRENT IRQL" : "APC STATE");
    case 0xF6:
        return ParameterIndex == 2 ? "HANDLE" :
            (ParameterIndex == 3 ? "PROCESS OBJECT" : "DRIVER ADDRESS");
    case 0xFA:
    case 0xFB:
        return ParameterIndex == 2 ? "COMPLETION ROUTINE" :
            (ParameterIndex == 3 ? "IRQL OR APC" : "CURRENT VALUE");
    case 0x110:
    case 0x111:
        return ParameterIndex == 2 ? "ISR ADDRESS" : "ISR CONTEXT";
    case 0x2000:
    case 0x2001:
    case 0x2002:
        return ParameterIndex == 2 ? "DRIVER ADDRESS" : "POLICY VALUE";
    default:
        return "VIOLATION DATA";
    }
}

PCSTR
KswordARKBugcheckDecodeParameterRole(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG ParameterIndex
    )
{
    static const PCSTR genericRoles[4] = {
        "PARAMETER 1", "PARAMETER 2", "PARAMETER 3", "PARAMETER 4"
    };

    if (Diagnostics == NULL || ParameterIndex < 1 || ParameterIndex > 4) {
        return "PARAMETER";
    }

    switch (Diagnostics->BugCheckCode) {
    case 0x0000000A:
    case 0x000000D1:
        return ParameterIndex == 1 ? "MEMORY" :
            (ParameterIndex == 2 ? "IRQL" :
             (ParameterIndex == 3 ? "ACCESS TYPE" : "INSTRUCTION"));
    case 0x0000001E:
    case 0x0000007E:
        return ParameterIndex == 1 ? "EXCEPTION CODE" :
            (ParameterIndex == 2 ? "INSTRUCTION" : "EXCEPTION DATA");
    case 0x0000003B:
        return ParameterIndex == 1 ? "EXCEPTION CODE" :
            (ParameterIndex == 2 ? "INSTRUCTION" :
             (ParameterIndex == 3 ? "CONTEXT RECORD" : "RESERVED"));
    case 0x00000050:
        return ParameterIndex == 1 ? "MEMORY" :
            (ParameterIndex == 2 ? "ACCESS TYPE" :
             (ParameterIndex == 3 ? "INSTRUCTION" : "RESERVED"));
    case 0x0000009F:
        return KswordARKBugcheckDecodePowerRole(
            Diagnostics->Parameter1,
            ParameterIndex);
    case 0x000000C4:
    case 0x000000C9:
        return KswordARKBugcheckDecodeVerifierRole(
            Diagnostics,
            ParameterIndex);
    case 0x000000C5:
        return ParameterIndex == 1 ? "MEMORY" :
            (ParameterIndex == 2 ? "CURRENT IRQL" :
             (ParameterIndex == 3 ? "ACCESS TYPE" : "INSTRUCTION"));
    case 0x000000D5:
        return ParameterIndex == 1 ? "MEMORY" :
            (ParameterIndex == 2 ? "ACCESS TYPE" :
             (ParameterIndex == 3 ? "INSTRUCTION" : "RESERVED"));
    case 0x000000EA:
        return ParameterIndex == 1 ? "STUCK THREAD" :
            (ParameterIndex == 2 ? "WATCHDOG" :
             (ParameterIndex == 3 ? "DRIVER NAME" : "HIT COUNT"));
    case 0x000000EF:
        return ParameterIndex == 1 ? "PROCESS OBJECT" :
            (ParameterIndex == 2 ? "OBJECT TYPE" : "RESERVED");
    case 0x00000116:
    case 0x00000117:
        return ParameterIndex == 1 ? "TDR CONTEXT" :
            (ParameterIndex == 2 ? "DRIVER ADDRESS" :
             (ParameterIndex == 3 ? "ERROR CODE" : "INTERNAL DATA"));
    default:
        return genericRoles[ParameterIndex - 1UL];
    }
}
