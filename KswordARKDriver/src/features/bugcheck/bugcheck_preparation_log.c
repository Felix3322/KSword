/*++

Module Name:

    bugcheck_preparation_log.c

Abstract:

    PASSIVE_LEVEL text reporting for BGP preparation. The report is written
    while the driver loads and is never touched by a bugcheck callback.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_bgp.h"
#include "bugcheck_bgp_internal.h"
#include "bugcheck_preparation_log.h"

#include <ntstrsafe.h>

#define KSWORD_ARK_BGP_PREPARATION_LOG_PATH \
    L"\\SystemRoot\\Temp\\KswordARK-bgp-preparation.log"
#define KSWORD_ARK_BGP_PREPARATION_LOG_CAPACITY 2048UL

static PCSTR
KswordARKBugcheckPreparationStageText(
    _In_ ULONG Stage
    )
{
    // Convert the stable preparation value to a label that can be read
    // without consulting symbols or source code.
    switch ((KSWORD_ARK_BGP_PREPARATION_STAGE)Stage) {
    case KswordArkBgpPreparationIdle: return "idle";
    case KswordArkBgpPreparationResolveFunctions: return "resolve-functions";
    case KswordArkBgpPreparationReadScreen: return "read-screen";
    case KswordArkBgpPreparationBackendReady: return "backend-ready";
    case KswordArkBgpPreparationValidatePanelScreen: return "validate-panel-screen";
    case KswordArkBgpPreparationPrepareLogo: return "prepare-logo";
    case KswordArkBgpPreparationPrepareGlyphs: return "prepare-glyphs";
    case KswordArkBgpPreparationArm: return "arm";
    case KswordArkBgpPreparationComplete: return "complete";
    default: return "unknown";
    }
}

static PCSTR
KswordARKBugcheckBgpStateText(
    _In_ ULONG State
    )
{
    // Convert the BGP state machine value to a stable report label.
    switch ((KSWORD_ARK_BGP_STATE)State) {
    case KswordArkBgpStateUninitialized: return "uninitialized";
    case KswordArkBgpStateQueryOnly: return "query-only";
    case KswordArkBgpStateReady: return "ready";
    case KswordArkBgpStateArmed: return "armed";
    case KswordArkBgpStateDrawn: return "drawn";
    case KswordArkBgpStateRejected: return "rejected";
    case KswordArkBgpStateUnloading: return "unloading";
    default: return "unknown";
    }
}

static NTSTATUS
KswordARKBugcheckWritePreparationText(
    _In_reads_bytes_(TextLength) PCSTR Text,
    _In_ ULONG TextLength
    )
{
    UNICODE_STRING reportPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle;
    NTSTATUS status;

    // Reject invalid input before creating or replacing the report file.
    if (Text == NULL || TextLength == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Use a kernel handle and a synchronous write-through file so the report
    // remains available even when the later test immediately crashes Windows.
    RtlInitUnicodeString(
        &reportPath,
        KSWORD_ARK_BGP_PREPARATION_LOG_PATH);
    InitializeObjectAttributes(
        &objectAttributes,
        &reportPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    fileHandle = NULL;
    status = ZwCreateFile(
        &fileHandle,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_WRITE_THROUGH,
        NULL,
        0UL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Write the report in one operation. FILE_WRITE_THROUGH and synchronous
    // close complete the write before initialization returns to the framework.
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));
    status = ZwWriteFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        (PVOID)Text,
        TextLength,
        NULL,
        NULL);
    if (NT_SUCCESS(status) && ioStatus.Information != TextLength) {
        status = STATUS_DEVICE_DATA_ERROR;
    }
    // Close the private kernel handle on every post-create path.
    ZwClose(fileHandle);
    return status;
}

NTSTATUS
KswordARKBugcheckWritePreparationLog(
    _In_ NTSTATUS BgpInitializeStatus,
    _In_ NTSTATUS PanelInitializeStatus,
    _In_ NTSTATUS CallbackRegistrationStatus
    )
{
    KSWORD_ARK_BGP_DUMP_STATE snapshot;
    CHAR report[KSWORD_ARK_BGP_PREPARATION_LOG_CAPACITY];
    SIZE_T reportLength;
    ULONG osMajor;
    ULONG osMinor;
    ULONG osBuild;
    NTSTATUS status;

    // Snapshot only the preallocated nonpaged state after all preparation and
    // callback registration attempts have completed.
    RtlZeroMemory(&snapshot, sizeof(snapshot));
    KswordARKBugcheckBgpSnapshot(&snapshot);
    osMajor = 0UL;
    osMinor = 0UL;
    osBuild = 0UL;
    (VOID)PsGetVersion(&osMajor, &osMinor, &osBuild, NULL);

    // Format a self-contained ASCII report that PowerShell or Notepad can read
    // directly after the driver is loaded on the target machine.
    RtlZeroMemory(report, sizeof(report));
    status = RtlStringCbPrintfA(
        report,
        sizeof(report),
        "KswordARK BGP preparation report v1\r\n"
        "secondary_dump_data_version=3\r\n"
        "os_version=%lu.%lu.%lu\r\n"
        "bgp_initialize_status=0x%08lX\r\n"
        "panel_initialize_status=0x%08lX\r\n"
        "callback_registration_status=0x%08lX\r\n"
        "state=%lu (%s)\r\n"
        "preparation_stage=%lu (%s)\r\n"
        "preparation_status=0x%08lX\r\n"
        "crash_stage=0x%08lX\r\n"
        "last_status=0x%08lX\r\n"
        "feature_mask=0x%08lX\r\n"
        "screen=%lux%lux%lu\r\n"
        "last_probe=%lux%lux%lu\r\n"
        "required=%lux%lu\r\n"
        "signature_family_clear=%lu\r\n"
        "signature_family_draw=%lu\r\n"
        "signature_family_acquire=%lu\r\n"
        "signature_family_release=%lu\r\n"
        "signature_family_resolution=%lu\r\n"
        "signature_family_bpp=%lu\r\n"
        "signature_family_parse=%lu\r\n"
        "signature_family_destroy=%lu\r\n"
        "callback_classic=%lu\r\n"
        "callback_secondary=%lu\r\n"
        "callback_dump_io=%lu\r\n"
        "callback_triage=%lu\r\n"
        "logo_source=qrc KswordHome-En.png -> embedded MainLogoBitmap.h\r\n"
        "runtime_bmp_file_dependency=none\r\n",
        osMajor,
        osMinor,
        osBuild,
        (ULONG)BgpInitializeStatus,
        (ULONG)PanelInitializeStatus,
        (ULONG)CallbackRegistrationStatus,
        snapshot.State,
        KswordARKBugcheckBgpStateText(snapshot.State),
        snapshot.PreparationStage,
        KswordARKBugcheckPreparationStageText(snapshot.PreparationStage),
        snapshot.PreparationStatus,
        snapshot.Stage,
        snapshot.LastStatus,
        snapshot.FeatureMask,
        snapshot.ScreenWidth,
        snapshot.ScreenHeight,
        snapshot.ScreenBpp,
        g_KswordArkBgp.ProbeWidth,
        g_KswordArkBgp.ProbeHeight,
        g_KswordArkBgp.ProbeBpp,
        snapshot.RequiredWidth,
        snapshot.RequiredHeight,
        snapshot.SignatureFamily[0],
        snapshot.SignatureFamily[1],
        snapshot.SignatureFamily[2],
        snapshot.SignatureFamily[3],
        snapshot.SignatureFamily[4],
        snapshot.SignatureFamily[5],
        snapshot.SignatureFamily[6],
        snapshot.SignatureFamily[7],
        g_KswordArkBugcheckState.ClassicRegistered ? 1UL : 0UL,
        g_KswordArkBugcheckState.SecondaryRegistered ? 1UL : 0UL,
        g_KswordArkBugcheckState.DumpIoRegistered ? 1UL : 0UL,
        g_KswordArkBugcheckState.TriageRegistered ? 1UL : 0UL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Measure the completed report and narrow the known 2 KiB bound to the
    // ULONG byte count accepted by ZwWriteFile.
    reportLength = 0U;
    status = RtlStringCbLengthA(report, sizeof(report), &reportLength);
    if (!NT_SUCCESS(status) || reportLength == 0U || reportLength > MAXULONG) {
        return NT_SUCCESS(status) ? STATUS_INVALID_BUFFER_SIZE : status;
    }

    return KswordARKBugcheckWritePreparationText(
        report,
        (ULONG)reportLength);
}
