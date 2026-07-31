/*++

Module Name:

    platform_audit.c

Abstract:

    HAL 与 KMDF 绑定表的只读、失败关闭审计。

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "driver/KswordArkPlatformAuditIoctl.h"
#include "../kernel/hook_scan_support.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntimage.h>
#include <ntstrsafe.h>

// ntddk.h exposes these HAL_DISPATCH members as object-like convenience
// macros.  Undefine the aliases in this translation unit so FIELD_OFFSET and
// member-size expressions below refer to the actual structure fields.
#undef HalQuerySystemInformation
#undef HalSetSystemInformation
#undef HalQueryBusSlots
#undef HalReferenceHandlerForBus
#undef HalReferenceBusHandler
#undef HalDereferenceBusHandler
#undef HalInitPnpDriver
#undef HalInitPowerManagement
#undef HalGetDmaAdapter
#undef HalGetInterruptTranslator
#undef HalStartMirroring
#undef HalEndMirroring
#undef HalMirrorPhysicalMemory
#undef HalEndOfBoot
#undef HalMirrorVerify
#undef HalGetCachedAcpiTable
#undef HalSetPciErrorHandlerCallback
#undef HalGetPrmCache
#undef HalInvokePrmFwHandler

#define KSW_PLATFORM_RESPONSE_HEADER_SIZE \
    (FIELD_OFFSET(KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE, entries))
#define KSW_PLATFORM_HAL_ACPI_SIGNATURE 0x204C4148UL
#define KSW_PLATFORM_HAL_ACPI_VERSION   5UL
#define KSW_PLATFORM_HAL_ACPI_FUNCTION_COUNT 18UL
#define KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT 22UL

typedef struct _KSW_PLATFORM_SLOT_DESCRIPTOR
{
    ULONG Offset;
    ULONG Width;
    PCWSTR Name;
    ULONG SlotKind;
    ULONG OwnerPolicy;
} KSW_PLATFORM_SLOT_DESCRIPTOR;

typedef struct _KSW_PLATFORM_PRIVATE_BUILD_DESCRIPTOR
{
    ULONG BuildNumber;
    ULONG Version;
    ULONG ByteSize;
    ULONG SignatureId;
} KSW_PLATFORM_PRIVATE_BUILD_DESCRIPTOR;

typedef struct _KSW_PLATFORM_HAL_ACPI_VIEW
{
    ULONG Signature;
    ULONG Version;
    PVOID Functions[KSW_PLATFORM_HAL_ACPI_FUNCTION_COUNT];
} KSW_PLATFORM_HAL_ACPI_VIEW;

typedef struct _KSW_PLATFORM_HAL_SUBCOMPONENT
{
    PVOID Function;
    PCWSTR Name;
} KSW_PLATFORM_HAL_SUBCOMPONENT;

typedef struct _KSW_PLATFORM_CALLBACK_DESCRIPTOR
{
    PVOID Address;
    PCWSTR Name;
} KSW_PLATFORM_CALLBACK_DESCRIPTOR;

#define KSW_PLATFORM_WIDE_IMPL(Value) L##Value
#define KSW_PLATFORM_WIDE(Value) KSW_PLATFORM_WIDE_IMPL(#Value)
#define KSW_HAL_PUBLIC_FUNCTION(Field, Policy) \
    { FIELD_OFFSET(HAL_DISPATCH, Field), sizeof(((PHAL_DISPATCH)0)->Field), \
      KSW_PLATFORM_WIDE(Field), KSWORD_ARK_PLATFORM_SLOT_FUNCTION, Policy }
#define KSW_HAL_PUBLIC_SCALAR(Field) \
    { FIELD_OFFSET(HAL_DISPATCH, Field), sizeof(((PHAL_DISPATCH)0)->Field), \
      KSW_PLATFORM_WIDE(Field), KSWORD_ARK_PLATFORM_SLOT_SCALAR, KSWORD_ARK_PLATFORM_OWNER_NONE }

static const KSW_PLATFORM_SLOT_DESCRIPTOR g_KswHalDispatchSlots[] = {
    KSW_HAL_PUBLIC_FUNCTION(HalQuerySystemInformation, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalSetSystemInformation, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalQueryBusSlots, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_SCALAR(Spare1),
    KSW_HAL_PUBLIC_FUNCTION(HalExamineMBR, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalIoReadPartitionTable, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalIoSetPartitionInformation, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalIoWritePartitionTable, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalReferenceHandlerForBus, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalReferenceBusHandler, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalDereferenceBusHandler, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalInitPnpDriver, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalInitPowerManagement, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI),
    KSW_HAL_PUBLIC_FUNCTION(HalGetDmaAdapter, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalGetInterruptTranslator, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalStartMirroring, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalEndMirroring, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalMirrorPhysicalMemory, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalEndOfBoot, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalMirrorVerify, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalGetCachedAcpiTable, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI),
    KSW_HAL_PUBLIC_FUNCTION(HalSetPciErrorHandlerCallback, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI),
    KSW_HAL_PUBLIC_FUNCTION(HalGetPrmCache, KSWORD_ARK_PLATFORM_OWNER_NT_HAL),
    KSW_HAL_PUBLIC_FUNCTION(HalInvokePrmFwHandler, KSWORD_ARK_PLATFORM_OWNER_NT_HAL)
};

#undef KSW_HAL_PUBLIC_SCALAR
#undef KSW_HAL_PUBLIC_FUNCTION
#undef KSW_PLATFORM_WIDE
#undef KSW_PLATFORM_WIDE_IMPL

#define KSW_PRIVATE_FUNCTION(OffsetValue, NameValue, PolicyValue) \
    { OffsetValue, sizeof(PVOID), L##NameValue, KSWORD_ARK_PLATFORM_SLOT_FUNCTION, PolicyValue }
#define KSW_PRIVATE_DUMMY(OffsetValue, NameValue) \
    { OffsetValue, sizeof(PVOID), L##NameValue, KSWORD_ARK_PLATFORM_SLOT_DUMMY, KSWORD_ARK_PLATFORM_OWNER_NONE }
#define KSW_PF(OffsetValue, NameValue) \
    KSW_PRIVATE_FUNCTION(OffsetValue, NameValue, KSWORD_ARK_PLATFORM_OWNER_NT_HAL)
#define KSW_PFP(OffsetValue, NameValue) \
    KSW_PRIVATE_FUNCTION(OffsetValue, NameValue, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI)
#define KSW_PFA(OffsetValue, NameValue) \
    KSW_PRIVATE_FUNCTION(OffsetValue, NameValue, KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)

// 中文说明：该描述表是 ntdiff 22000/22621/26100 结构的共同前缀。
// 每个版本只能读取其 build descriptor 指定的 ByteSize，绝不把尾部或 padding 当函数。
static const KSW_PLATFORM_SLOT_DESCRIPTOR g_KswHalPrivateSlots[] = {
    KSW_PF(0x008, "HalHandlerForBus"),
    KSW_PF(0x010, "HalHandlerForConfigSpace"),
    KSW_PF(0x018, "HalLocateHiberRanges"),
    KSW_PF(0x020, "HalRegisterBusHandler"),
    KSW_PFA(0x028, "HalSetWakeEnable"),
    KSW_PFA(0x030, "HalSetWakeAlarm"),
    KSW_PFP(0x038, "HalPciTranslateBusAddress"),
    KSW_PFP(0x040, "HalPciAssignSlotResources"),
    KSW_PF(0x048, "HalHaltSystem"),
    KSW_PF(0x050, "HalFindBusAddressTranslation"),
    KSW_PF(0x058, "HalResetDisplay"),
    KSW_PF(0x060, "HalAllocateMapRegisters"),
    KSW_PFP(0x068, "KdSetupPciDeviceForDebugging"),
    KSW_PFP(0x070, "KdReleasePciDeviceForDebugging"),
    KSW_PFA(0x078, "KdGetAcpiTablePhase0"),
    KSW_PFA(0x080, "KdCheckPowerButton"),
    KSW_PF(0x088, "HalVectorToIDTEntry"),
    KSW_PF(0x090, "KdMapPhysicalMemory64"),
    KSW_PF(0x098, "KdUnmapVirtualAddress"),
    KSW_PFP(0x0A0, "KdGetPciDataByOffset"),
    KSW_PFP(0x0A8, "KdSetPciDataByOffset"),
    KSW_PFA(0x0B0, "HalGetInterruptVectorOverride"),
    KSW_PFA(0x0B8, "HalGetVectorInputOverride"),
    KSW_PF(0x0C0, "HalLoadMicrocode"),
    KSW_PF(0x0C8, "HalUnloadMicrocode"),
    KSW_PF(0x0D0, "HalPostMicrocodeUpdate"),
    KSW_PFA(0x0D8, "HalAllocateMessageTargetOverride"),
    KSW_PFA(0x0E0, "HalFreeMessageTargetOverride"),
    KSW_PF(0x0E8, "HalDpReplaceBegin"),
    KSW_PF(0x0F0, "HalDpReplaceTarget"),
    KSW_PF(0x0F8, "HalDpReplaceControl"),
    KSW_PF(0x100, "HalDpReplaceEnd"),
    KSW_PF(0x108, "HalPrepareForBugcheck"),
    KSW_PFA(0x110, "HalQueryWakeTime"),
    KSW_PF(0x118, "HalReportIdleStateUsage"),
    KSW_PF(0x120, "HalTscSynchronization"),
    KSW_PF(0x128, "HalWheaInitProcessorGenericSection"),
    KSW_PF(0x130, "HalStopLegacyUsbInterrupts"),
    KSW_PF(0x138, "HalReadWheaPhysicalMemory"),
    KSW_PF(0x140, "HalWriteWheaPhysicalMemory"),
    KSW_PF(0x148, "HalDpMaskLevelTriggeredInterrupts"),
    KSW_PF(0x150, "HalDpUnmaskLevelTriggeredInterrupts"),
    KSW_PF(0x158, "HalDpGetInterruptReplayState"),
    KSW_PF(0x160, "HalDpReplayInterrupts"),
    KSW_PF(0x168, "HalQueryIoPortAccessSupported"),
    KSW_PF(0x170, "KdSetupIntegratedDeviceForDebugging"),
    KSW_PF(0x178, "KdReleaseIntegratedDeviceForDebugging"),
    KSW_PF(0x180, "HalGetEnlightenmentInformation"),
    KSW_PF(0x188, "HalAllocateEarlyPages"),
    KSW_PF(0x190, "HalMapEarlyPages"),
    KSW_PRIVATE_DUMMY(0x198, "Dummy1"),
    KSW_PRIVATE_DUMMY(0x1A0, "Dummy2"),
    KSW_PF(0x1A8, "HalNotifyProcessorFreeze"),
    KSW_PF(0x1B0, "HalPrepareProcessorForIdle"),
    KSW_PF(0x1B8, "HalRegisterLogRoutine"),
    KSW_PF(0x1C0, "HalResumeProcessorFromIdle"),
    KSW_PRIVATE_DUMMY(0x1C8, "Dummy"),
    KSW_PF(0x1D0, "HalVectorToIDTEntryEx"),
    KSW_PF(0x1D8, "HalSecondaryInterruptQueryPrimaryInformation"),
    KSW_PF(0x1E0, "HalMaskInterrupt"),
    KSW_PF(0x1E8, "HalUnmaskInterrupt"),
    KSW_PF(0x1F0, "HalIsInterruptTypeSecondary"),
    KSW_PF(0x1F8, "HalAllocateGsivForSecondaryInterrupt"),
    KSW_PF(0x200, "HalAddInterruptRemapping"),
    KSW_PF(0x208, "HalRemoveInterruptRemapping"),
    KSW_PF(0x210, "HalSaveAndDisableHvEnlightenment"),
    KSW_PF(0x218, "HalRestoreHvEnlightenment"),
    KSW_PF(0x220, "HalFlushIoBuffersExternalCache"),
    KSW_PF(0x228, "HalFlushExternalCache"),
    KSW_PFP(0x230, "HalPciEarlyRestore"),
    KSW_PF(0x238, "HalGetProcessorId"),
    KSW_PF(0x240, "HalAllocatePmcCounterSet"),
    KSW_PF(0x248, "HalCollectPmcCounters"),
    KSW_PF(0x250, "HalFreePmcCounterSet"),
    KSW_PF(0x258, "HalProcessorHalt"),
    KSW_PF(0x260, "HalTimerQueryCycleCounter"),
    KSW_PRIVATE_DUMMY(0x268, "Dummy3"),
    KSW_PFP(0x270, "HalPciMarkHiberPhase"),
    KSW_PF(0x278, "HalQueryProcessorRestartEntryPoint"),
    KSW_PF(0x280, "HalRequestInterrupt"),
    KSW_PF(0x288, "HalEnumerateUnmaskedInterrupts"),
    KSW_PF(0x290, "HalFlushAndInvalidatePageExternalCache"),
    KSW_PF(0x298, "KdEnumerateDebuggingDevices"),
    KSW_PF(0x2A0, "HalFlushIoRectangleExternalCache"),
    KSW_PFA(0x2A8, "HalPowerEarlyRestore"),
    KSW_PF(0x2B0, "HalQueryCapsuleCapabilities"),
    KSW_PF(0x2B8, "HalUpdateCapsule"),
    KSW_PFP(0x2C0, "HalPciMultiStageResumeCapable"),
    KSW_PF(0x2C8, "HalDmaFreeCrashDumpRegisters"),
    KSW_PFA(0x2D0, "HalAcpiAoacCapable"),
    KSW_PF(0x2D8, "HalInterruptSetDestination"),
    KSW_PF(0x2E0, "HalGetClockConfiguration"),
    KSW_PF(0x2E8, "HalClockTimerActivate"),
    KSW_PF(0x2F0, "HalClockTimerInitialize"),
    KSW_PF(0x2F8, "HalClockTimerStop"),
    KSW_PF(0x300, "HalClockTimerArm"),
    KSW_PF(0x308, "HalTimerOnlyClockInterruptPending"),
    KSW_PFA(0x310, "HalAcpiGetMultiNode"),
    KSW_PFA(0x318, "HalPowerSetRebootHandler"),
    KSW_PF(0x320, "HalIommuRegisterDispatchTable"),
    KSW_PF(0x328, "HalTimerWatchdogStart"),
    KSW_PF(0x330, "HalTimerWatchdogResetCountdown"),
    KSW_PF(0x338, "HalTimerWatchdogStop"),
    KSW_PF(0x340, "HalTimerWatchdogGeneratedLastReset"),
    KSW_PF(0x348, "HalTimerWatchdogTriggerSystemReset"),
    KSW_PF(0x350, "HalInterruptVectorDataToGsiv"),
    KSW_PF(0x358, "HalInterruptGetHighestPriorityInterrupt"),
    KSW_PF(0x360, "HalProcessorOn"),
    KSW_PF(0x368, "HalProcessorOff"),
    KSW_PF(0x370, "HalProcessorFreeze"),
    KSW_PF(0x378, "HalDmaLinkDeviceObjectByToken"),
    KSW_PF(0x380, "HalDmaCheckAdapterToken"),
    KSW_PRIVATE_DUMMY(0x388, "Dummy4"),
    KSW_PF(0x390, "HalTimerConvertPerformanceCounterToAuxiliaryCounter"),
    KSW_PF(0x398, "HalTimerConvertAuxiliaryCounterToPerformanceCounter"),
    KSW_PF(0x3A0, "HalTimerQueryAuxiliaryCounterFrequency"),
    KSW_PF(0x3A8, "HalConnectThermalInterrupt"),
    KSW_PF(0x3B0, "HalIsEFIRuntimeActive"),
    KSW_PF(0x3B8, "HalTimerQueryAndResetRtcErrors"),
    KSW_PFA(0x3C0, "HalAcpiLateRestore"),
    KSW_PF(0x3C8, "KdWatchdogDelayExpiration"),
    KSW_PF(0x3D0, "HalGetProcessorStats"),
    KSW_PF(0x3D8, "HalTimerWatchdogQueryDueTime"),
    KSW_PF(0x3E0, "HalConnectSyntheticInterrupt"),
    KSW_PF(0x3E8, "HalPreprocessNmi"),
    KSW_PF(0x3F0, "HalEnumerateEnvironmentVariablesWithFilter"),
    KSW_PF(0x3F8, "HalCaptureLastBranchRecordStack"),
    KSW_PF(0x400, "HalClearLastBranchRecordStack"),
    KSW_PF(0x408, "HalConfigureLastBranchRecord"),
    KSW_PF(0x410, "HalGetLastBranchInformation"),
    KSW_PF(0x418, "HalResumeLastBranchRecord"),
    KSW_PF(0x420, "HalStartLastBranchRecord"),
    KSW_PF(0x428, "HalStopLastBranchRecord"),
    KSW_PF(0x430, "HalIommuBlockDevice"),
    KSW_PF(0x438, "HalIommuUnblockDevice"),
    KSW_PF(0x440, "HalGetIommuInterface"),
    KSW_PF(0x448, "HalRequestGenericErrorRecovery"),
    KSW_PF(0x450, "HalTimerQueryHostPerformanceCounter"),
    KSW_PF(0x458, "HalTopologyQueryProcessorRelationships"),
    KSW_PF(0x460, "HalInitPlatformDebugTriggers"),
    KSW_PF(0x468, "HalRunPlatformDebugTriggers"),
    KSW_PF(0x470, "HalTimerGetReferencePage"),
    KSW_PF(0x478, "HalGetHiddenProcessorPowerInterface"),
    KSW_PF(0x480, "HalGetHiddenProcessorPackageId"),
    KSW_PF(0x488, "HalGetHiddenPackageProcessorCount"),
    KSW_PF(0x490, "HalGetHiddenProcessorApicIdByIndex"),
    KSW_PF(0x498, "HalRegisterHiddenProcessorIdleState"),
    KSW_PF(0x4A0, "HalIommuReportIommuFault"),
    KSW_PF(0x4A8, "HalIommuDmaRemappingCapable"),
    KSW_PF(0x4B0, "HalAllocatePmcCounterSetEx"),
    KSW_PF(0x4B8, "HalStartProfileInterruptEx"),
    KSW_PF(0x4C0, "HalGetIommuInterfaceEx"),
    KSW_PF(0x4C8, "HalNotifyIommuDomainPolicyChange"),
    KSW_PFP(0x4D0, "HalPciGetDeviceLocationFromPhysicalAddress"),
    KSW_PF(0x4D8, "HalInvokeSmc"),
    KSW_PF(0x4E0, "HalInvokeHvc"),
    KSW_PF(0x4E8, "HalGetSoftRebootDatabase"),
    KSW_PF(0x4F0, "HalRequestPmuAccess"),
    KSW_PF(0x4F8, "HalTopologyQueryProcessorCacheInformation"),
    KSW_PF(0x500, "HalReleasePmuAccessRequest"),
    KSW_PF(0x508, "HalTimerQueryRtcErrors"),
    KSW_PFP(0x510, "HalExternalPciConfigSpaceAccess")
};

#undef KSW_PFA
#undef KSW_PFP
#undef KSW_PF
#undef KSW_PRIVATE_DUMMY
#undef KSW_PRIVATE_FUNCTION

static const KSW_PLATFORM_PRIVATE_BUILD_DESCRIPTOR g_KswHalPrivateBuilds[] = {
    { 22000UL, 54UL, 0x4D8UL, KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V54 },
    { 22621UL, 58UL, 0x4F0UL, KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V58 },
    { 26100UL, 61UL, 0x518UL, KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V61 },
    { 26220UL, 61UL, 0x518UL, KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V61 }
};

static const PCWSTR g_KswHalAcpiFunctionNames[KSW_PLATFORM_HAL_ACPI_FUNCTION_COUNT] = {
    L"HalpAcpiTimerInterrupt",
    L"HalpAcpiMachineStateInit",
    L"HalpAcpiQueryFlags",
    L"HalxPicStateIntact",
    L"HalxRestorePicState",
    L"HalpPciInterfaceReadConfig",
    L"HalpPciInterfaceWriteConfig",
    L"HalpGetIOApicVersion",
    L"HalpSetMaxLegacyPciBusNumber",
    L"HalpIsVectorValid",
    L"HalpGetAcpiTable",
    L"HalpAcpiGetRsdp",
    L"HalpAcpiGetFacsMapping",
    L"HalpAcpiGetAllTables",
    L"HalpAcpiPmRegisterAvailable",
    L"HalpAcpiPmRegisterRead",
    L"HalpAcpiPmRegisterWrite",
    L"HalpAcpiTimerQueryCounter"
};

static const PCWSTR g_KswHalSubcomponentNames[KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT] = {
    L"Acpi", L"Dbg", L"Dma", L"Dp", L"Errata", L"ExtEnv", L"Firmware",
    L"HalExt", L"Hv", L"HwPerfCnt", L"Interrupt", L"Iommu", L"Misc", L"Mm",
    L"Pci", L"Pnp", L"Power", L"Proc", L"Qos", L"Timer", L"Topology", L"Whea"
};

// KMDF 1.15 wdffuncenum.h defines a contiguous, index-stable table of 444 APIs.
// Keep the display names in that exact order so every WdfFunctions slot is named
// without relying on PDBs or runtime signature guesses.
static const PCWSTR g_KswWdfFunctionNames[] = {
    L"WdfChildListCreate",
    L"WdfChildListGetDevice",
    L"WdfChildListRetrievePdo",
    L"WdfChildListRetrieveAddressDescription",
    L"WdfChildListBeginScan",
    L"WdfChildListEndScan",
    L"WdfChildListBeginIteration",
    L"WdfChildListRetrieveNextDevice",
    L"WdfChildListEndIteration",
    L"WdfChildListAddOrUpdateChildDescriptionAsPresent",
    L"WdfChildListUpdateChildDescriptionAsMissing",
    L"WdfChildListUpdateAllChildDescriptionsAsPresent",
    L"WdfChildListRequestChildEject",
    L"WdfCollectionCreate",
    L"WdfCollectionGetCount",
    L"WdfCollectionAdd",
    L"WdfCollectionRemove",
    L"WdfCollectionRemoveItem",
    L"WdfCollectionGetItem",
    L"WdfCollectionGetFirstItem",
    L"WdfCollectionGetLastItem",
    L"WdfCommonBufferCreate",
    L"WdfCommonBufferGetAlignedVirtualAddress",
    L"WdfCommonBufferGetAlignedLogicalAddress",
    L"WdfCommonBufferGetLength",
    L"WdfControlDeviceInitAllocate",
    L"WdfControlDeviceInitSetShutdownNotification",
    L"WdfControlFinishInitializing",
    L"WdfDeviceGetDeviceState",
    L"WdfDeviceSetDeviceState",
    L"WdfWdmDeviceGetWdfDeviceHandle",
    L"WdfDeviceWdmGetDeviceObject",
    L"WdfDeviceWdmGetAttachedDevice",
    L"WdfDeviceWdmGetPhysicalDevice",
    L"WdfDeviceWdmDispatchPreprocessedIrp",
    L"WdfDeviceAddDependentUsageDeviceObject",
    L"WdfDeviceAddRemovalRelationsPhysicalDevice",
    L"WdfDeviceRemoveRemovalRelationsPhysicalDevice",
    L"WdfDeviceClearRemovalRelationsDevices",
    L"WdfDeviceGetDriver",
    L"WdfDeviceRetrieveDeviceName",
    L"WdfDeviceAssignMofResourceName",
    L"WdfDeviceGetIoTarget",
    L"WdfDeviceGetDevicePnpState",
    L"WdfDeviceGetDevicePowerState",
    L"WdfDeviceGetDevicePowerPolicyState",
    L"WdfDeviceAssignS0IdleSettings",
    L"WdfDeviceAssignSxWakeSettings",
    L"WdfDeviceOpenRegistryKey",
    L"WdfDeviceSetSpecialFileSupport",
    L"WdfDeviceSetCharacteristics",
    L"WdfDeviceGetCharacteristics",
    L"WdfDeviceGetAlignmentRequirement",
    L"WdfDeviceSetAlignmentRequirement",
    L"WdfDeviceInitFree",
    L"WdfDeviceInitSetPnpPowerEventCallbacks",
    L"WdfDeviceInitSetPowerPolicyEventCallbacks",
    L"WdfDeviceInitSetPowerPolicyOwnership",
    L"WdfDeviceInitRegisterPnpStateChangeCallback",
    L"WdfDeviceInitRegisterPowerStateChangeCallback",
    L"WdfDeviceInitRegisterPowerPolicyStateChangeCallback",
    L"WdfDeviceInitSetIoType",
    L"WdfDeviceInitSetExclusive",
    L"WdfDeviceInitSetPowerNotPageable",
    L"WdfDeviceInitSetPowerPageable",
    L"WdfDeviceInitSetPowerInrush",
    L"WdfDeviceInitSetDeviceType",
    L"WdfDeviceInitAssignName",
    L"WdfDeviceInitAssignSDDLString",
    L"WdfDeviceInitSetDeviceClass",
    L"WdfDeviceInitSetCharacteristics",
    L"WdfDeviceInitSetFileObjectConfig",
    L"WdfDeviceInitSetRequestAttributes",
    L"WdfDeviceInitAssignWdmIrpPreprocessCallback",
    L"WdfDeviceInitSetIoInCallerContextCallback",
    L"WdfDeviceCreate",
    L"WdfDeviceSetStaticStopRemove",
    L"WdfDeviceCreateDeviceInterface",
    L"WdfDeviceSetDeviceInterfaceState",
    L"WdfDeviceRetrieveDeviceInterfaceString",
    L"WdfDeviceCreateSymbolicLink",
    L"WdfDeviceQueryProperty",
    L"WdfDeviceAllocAndQueryProperty",
    L"WdfDeviceSetPnpCapabilities",
    L"WdfDeviceSetPowerCapabilities",
    L"WdfDeviceSetBusInformationForChildren",
    L"WdfDeviceIndicateWakeStatus",
    L"WdfDeviceSetFailed",
    L"WdfDeviceStopIdleNoTrack",
    L"WdfDeviceResumeIdleNoTrack",
    L"WdfDeviceGetFileObject",
    L"WdfDeviceEnqueueRequest",
    L"WdfDeviceGetDefaultQueue",
    L"WdfDeviceConfigureRequestDispatching",
    L"WdfDmaEnablerCreate",
    L"WdfDmaEnablerGetMaximumLength",
    L"WdfDmaEnablerGetMaximumScatterGatherElements",
    L"WdfDmaEnablerSetMaximumScatterGatherElements",
    L"WdfDmaTransactionCreate",
    L"WdfDmaTransactionInitialize",
    L"WdfDmaTransactionInitializeUsingRequest",
    L"WdfDmaTransactionExecute",
    L"WdfDmaTransactionRelease",
    L"WdfDmaTransactionDmaCompleted",
    L"WdfDmaTransactionDmaCompletedWithLength",
    L"WdfDmaTransactionDmaCompletedFinal",
    L"WdfDmaTransactionGetBytesTransferred",
    L"WdfDmaTransactionSetMaximumLength",
    L"WdfDmaTransactionGetRequest",
    L"WdfDmaTransactionGetCurrentDmaTransferLength",
    L"WdfDmaTransactionGetDevice",
    L"WdfDpcCreate",
    L"WdfDpcEnqueue",
    L"WdfDpcCancel",
    L"WdfDpcGetParentObject",
    L"WdfDpcWdmGetDpc",
    L"WdfDriverCreate",
    L"WdfDriverGetRegistryPath",
    L"WdfDriverWdmGetDriverObject",
    L"WdfDriverOpenParametersRegistryKey",
    L"WdfWdmDriverGetWdfDriverHandle",
    L"WdfDriverRegisterTraceInfo",
    L"WdfDriverRetrieveVersionString",
    L"WdfDriverIsVersionAvailable",
    L"WdfFdoInitWdmGetPhysicalDevice",
    L"WdfFdoInitOpenRegistryKey",
    L"WdfFdoInitQueryProperty",
    L"WdfFdoInitAllocAndQueryProperty",
    L"WdfFdoInitSetEventCallbacks",
    L"WdfFdoInitSetFilter",
    L"WdfFdoInitSetDefaultChildListConfig",
    L"WdfFdoQueryForInterface",
    L"WdfFdoGetDefaultChildList",
    L"WdfFdoAddStaticChild",
    L"WdfFdoLockStaticChildListForIteration",
    L"WdfFdoRetrieveNextStaticChild",
    L"WdfFdoUnlockStaticChildListFromIteration",
    L"WdfFileObjectGetFileName",
    L"WdfFileObjectGetFlags",
    L"WdfFileObjectGetDevice",
    L"WdfFileObjectWdmGetFileObject",
    L"WdfInterruptCreate",
    L"WdfInterruptQueueDpcForIsr",
    L"WdfInterruptSynchronize",
    L"WdfInterruptAcquireLock",
    L"WdfInterruptReleaseLock",
    L"WdfInterruptEnable",
    L"WdfInterruptDisable",
    L"WdfInterruptWdmGetInterrupt",
    L"WdfInterruptGetInfo",
    L"WdfInterruptSetPolicy",
    L"WdfInterruptGetDevice",
    L"WdfIoQueueCreate",
    L"WdfIoQueueGetState",
    L"WdfIoQueueStart",
    L"WdfIoQueueStop",
    L"WdfIoQueueStopSynchronously",
    L"WdfIoQueueGetDevice",
    L"WdfIoQueueRetrieveNextRequest",
    L"WdfIoQueueRetrieveRequestByFileObject",
    L"WdfIoQueueFindRequest",
    L"WdfIoQueueRetrieveFoundRequest",
    L"WdfIoQueueDrainSynchronously",
    L"WdfIoQueueDrain",
    L"WdfIoQueuePurgeSynchronously",
    L"WdfIoQueuePurge",
    L"WdfIoQueueReadyNotify",
    L"WdfIoTargetCreate",
    L"WdfIoTargetOpen",
    L"WdfIoTargetCloseForQueryRemove",
    L"WdfIoTargetClose",
    L"WdfIoTargetStart",
    L"WdfIoTargetStop",
    L"WdfIoTargetGetState",
    L"WdfIoTargetGetDevice",
    L"WdfIoTargetQueryTargetProperty",
    L"WdfIoTargetAllocAndQueryTargetProperty",
    L"WdfIoTargetQueryForInterface",
    L"WdfIoTargetWdmGetTargetDeviceObject",
    L"WdfIoTargetWdmGetTargetPhysicalDevice",
    L"WdfIoTargetWdmGetTargetFileObject",
    L"WdfIoTargetWdmGetTargetFileHandle",
    L"WdfIoTargetSendReadSynchronously",
    L"WdfIoTargetFormatRequestForRead",
    L"WdfIoTargetSendWriteSynchronously",
    L"WdfIoTargetFormatRequestForWrite",
    L"WdfIoTargetSendIoctlSynchronously",
    L"WdfIoTargetFormatRequestForIoctl",
    L"WdfIoTargetSendInternalIoctlSynchronously",
    L"WdfIoTargetFormatRequestForInternalIoctl",
    L"WdfIoTargetSendInternalIoctlOthersSynchronously",
    L"WdfIoTargetFormatRequestForInternalIoctlOthers",
    L"WdfMemoryCreate",
    L"WdfMemoryCreatePreallocated",
    L"WdfMemoryGetBuffer",
    L"WdfMemoryAssignBuffer",
    L"WdfMemoryCopyToBuffer",
    L"WdfMemoryCopyFromBuffer",
    L"WdfLookasideListCreate",
    L"WdfMemoryCreateFromLookaside",
    L"WdfDeviceMiniportCreate",
    L"WdfDriverMiniportUnload",
    L"WdfObjectGetTypedContextWorker",
    L"WdfObjectAllocateContext",
    L"WdfObjectContextGetObject",
    L"WdfObjectReferenceActual",
    L"WdfObjectDereferenceActual",
    L"WdfObjectCreate",
    L"WdfObjectDelete",
    L"WdfObjectQuery",
    L"WdfPdoInitAllocate",
    L"WdfPdoInitSetEventCallbacks",
    L"WdfPdoInitAssignDeviceID",
    L"WdfPdoInitAssignInstanceID",
    L"WdfPdoInitAddHardwareID",
    L"WdfPdoInitAddCompatibleID",
    L"WdfPdoInitAddDeviceText",
    L"WdfPdoInitSetDefaultLocale",
    L"WdfPdoInitAssignRawDevice",
    L"WdfPdoMarkMissing",
    L"WdfPdoRequestEject",
    L"WdfPdoGetParent",
    L"WdfPdoRetrieveIdentificationDescription",
    L"WdfPdoRetrieveAddressDescription",
    L"WdfPdoUpdateAddressDescription",
    L"WdfPdoAddEjectionRelationsPhysicalDevice",
    L"WdfPdoRemoveEjectionRelationsPhysicalDevice",
    L"WdfPdoClearEjectionRelationsDevices",
    L"WdfDeviceAddQueryInterface",
    L"WdfRegistryOpenKey",
    L"WdfRegistryCreateKey",
    L"WdfRegistryClose",
    L"WdfRegistryWdmGetHandle",
    L"WdfRegistryRemoveKey",
    L"WdfRegistryRemoveValue",
    L"WdfRegistryQueryValue",
    L"WdfRegistryQueryMemory",
    L"WdfRegistryQueryMultiString",
    L"WdfRegistryQueryUnicodeString",
    L"WdfRegistryQueryString",
    L"WdfRegistryQueryULong",
    L"WdfRegistryAssignValue",
    L"WdfRegistryAssignMemory",
    L"WdfRegistryAssignMultiString",
    L"WdfRegistryAssignUnicodeString",
    L"WdfRegistryAssignString",
    L"WdfRegistryAssignULong",
    L"WdfRequestCreate",
    L"WdfRequestCreateFromIrp",
    L"WdfRequestReuse",
    L"WdfRequestChangeTarget",
    L"WdfRequestFormatRequestUsingCurrentType",
    L"WdfRequestWdmFormatUsingStackLocation",
    L"WdfRequestSend",
    L"WdfRequestGetStatus",
    L"WdfRequestMarkCancelable",
    L"WdfRequestUnmarkCancelable",
    L"WdfRequestIsCanceled",
    L"WdfRequestCancelSentRequest",
    L"WdfRequestIsFrom32BitProcess",
    L"WdfRequestSetCompletionRoutine",
    L"WdfRequestGetCompletionParams",
    L"WdfRequestAllocateTimer",
    L"WdfRequestComplete",
    L"WdfRequestCompleteWithPriorityBoost",
    L"WdfRequestCompleteWithInformation",
    L"WdfRequestGetParameters",
    L"WdfRequestRetrieveInputMemory",
    L"WdfRequestRetrieveOutputMemory",
    L"WdfRequestRetrieveInputBuffer",
    L"WdfRequestRetrieveOutputBuffer",
    L"WdfRequestRetrieveInputWdmMdl",
    L"WdfRequestRetrieveOutputWdmMdl",
    L"WdfRequestRetrieveUnsafeUserInputBuffer",
    L"WdfRequestRetrieveUnsafeUserOutputBuffer",
    L"WdfRequestSetInformation",
    L"WdfRequestGetInformation",
    L"WdfRequestGetFileObject",
    L"WdfRequestProbeAndLockUserBufferForRead",
    L"WdfRequestProbeAndLockUserBufferForWrite",
    L"WdfRequestGetRequestorMode",
    L"WdfRequestForwardToIoQueue",
    L"WdfRequestGetIoQueue",
    L"WdfRequestRequeue",
    L"WdfRequestStopAcknowledge",
    L"WdfRequestWdmGetIrp",
    L"WdfIoResourceRequirementsListSetSlotNumber",
    L"WdfIoResourceRequirementsListSetInterfaceType",
    L"WdfIoResourceRequirementsListAppendIoResList",
    L"WdfIoResourceRequirementsListInsertIoResList",
    L"WdfIoResourceRequirementsListGetCount",
    L"WdfIoResourceRequirementsListGetIoResList",
    L"WdfIoResourceRequirementsListRemove",
    L"WdfIoResourceRequirementsListRemoveByIoResList",
    L"WdfIoResourceListCreate",
    L"WdfIoResourceListAppendDescriptor",
    L"WdfIoResourceListInsertDescriptor",
    L"WdfIoResourceListUpdateDescriptor",
    L"WdfIoResourceListGetCount",
    L"WdfIoResourceListGetDescriptor",
    L"WdfIoResourceListRemove",
    L"WdfIoResourceListRemoveByDescriptor",
    L"WdfCmResourceListAppendDescriptor",
    L"WdfCmResourceListInsertDescriptor",
    L"WdfCmResourceListGetCount",
    L"WdfCmResourceListGetDescriptor",
    L"WdfCmResourceListRemove",
    L"WdfCmResourceListRemoveByDescriptor",
    L"WdfStringCreate",
    L"WdfStringGetUnicodeString",
    L"WdfObjectAcquireLock",
    L"WdfObjectReleaseLock",
    L"WdfWaitLockCreate",
    L"WdfWaitLockAcquire",
    L"WdfWaitLockRelease",
    L"WdfSpinLockCreate",
    L"WdfSpinLockAcquire",
    L"WdfSpinLockRelease",
    L"WdfTimerCreate",
    L"WdfTimerStart",
    L"WdfTimerStop",
    L"WdfTimerGetParentObject",
    L"WdfUsbTargetDeviceCreate",
    L"WdfUsbTargetDeviceRetrieveInformation",
    L"WdfUsbTargetDeviceGetDeviceDescriptor",
    L"WdfUsbTargetDeviceRetrieveConfigDescriptor",
    L"WdfUsbTargetDeviceQueryString",
    L"WdfUsbTargetDeviceAllocAndQueryString",
    L"WdfUsbTargetDeviceFormatRequestForString",
    L"WdfUsbTargetDeviceGetNumInterfaces",
    L"WdfUsbTargetDeviceSelectConfig",
    L"WdfUsbTargetDeviceWdmGetConfigurationHandle",
    L"WdfUsbTargetDeviceRetrieveCurrentFrameNumber",
    L"WdfUsbTargetDeviceSendControlTransferSynchronously",
    L"WdfUsbTargetDeviceFormatRequestForControlTransfer",
    L"WdfUsbTargetDeviceIsConnectedSynchronous",
    L"WdfUsbTargetDeviceResetPortSynchronously",
    L"WdfUsbTargetDeviceCyclePortSynchronously",
    L"WdfUsbTargetDeviceFormatRequestForCyclePort",
    L"WdfUsbTargetDeviceSendUrbSynchronously",
    L"WdfUsbTargetDeviceFormatRequestForUrb",
    L"WdfUsbTargetPipeGetInformation",
    L"WdfUsbTargetPipeIsInEndpoint",
    L"WdfUsbTargetPipeIsOutEndpoint",
    L"WdfUsbTargetPipeGetType",
    L"WdfUsbTargetPipeSetNoMaximumPacketSizeCheck",
    L"WdfUsbTargetPipeWriteSynchronously",
    L"WdfUsbTargetPipeFormatRequestForWrite",
    L"WdfUsbTargetPipeReadSynchronously",
    L"WdfUsbTargetPipeFormatRequestForRead",
    L"WdfUsbTargetPipeConfigContinuousReader",
    L"WdfUsbTargetPipeAbortSynchronously",
    L"WdfUsbTargetPipeFormatRequestForAbort",
    L"WdfUsbTargetPipeResetSynchronously",
    L"WdfUsbTargetPipeFormatRequestForReset",
    L"WdfUsbTargetPipeSendUrbSynchronously",
    L"WdfUsbTargetPipeFormatRequestForUrb",
    L"WdfUsbInterfaceGetInterfaceNumber",
    L"WdfUsbInterfaceGetNumEndpoints",
    L"WdfUsbInterfaceGetDescriptor",
    L"WdfUsbInterfaceSelectSetting",
    L"WdfUsbInterfaceGetEndpointInformation",
    L"WdfUsbTargetDeviceGetInterface",
    L"WdfUsbInterfaceGetConfiguredSettingIndex",
    L"WdfUsbInterfaceGetNumConfiguredPipes",
    L"WdfUsbInterfaceGetConfiguredPipe",
    L"WdfUsbTargetPipeWdmGetPipeHandle",
    L"WdfVerifierDbgBreakPoint",
    L"WdfVerifierKeBugCheck",
    L"WdfWmiProviderCreate",
    L"WdfWmiProviderGetDevice",
    L"WdfWmiProviderIsEnabled",
    L"WdfWmiProviderGetTracingHandle",
    L"WdfWmiInstanceCreate",
    L"WdfWmiInstanceRegister",
    L"WdfWmiInstanceDeregister",
    L"WdfWmiInstanceGetDevice",
    L"WdfWmiInstanceGetProvider",
    L"WdfWmiInstanceFireEvent",
    L"WdfWorkItemCreate",
    L"WdfWorkItemEnqueue",
    L"WdfWorkItemGetParentObject",
    L"WdfWorkItemFlush",
    L"WdfCommonBufferCreateWithConfig",
    L"WdfDmaEnablerGetFragmentLength",
    L"WdfDmaEnablerWdmGetDmaAdapter",
    L"WdfUsbInterfaceGetNumSettings",
    L"WdfDeviceRemoveDependentUsageDeviceObject",
    L"WdfDeviceGetSystemPowerAction",
    L"WdfInterruptSetExtendedPolicy",
    L"WdfIoQueueAssignForwardProgressPolicy",
    L"WdfPdoInitAssignContainerID",
    L"WdfPdoInitAllowForwardingRequestToParent",
    L"WdfRequestMarkCancelableEx",
    L"WdfRequestIsReserved",
    L"WdfRequestForwardToParentDeviceIoQueue",
    L"WdfCxDeviceInitAllocate",
    L"WdfCxDeviceInitAssignWdmIrpPreprocessCallback",
    L"WdfCxDeviceInitSetIoInCallerContextCallback",
    L"WdfCxDeviceInitSetRequestAttributes",
    L"WdfCxDeviceInitSetFileObjectConfig",
    L"WdfDeviceWdmDispatchIrp",
    L"WdfDeviceWdmDispatchIrpToIoQueue",
    L"WdfDeviceInitSetRemoveLockOptions",
    L"WdfDeviceConfigureWdmIrpDispatchCallback",
    L"WdfDmaEnablerConfigureSystemProfile",
    L"WdfDmaTransactionInitializeUsingOffset",
    L"WdfDmaTransactionGetTransferInfo",
    L"WdfDmaTransactionSetChannelConfigurationCallback",
    L"WdfDmaTransactionSetTransferCompleteCallback",
    L"WdfDmaTransactionSetImmediateExecution",
    L"WdfDmaTransactionAllocateResources",
    L"WdfDmaTransactionSetDeviceAddressOffset",
    L"WdfDmaTransactionFreeResources",
    L"WdfDmaTransactionCancel",
    L"WdfDmaTransactionWdmGetTransferContext",
    L"WdfInterruptQueueWorkItemForIsr",
    L"WdfInterruptTryToAcquireLock",
    L"WdfIoQueueStopAndPurge",
    L"WdfIoQueueStopAndPurgeSynchronously",
    L"WdfIoTargetPurge",
    L"WdfUsbTargetDeviceCreateWithParameters",
    L"WdfUsbTargetDeviceQueryUsbCapability",
    L"WdfUsbTargetDeviceCreateUrb",
    L"WdfUsbTargetDeviceCreateIsochUrb",
    L"WdfDeviceWdmAssignPowerFrameworkSettings",
    L"WdfDmaTransactionStopSystemTransfer",
    L"WdfCxVerifierKeBugCheck",
    L"WdfInterruptReportActive",
    L"WdfInterruptReportInactive",
    L"WdfDeviceInitSetReleaseHardwareOrderOnFailure",
    L"WdfGetTriageInfo",
    L"WdfDeviceInitSetIoTypeEx",
    L"WdfDeviceQueryPropertyEx",
    L"WdfDeviceAllocAndQueryPropertyEx",
    L"WdfDeviceAssignProperty",
    L"WdfFdoInitQueryPropertyEx",
    L"WdfFdoInitAllocAndQueryPropertyEx",
    L"WdfDeviceStopIdleActual",
    L"WdfDeviceResumeIdleActual",
    L"WdfDeviceGetSelfIoTarget",
    L"WdfDeviceInitAllowSelfIoTarget",
    L"WdfIoTargetSelfAssignDefaultIoQueue",
    L"WdfDeviceOpenDevicemapKey"
};
C_ASSERT(RTL_NUMBER_OF(g_KswWdfFunctionNames) == WdfFunctionTableNumEntries);

static const KSW_PLATFORM_CALLBACK_DESCRIPTOR g_KswWdfCallbacks[] = {
    { (PVOID)KswordARKDriverEvtDriverUnload, L"KswordARKDriverEvtDriverUnload" },
    { (PVOID)KswordARKDriverEvtDriverContextCleanup, L"KswordARKDriverEvtDriverContextCleanup" },
    { (PVOID)KswordARKDriverEvtIoDeviceControl, L"KswordARKDriverEvtIoDeviceControl" },
    { (PVOID)KswordARKDriverEvtIoRead, L"KswordARKDriverEvtIoRead" },
    { (PVOID)KswordARKDriverEvtIoStop, L"KswordARKDriverEvtIoStop" },
    { (PVOID)KswordARKDriverEvtDevicePrepareHardware, L"KswordARKDriverEvtDevicePrepareHardware" }
};

static VOID
KswPlatformCopyWide(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ PCWSTR Source
    )
{
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    Destination[0] = L'\0';
    if (Source != NULL) {
        (VOID)RtlStringCchCopyNW(Destination, DestinationChars, Source, DestinationChars - 1UL);
    }
}

static PVOID
KswPlatformGetRoutine(
    _In_z_ PCWSTR RoutineName
    )
{
    UNICODE_STRING routineNameString;

    if (RoutineName == NULL) {
        return NULL;
    }
    RtlInitUnicodeString(&routineNameString, RoutineName);
    return MmGetSystemRoutineAddress(&routineNameString);
}

static BOOLEAN
KswPlatformModuleNameEquals(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_z_ PCSTR ExpectedName
    )
{
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;

    if (Module == NULL || ExpectedName == NULL) {
        return FALSE;
    }
    KswordARKHookGetModuleFileName(Module, &fileName, &fileNameBytes);
    return KswordARKHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, ExpectedName);
}

static BOOLEAN
KswPlatformIsExpectedHalOwner(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module
    )
{
    return KswPlatformModuleNameEquals(Module, "ntoskrnl.exe") ||
        KswPlatformModuleNameEquals(Module, "ntkrnlmp.exe") ||
        KswPlatformModuleNameEquals(Module, "ntkrnlpa.exe") ||
        KswPlatformModuleNameEquals(Module, "ntkrpamp.exe") ||
        KswPlatformModuleNameEquals(Module, "hal.dll");
}

static BOOLEAN
KswPlatformOwnerMatchesPolicy(
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_ ULONG OwnerPolicy
    )
{
    switch (OwnerPolicy) {
    case KSWORD_ARK_PLATFORM_OWNER_NT_HAL:
        return KswPlatformIsExpectedHalOwner(Module);
    case KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI:
        return KswPlatformIsExpectedHalOwner(Module) ||
            KswPlatformModuleNameEquals(Module, "pci.sys");
    case KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI:
        return KswPlatformIsExpectedHalOwner(Module) ||
            KswPlatformModuleNameEquals(Module, "ACPI.sys");
    case KSWORD_ARK_PLATFORM_OWNER_WDF:
        return KswPlatformModuleNameEquals(Module, "Wdf01000.sys");
    case KSWORD_ARK_PLATFORM_OWNER_KSWORD:
        return KswPlatformModuleNameEquals(Module, "KswordARK.sys");
    default:
        return FALSE;
    }
}

static VOID
KswPlatformFillModule(
    _Inout_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* Entry,
    _In_opt_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module
    )
{
    if (Entry == NULL || Module == NULL) {
        return;
    }

    Entry->moduleBase = (ULONGLONG)(ULONG_PTR)Module->ImageBase;
    Entry->moduleSize = Module->ImageSize;
    Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_MODULE;
    KswordARKHookCopyBoundedAnsiToWide(
        Module->FullPathName,
        RTL_NUMBER_OF(Module->FullPathName),
        Entry->modulePath,
        RTL_NUMBER_OF(Entry->modulePath));
}

static BOOLEAN
KswPlatformAddressSectionMatches(
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_ ULONG_PTR Address,
    _In_ BOOLEAN RequireExecutable
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionIndex = 0UL;
    ULONG sectionTableRva = 0UL;

    if (Module == NULL ||
        Address < (ULONG_PTR)Module->ImageBase ||
        Address >= ((ULONG_PTR)Module->ImageBase + Module->ImageSize)) {
        return FALSE;
    }
    if (!KswordARKHookReadMemorySafe(Module->ImageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        !KswordARKHookValidateRvaRange((ULONG)dosHeader.e_lfanew, sizeof(ntHeaders), Module->ImageSize) ||
        !KswordARKHookReadMemorySafe(
            (const UCHAR*)Module->ImageBase + (ULONG)dosHeader.e_lfanew,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > 96U) {
        return FALSE;
    }

    sectionTableRva = (ULONG)dosHeader.e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    for (sectionIndex = 0UL; sectionIndex < ntHeaders.FileHeader.NumberOfSections; ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG currentRva = sectionTableRva + (sectionIndex * sizeof(IMAGE_SECTION_HEADER));
        ULONG span = 0UL;
        ULONG_PTR startAddress = 0U;
        ULONG_PTR endAddress = 0U;
        BOOLEAN executable = FALSE;

        if (!KswordARKHookValidateRvaRange(currentRva, sizeof(sectionHeader), Module->ImageSize) ||
            !KswordARKHookReadMemorySafe(
                (const UCHAR*)Module->ImageBase + currentRva,
                &sectionHeader,
                sizeof(sectionHeader))) {
            return FALSE;
        }

        span = sectionHeader.Misc.VirtualSize;
        if (span < sectionHeader.SizeOfRawData) {
            span = sectionHeader.SizeOfRawData;
        }
        if (span == 0UL ||
            !KswordARKHookValidateRvaRange(sectionHeader.VirtualAddress, span, Module->ImageSize)) {
            continue;
        }

        startAddress = (ULONG_PTR)Module->ImageBase + sectionHeader.VirtualAddress;
        endAddress = startAddress + span;
        executable = (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL;
        if (Address >= startAddress &&
            Address < endAddress &&
            executable == RequireExecutable) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KswPlatformRangeInSection(
    _In_ const KSW_HOOK_SYSTEM_MODULE_ENTRY* Module,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T ByteCount,
    _In_ BOOLEAN RequireExecutable,
    _In_ BOOLEAN RequireReadOnly
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionIndex = 0UL;
    ULONG sectionTableRva = 0UL;
    ULONG_PTR rangeEnd = 0U;

    if (Module == NULL || ByteCount == 0U ||
        Address < (ULONG_PTR)Module->ImageBase ||
        Address > MAXULONG_PTR - ByteCount) {
        return FALSE;
    }
    rangeEnd = Address + ByteCount;
    if (rangeEnd > (ULONG_PTR)Module->ImageBase + Module->ImageSize) {
        return FALSE;
    }
    if (!KswordARKHookReadMemorySafe(Module->ImageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        !KswordARKHookValidateRvaRange((ULONG)dosHeader.e_lfanew, sizeof(ntHeaders), Module->ImageSize) ||
        !KswordARKHookReadMemorySafe(
            (const UCHAR*)Module->ImageBase + (ULONG)dosHeader.e_lfanew,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > 96U) {
        return FALSE;
    }

    sectionTableRva = (ULONG)dosHeader.e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    for (sectionIndex = 0UL; sectionIndex < ntHeaders.FileHeader.NumberOfSections; ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG currentRva = sectionTableRva + (sectionIndex * sizeof(IMAGE_SECTION_HEADER));
        ULONG span = 0UL;
        ULONG_PTR sectionStart = 0U;
        ULONG_PTR sectionEnd = 0U;
        BOOLEAN executable = FALSE;
        BOOLEAN writable = FALSE;

        if (!KswordARKHookValidateRvaRange(currentRva, sizeof(sectionHeader), Module->ImageSize) ||
            !KswordARKHookReadMemorySafe(
                (const UCHAR*)Module->ImageBase + currentRva,
                &sectionHeader,
                sizeof(sectionHeader))) {
            return FALSE;
        }
        span = sectionHeader.Misc.VirtualSize;
        if (span < sectionHeader.SizeOfRawData) {
            span = sectionHeader.SizeOfRawData;
        }
        if (span == 0UL ||
            !KswordARKHookValidateRvaRange(sectionHeader.VirtualAddress, span, Module->ImageSize)) {
            continue;
        }
        sectionStart = (ULONG_PTR)Module->ImageBase + sectionHeader.VirtualAddress;
        sectionEnd = sectionStart + span;
        executable = (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL;
        writable = (sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE) != 0UL;
        if (Address >= sectionStart && rangeEnd <= sectionEnd &&
            executable == RequireExecutable &&
            (!RequireReadOnly || !writable)) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
KswPlatformAddSignedDisplacement(
    _In_ ULONG64 Base,
    _In_ LONGLONG Displacement,
    _Out_ ULONG64* ResultOut
    );

static BOOLEAN
KswPlatformDecodeDetourTarget(
    _In_ ULONG64 Address,
    _Out_ ULONG64* TargetOut
    )
{
    UCHAR codeBytes[16];
    ULONG offset = 0UL;

    if (TargetOut == NULL || Address == 0ULL) {
        return FALSE;
    }
    *TargetOut = 0ULL;
    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    if (!KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)Address, codeBytes, sizeof(codeBytes))) {
        return FALSE;
    }

    if (codeBytes[0] == 0xF3U && codeBytes[1] == 0x0FU &&
        codeBytes[2] == 0x1EU && codeBytes[3] == 0xFAU) {
        offset = 4UL;
    }

    if (codeBytes[offset] == 0xE9U) {
        LONG displacement = 0;
        ULONG64 instructionEnd = 0ULL;
        RtlCopyMemory(&displacement, &codeBytes[offset + 1UL], sizeof(displacement));
        if (Address > MAXULONGLONG - offset - 5ULL) {
            return FALSE;
        }
        instructionEnd = Address + offset + 5ULL;
        return KswPlatformAddSignedDisplacement(
            instructionEnd,
            (LONGLONG)displacement,
            TargetOut);
    }
    if (codeBytes[offset] == 0xEBU) {
        CHAR displacement8 = (CHAR)codeBytes[offset + 1UL];
        ULONG64 instructionEnd = 0ULL;
        if (Address > MAXULONGLONG - offset - 2ULL) {
            return FALSE;
        }
        instructionEnd = Address + offset + 2ULL;
        return KswPlatformAddSignedDisplacement(
            instructionEnd,
            (LONGLONG)displacement8,
            TargetOut);
    }
    if (codeBytes[offset] == 0xFFU && codeBytes[offset + 1UL] == 0x25U) {
        LONG displacement = 0;
        ULONG64 pointerAddress = 0ULL;
        ULONG64 instructionEnd = 0ULL;
        RtlCopyMemory(&displacement, &codeBytes[offset + 2UL], sizeof(displacement));
        if (Address > MAXULONGLONG - offset - 6ULL) {
            return FALSE;
        }
        instructionEnd = Address + offset + 6ULL;
        if (!KswPlatformAddSignedDisplacement(
                instructionEnd,
                (LONGLONG)displacement,
                &pointerAddress)) {
            return FALSE;
        }
        return KswordARKHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)pointerAddress,
            TargetOut,
            sizeof(*TargetOut));
    }
    if (codeBytes[offset] == 0x48U && codeBytes[offset + 1UL] == 0xB8U &&
        codeBytes[offset + 10UL] == 0xFFU && codeBytes[offset + 11UL] == 0xE0U) {
        RtlCopyMemory(TargetOut, &codeBytes[offset + 2UL], sizeof(*TargetOut));
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN
KswPlatformAddSignedDisplacement(
    _In_ ULONG64 Base,
    _In_ LONGLONG Displacement,
    _Out_ ULONG64* ResultOut
    )
{
    ULONG64 magnitude = 0ULL;

    if (ResultOut == NULL) {
        return FALSE;
    }
    *ResultOut = 0ULL;
    if (Displacement >= 0) {
        magnitude = (ULONG64)Displacement;
        if (Base > MAXULONGLONG - magnitude) {
            return FALSE;
        }
        *ResultOut = Base + magnitude;
        return TRUE;
    }

    // 中文说明：避免直接对最小 LONGLONG 取负导致有符号溢出。
    magnitude = (ULONG64)(-(Displacement + 1LL)) + 1ULL;
    if (Base < magnitude) {
        return FALSE;
    }
    *ResultOut = Base - magnitude;
    return TRUE;
}

typedef struct _KSW_PLATFORM_MASKED_SIGNATURE
{
    UCHAR Bytes[12];
    UCHAR Mask[12];
    ULONG Length;
    ULONG Identifier;
} KSW_PLATFORM_MASKED_SIGNATURE;

static const KSW_PLATFORM_MASKED_SIGNATURE g_KswX64PrologueSignatures[] = {
    { { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x57, 0x48, 0x83, 0xEC, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      10UL, 1UL },
    { { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      6UL, 2UL },
    { { 0x48, 0x83, 0xEC, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0x00 },
      4UL, 3UL },
    { { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x5B, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      7UL, 4UL },
    { { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      7UL, 5UL },
    { { 0x48, 0x89, 0x5C, 0x24, 0x00, 0x48, 0x89, 0x6C, 0x24, 0x00 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 },
      10UL, 6UL },
    { { 0x48, 0x8B, 0xC4, 0x55, 0x53, 0x56, 0x57 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
      7UL, 7UL },
    { { 0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54 },
      { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
      7UL, 8UL }
};

static BOOLEAN
KswPlatformMaskedBytesMatch(
    _In_reads_(ByteCount) const UCHAR* Data,
    _In_reads_(ByteCount) const UCHAR* Bytes,
    _In_reads_(ByteCount) const UCHAR* Mask,
    _In_ ULONG ByteCount
    )
{
    ULONG index = 0UL;

    if (Data == NULL || Bytes == NULL || Mask == NULL || ByteCount == 0UL) {
        return FALSE;
    }
    for (index = 0UL; index < ByteCount; ++index) {
        if ((Data[index] & Mask[index]) != (Bytes[index] & Mask[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
KswPlatformIdentifyX64Prologue(
    _In_ ULONG64 Address,
    _Out_ ULONG* SignatureIdOut
    )
{
    UCHAR bytes[20];
    ULONG codeOffset = 0UL;
    ULONG index = 0UL;
    ULONG matchedCount = 0UL;
    ULONG matchedId = 0UL;

    if (SignatureIdOut == NULL) {
        return FALSE;
    }
    *SignatureIdOut = 0UL;
    RtlZeroMemory(bytes, sizeof(bytes));
    if (Address == 0ULL ||
        !KswordARKHookReadMemorySafe((const VOID*)(ULONG_PTR)Address, bytes, sizeof(bytes))) {
        return FALSE;
    }
    if (bytes[0] == 0xF3U && bytes[1] == 0x0FU &&
        bytes[2] == 0x1EU && bytes[3] == 0xFAU) {
        codeOffset = 4UL;
    }

    // 中文说明：每个模式都是真实字节 + mask，且只检查函数头固定 20 字节。
    // 只有恰好一个模式命中才接受；多命中与零命中都按未知版本失败关闭。
    for (index = 0UL; index < RTL_NUMBER_OF(g_KswX64PrologueSignatures); ++index) {
        const KSW_PLATFORM_MASKED_SIGNATURE* signature =
            &g_KswX64PrologueSignatures[index];
        if (codeOffset + signature->Length > sizeof(bytes)) {
            continue;
        }
        if (KswPlatformMaskedBytesMatch(
                bytes + codeOffset,
                signature->Bytes,
                signature->Mask,
                signature->Length)) {
            matchedCount += 1UL;
            matchedId = signature->Identifier;
        }
    }
    if (matchedCount != 1UL) {
        return FALSE;
    }
    *SignatureIdOut = matchedId;
    return TRUE;
}

static VOID
KswPlatformSetDetail(
    _Inout_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* Entry,
    _In_ ULONG DetailCode,
    _In_ ULONGLONG Arg0,
    _In_ ULONGLONG Arg1,
    _In_ ULONGLONG Arg2,
    _In_ ULONGLONG Arg3
    )
{
    if (Entry == NULL) {
        return;
    }
    Entry->detailCode = DetailCode;
    Entry->detailArgs[0] = Arg0;
    Entry->detailArgs[1] = Arg1;
    Entry->detailArgs[2] = Arg2;
    Entry->detailArgs[3] = Arg3;
    if (DetailCode != KSWORD_ARK_PLATFORM_DETAIL_NONE) {
        Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_DETAIL_ARGS;
    }
}

static VOID
KswPlatformClassifyFunction(
    _Inout_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* Entry,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONG OwnerPolicy
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* owner = NULL;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* detourOwner = NULL;
    ULONG64 detourTarget = 0ULL;
    BOOLEAN ownerExpected = FALSE;
    BOOLEAN executable = FALSE;
    ULONG prologueSignatureId = 0UL;

    if (Entry == NULL || Entry->liveAddress == 0ULL) {
        return;
    }

    owner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)Entry->liveAddress);
    KswPlatformFillModule(Entry, owner);
    executable = owner != NULL &&
        KswPlatformAddressSectionMatches(owner, (ULONG_PTR)Entry->liveAddress, TRUE);
    Entry->ownerPolicy = OwnerPolicy;
    ownerExpected = KswPlatformOwnerMatchesPolicy(owner, OwnerPolicy);

    if (ownerExpected) {
        Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED;
    }
    if (!ownerExpected) {
        Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
        Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
        Entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
        Entry->lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        KswPlatformSetDetail(
            Entry,
            KSWORD_ARK_PLATFORM_DETAIL_OWNER_MISMATCH,
            Entry->liveAddress,
            Entry->moduleBase,
            OwnerPolicy,
            0ULL);
        return;
    }
    if (!executable) {
        Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
        Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
        Entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
        Entry->lastStatus = STATUS_INVALID_ADDRESS;
        KswPlatformSetDetail(
            Entry,
            KSWORD_ARK_PLATFORM_DETAIL_NON_EXECUTABLE,
            Entry->liveAddress,
            Entry->moduleBase,
            OwnerPolicy,
            0ULL);
        return;
    }
    Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_EXECUTABLE_VALIDATED;

    if (KswPlatformDecodeDetourTarget(Entry->liveAddress, &detourTarget)) {
        detourOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)detourTarget);
        if (!KswPlatformOwnerMatchesPolicy(detourOwner, OwnerPolicy)) {
            Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS;
            Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH;
            Entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH;
            Entry->lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
            KswPlatformSetDetail(
                Entry,
                KSWORD_ARK_PLATFORM_DETAIL_DETOUR_EXTERNAL,
                Entry->liveAddress,
                detourTarget,
                OwnerPolicy,
                0ULL);
        }
        else {
            Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
            Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM;
            KswPlatformSetDetail(
                Entry,
                KSWORD_ARK_PLATFORM_DETAIL_DETOUR_SAME_OWNER,
                Entry->liveAddress,
                detourTarget,
                OwnerPolicy,
                0ULL);
        }
        return;
    }

    if (KswPlatformIdentifyX64Prologue(Entry->liveAddress, &prologueSignatureId)) {
        Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT;
        Entry->prologueSignatureId = prologueSignatureId;
        Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
        Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM;
        KswPlatformSetDetail(
            Entry,
            KSWORD_ARK_PLATFORM_DETAIL_FORMAT_RECOGNIZED,
            prologueSignatureId,
            OwnerPolicy,
            0ULL,
            0ULL);
    }
    else {
        Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
        Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_LOW;
        KswPlatformSetDetail(
            Entry,
            KSWORD_ARK_PLATFORM_DETAIL_FORMAT_UNKNOWN,
            OwnerPolicy,
            0ULL,
            0ULL,
            0ULL);
    }
}

static ULONG
KswPlatformOutputCapacity(
    _In_ size_t OutputBytes
    )
{
    size_t payloadBytes = 0U;
    size_t capacity = 0U;

    if (OutputBytes <= KSW_PLATFORM_RESPONSE_HEADER_SIZE) {
        return 0UL;
    }
    payloadBytes = OutputBytes - KSW_PLATFORM_RESPONSE_HEADER_SIZE;
    capacity = payloadBytes / sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY);
    if (capacity > MAXULONG) {
        return MAXULONG;
    }
    return (ULONG)capacity;
}

static VOID
KswPlatformAppend(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSWORD_ARK_PLATFORM_AUDIT_ENTRY* Entry
    )
{
    if (Response == NULL || Entry == NULL) {
        return;
    }
    Response->totalCount += 1UL;
    if (Response->returnedCount >= Capacity || Response->returnedCount >= MaxRows) {
        Response->responseFlags |= KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED |
            KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL;
        Response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL;
        Response->lastStatus = STATUS_BUFFER_OVERFLOW;
        return;
    }
    Response->entries[Response->returnedCount] = *Entry;
    Response->returnedCount += 1UL;
    if (Entry->status != KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK) {
        Response->responseFlags |= KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL;
        if (Response->queryStatus == KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK) {
            Response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL;
        }
    }
}

static VOID
KswPlatformAddDiagnostic(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ ULONG Scope,
    _In_ ULONG Status,
    _In_ NTSTATUS LastStatus,
    _In_z_ PCWSTR Name,
    _In_ ULONG DetailCode,
    _In_ ULONGLONG DetailArg0,
    _In_ ULONGLONG DetailArg1
    )
{
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

    RtlZeroMemory(&entry, sizeof(entry));
    entry.size = sizeof(entry);
    entry.scope = Scope;
    entry.rowKind = KSWORD_ARK_PLATFORM_AUDIT_ROW_DIAGNOSTIC;
    entry.status = Status;
    entry.hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNSUPPORTED;
    entry.confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_NONE;
    entry.signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY;
    entry.lastStatus = LastStatus;
    KswPlatformCopyWide(entry.name, RTL_NUMBER_OF(entry.name), Name);
    KswPlatformSetDetail(&entry, DetailCode, DetailArg0, DetailArg1, 0ULL, 0ULL);
    KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    Response->responseFlags |= KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL |
        KSWORD_ARK_PLATFORM_RESPONSE_FAIL_CLOSED;
    if (Response->queryStatus == KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK) {
        Response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL;
    }
    Response->lastStatus = LastStatus;
}





static VOID
KswPlatformInitializeEntry(
    _Out_ KSWORD_ARK_PLATFORM_AUDIT_ENTRY* Entry,
    _In_ ULONG Scope,
    _In_ ULONG RowKind,
    _In_ ULONG SignatureId,
    _In_ ULONG SlotKind,
    _In_ ULONG OwnerPolicy,
    _In_ ULONG EntryIndex,
    _In_opt_ PVOID TableAddress,
    _In_z_ PCWSTR Name
    )
{
    RtlZeroMemory(Entry, sizeof(*Entry));
    Entry->size = sizeof(*Entry);
    Entry->scope = Scope;
    Entry->rowKind = RowKind;
    Entry->status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK;
    Entry->hookStatus = KSWORD_ARK_PLATFORM_HOOK_UNKNOWN;
    Entry->confidence = KSWORD_ARK_PLATFORM_CONFIDENCE_NONE;
    Entry->signatureId = SignatureId;
    Entry->slotKind = SlotKind;
    Entry->ownerPolicy = OwnerPolicy;
    Entry->entryIndex = EntryIndex;
    Entry->lastStatus = STATUS_SUCCESS;
    if (TableAddress != NULL) {
        Entry->tableAddress = (ULONGLONG)(ULONG_PTR)TableAddress;
        Entry->fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS;
    }
    KswPlatformCopyWide(Entry->name, RTL_NUMBER_OF(Entry->name), Name);
}

static BOOLEAN
KswPlatformAddExportedFunction(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ ULONG Scope,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_z_ PCWSTR ExportName,
    _In_ ULONG OwnerPolicy
    )
{
    PVOID functionAddress = KswPlatformGetRoutine(ExportName);
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

    if (functionAddress == NULL) {
        return FALSE;
    }
    KswPlatformInitializeEntry(
        &entry,
        Scope,
        KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION,
        KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY,
        KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
        OwnerPolicy,
        0UL,
        NULL,
        ExportName);
    entry.liveAddress = (ULONGLONG)(ULONG_PTR)functionAddress;
    entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS |
        KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT;
    KswPlatformClassifyFunction(&entry, ModuleInfo, OwnerPolicy);
    KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    return TRUE;
}

static ULONG
KswPlatformHalDispatchSlotCount(
    _In_ ULONG Version
    )
{
    // 中文说明：HAL_DISPATCH 以尾部追加字段演进；v4 到
    // HalSetPciErrorHandlerCallback，v5 再含 HalGetPrmCache，v6 含全部字段。
    if (Version == 4UL) {
        return 22UL;
    }
    if (Version == 5UL) {
        return 23UL;
    }
    if (Version == 6UL) {
        return (ULONG)RTL_NUMBER_OF(g_KswHalDispatchSlots);
    }
    return 0UL;
}

static VOID
KswPlatformAddHalDispatch(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo
    )
{
    PVOID tableAddress = KswPlatformGetRoutine(L"HalDispatchTable");
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    ULONG version = 0UL;
    ULONG index = 0UL;
    ULONG slotCount = 0UL;
    ULONG tableBytes = 0UL;
    ULONG signatureId = KSWORD_ARK_PLATFORM_SIGNATURE_NONE;
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY versionEntry;

    if (tableAddress == NULL) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_PROCEDURE_NOT_FOUND,
            L"HalDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND,
            0ULL,
            0ULL);
        return;
    }

    tableOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)tableAddress);
    if (!KswPlatformIsExpectedHalOwner(tableOwner) ||
        !KswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            sizeof(version),
            FALSE,
            FALSE) ||
        !KswordARKHookReadMemorySafe(tableAddress, &version, sizeof(version))) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_DATA_ERROR,
            L"HalDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_RANGE_INVALID,
            sizeof(version),
            0ULL);
        return;
    }
    slotCount = KswPlatformHalDispatchSlotCount(version);
    if (slotCount == 0UL) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_REVISION_MISMATCH,
            L"HalDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_VERSION_MISMATCH,
            4ULL,
            version);
        return;
    }
    tableBytes = g_KswHalDispatchSlots[slotCount - 1UL].Offset +
        g_KswHalDispatchSlots[slotCount - 1UL].Width;
    if (!KswPlatformIsExpectedHalOwner(tableOwner) ||
        !KswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            tableBytes,
            FALSE,
            FALSE)) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_DATA_ERROR,
            L"HalDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_RANGE_INVALID,
            tableBytes,
            0ULL);
        return;
    }
    signatureId = version == HAL_DISPATCH_VERSION ?
        KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V6 :
        KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V4_V5;
    KswPlatformInitializeEntry(
        &versionEntry,
        KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
        KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
        signatureId,
        KSWORD_ARK_PLATFORM_SLOT_SCALAR,
        KSWORD_ARK_PLATFORM_OWNER_NONE,
        0UL,
        tableAddress,
        L"Version");
    versionEntry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
        KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED;
    KswPlatformSetDetail(
        &versionEntry,
        KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE,
        version,
        tableBytes,
        slotCount,
        0ULL);
    KswPlatformAppend(Response, Capacity, MaxRows, &versionEntry);

    for (index = 0UL; index < slotCount; ++index) {
        const KSW_PLATFORM_SLOT_DESCRIPTOR* descriptor = &g_KswHalDispatchSlots[index];
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        ULONGLONG value = 0ULL;

        KswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH,
            descriptor->SlotKind == KSWORD_ARK_PLATFORM_SLOT_FUNCTION ?
                KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION :
                KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
            signatureId,
            descriptor->SlotKind,
            descriptor->OwnerPolicy,
            index,
            tableAddress,
            descriptor->Name);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT;

        if (descriptor->Width > sizeof(value) ||
            !KswordARKHookReadMemorySafe(
                (const UCHAR*)tableAddress + descriptor->Offset,
                &value,
                descriptor->Width)) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED;
            entry.lastStatus = STATUS_PARTIAL_COPY;
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
                descriptor->Offset,
                descriptor->Width,
                0ULL,
                0ULL);
        }
        else if (descriptor->SlotKind == KSWORD_ARK_PLATFORM_SLOT_SCALAR) {
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE,
                value,
                descriptor->Offset,
                descriptor->Width,
                0ULL);
        }
        else if (value == 0ULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                descriptor->Offset,
                0ULL,
                0ULL,
                0ULL);
        }
        else {
            entry.liveAddress = value;
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
            KswPlatformClassifyFunction(&entry, ModuleInfo, descriptor->OwnerPolicy);
        }
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

static const KSW_PLATFORM_PRIVATE_BUILD_DESCRIPTOR*
KswPlatformFindPrivateBuild(
    _In_ ULONG BuildNumber
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < RTL_NUMBER_OF(g_KswHalPrivateBuilds); ++index) {
        if (g_KswHalPrivateBuilds[index].BuildNumber == BuildNumber) {
            return &g_KswHalPrivateBuilds[index];
        }
    }
    return NULL;
}

static const KSW_PLATFORM_PRIVATE_BUILD_DESCRIPTOR*
KswPlatformFindPrivateVersion(
    _In_ ULONG Version
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < RTL_NUMBER_OF(g_KswHalPrivateBuilds); ++index) {
        if (g_KswHalPrivateBuilds[index].Version == Version) {
            return &g_KswHalPrivateBuilds[index];
        }
    }
    return NULL;
}

static NTSTATUS
KswPlatformLocateHalPrivateBySignature(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONG BuildNumber,
    _In_ const KSW_PLATFORM_PRIVATE_BUILD_DESCRIPTOR* Build,
    _Outptr_ PVOID* TableAddressOut,
    _Out_ ULONG* VersionOut
    );

static VOID
KswPlatformAddHalPrivate(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONG BuildNumber
    )
{
    const KSW_PLATFORM_PRIVATE_BUILD_DESCRIPTOR* build =
        KswPlatformFindPrivateBuild(BuildNumber);
    PVOID tableAddress = NULL;
    ULONG version = 0UL;
    ULONG index = 0UL;
    NTSTATUS locateStatus = STATUS_NOT_SUPPORTED;
    BOOLEAN exactExport = FALSE;
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY versionEntry;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;

    // 中文说明：数据导出提供精确表地址，先验证 owner、受界范围和版本，
    // 避免依赖单一系统构建的指令窗口。只有已知 Version/ByteSize 才展开槽位。
    tableAddress = KswPlatformGetRoutine(L"HalPrivateDispatchTable");
    tableOwner = KswordARKHookFindModuleForAddress(
        ModuleInfo,
        (ULONG_PTR)tableAddress);
    if (tableAddress != NULL &&
        KswPlatformIsExpectedHalOwner(tableOwner) &&
        KswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            sizeof(version),
            FALSE,
            FALSE) &&
        KswordARKHookReadMemorySafe(
            tableAddress,
            &version,
            sizeof(version))) {
        const KSW_PLATFORM_PRIVATE_BUILD_DESCRIPTOR* versionBuild =
            KswPlatformFindPrivateVersion(version);
        if (versionBuild != NULL &&
            KswPlatformRangeInSection(
                tableOwner,
                (ULONG_PTR)tableAddress,
                versionBuild->ByteSize,
                FALSE,
                FALSE)) {
            build = versionBuild;
            locateStatus = STATUS_SUCCESS;
            exactExport = TRUE;
        }
        else {
            KswPlatformInitializeEntry(
                &versionEntry,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
                KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
                KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY,
                KSWORD_ARK_PLATFORM_SLOT_SCALAR,
                KSWORD_ARK_PLATFORM_OWNER_NONE,
                0UL,
                tableAddress,
                L"Version");
            versionEntry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT;
            KswPlatformSetDetail(
                &versionEntry,
                KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE,
                version,
                BuildNumber,
                0ULL,
                0ULL);
            KswPlatformAppend(Response, Capacity, MaxRows, &versionEntry);
            (VOID)KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
                ModuleInfo,
                L"HalTranslateBusAddress",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI);
            (VOID)KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
                ModuleInfo,
                L"HalAssignSlotResources",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI);
            return;
        }
    }

    // 中文说明：旧系统若不暴露数据导出，仍保留受界 RIP-relative
    // 定位；候选必须唯一，且完整 Version/ByteSize 同时验证。
    if (!NT_SUCCESS(locateStatus) && build != NULL) {
        locateStatus = KswPlatformLocateHalPrivateBySignature(
            ModuleInfo,
            BuildNumber,
            build,
            &tableAddress,
            &version);
    }
    if (!NT_SUCCESS(locateStatus)) {
        if (KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
                ModuleInfo,
                L"HalTranslateBusAddress",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI)) {
            return;
        }
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
            locateStatus == STATUS_NOT_SUPPORTED ?
                KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED :
                KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            locateStatus,
            L"HalPrivateDispatchTable",
            locateStatus == STATUS_OBJECT_NAME_COLLISION ?
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_UNIQUE :
                (locateStatus == STATUS_REVISION_MISMATCH ?
                    KSWORD_ARK_PLATFORM_DETAIL_VERSION_MISMATCH :
                    (locateStatus == STATUS_NOT_SUPPORTED ?
                        KSWORD_ARK_PLATFORM_DETAIL_BUILD_UNSUPPORTED :
                        KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND)),
            locateStatus == STATUS_REVISION_MISMATCH && build != NULL ?
                build->Version :
                BuildNumber,
            locateStatus == STATUS_REVISION_MISMATCH && build != NULL ?
                version :
                (build != NULL ? build->ByteSize : 0UL));
        return;
    }

    KswPlatformInitializeEntry(
        &versionEntry,
        KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
        KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
        build->SignatureId,
        KSWORD_ARK_PLATFORM_SLOT_SCALAR,
        KSWORD_ARK_PLATFORM_OWNER_NONE,
        0UL,
        tableAddress,
        L"Version");
    versionEntry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
        (exactExport ?
            KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT :
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED);
    KswPlatformSetDetail(
        &versionEntry,
        KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE,
        version,
        build->ByteSize,
        BuildNumber,
        0ULL);
    KswPlatformAppend(Response, Capacity, MaxRows, &versionEntry);

    for (index = 0UL; index < RTL_NUMBER_OF(g_KswHalPrivateSlots); ++index) {
        const KSW_PLATFORM_SLOT_DESCRIPTOR* descriptor = &g_KswHalPrivateSlots[index];
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        PVOID functionAddress = NULL;

        if (descriptor->Offset + descriptor->Width > build->ByteSize) {
            break;
        }
        KswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE,
            descriptor->SlotKind == KSWORD_ARK_PLATFORM_SLOT_FUNCTION ?
                KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION :
                KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE,
            build->SignatureId,
            descriptor->SlotKind,
            descriptor->OwnerPolicy,
            index + 1UL,
            tableAddress,
            descriptor->Name);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            (exactExport ?
                KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT :
                KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED);

        if (!KswordARKHookReadMemorySafe(
                (const UCHAR*)tableAddress + descriptor->Offset,
                &functionAddress,
                descriptor->Width)) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED;
            entry.lastStatus = STATUS_PARTIAL_COPY;
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
                descriptor->Offset,
                descriptor->Width,
                BuildNumber,
                version);
        }
        else if (descriptor->SlotKind == KSWORD_ARK_PLATFORM_SLOT_DUMMY) {
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_DUMMY_SLOT,
                (ULONGLONG)(ULONG_PTR)functionAddress,
                descriptor->Offset,
                BuildNumber,
                version);
        }
        else if (functionAddress == NULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                descriptor->Offset,
                BuildNumber,
                version,
                0ULL);
        }
        else {
            entry.liveAddress = (ULONGLONG)(ULONG_PTR)functionAddress;
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
            KswPlatformClassifyFunction(&entry, ModuleInfo, descriptor->OwnerPolicy);
        }
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

typedef struct _KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR
{
    ULONG BuildNumber;
    PCWSTR AnchorName;
    ULONG ScanOffset;
    ULONG ScanBytes;
    LONG CandidateAdjustment;
    ULONG TableByteSize;
    ULONG ExpectedVersion;
    UCHAR Bytes[7];
    UCHAR Mask[7];
} KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR;

typedef BOOLEAN
(*KSW_PLATFORM_VALIDATE_TABLE_ROUTINE)(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PVOID Candidate,
    _In_ const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR* Locator
    );

// HalTranslateBusAddress 通过 HalPrivateDispatchTable+0x38 分派。
// 表基址必须由该受信导出的有界代码窗口内唯一的 RIP-relative 读取反推，
// 不允许回退到 HalPrivateDispatchTable 导出，也不扫描整个内核映像。
static const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR g_KswHalPrivateLocators[] = {
    {
        22000UL, L"HalTranslateBusAddress", 0x00UL, 0x80UL, -0x38L,
        0x4D8UL, 54UL,
        { 0x48U, 0x8BU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    },
    {
        22621UL, L"HalTranslateBusAddress", 0x00UL, 0x80UL, -0x38L,
        0x4F0UL, 58UL,
        { 0x48U, 0x8BU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    },
    {
        26100UL, L"HalTranslateBusAddress", 0x00UL, 0x80UL, -0x38L,
        0x518UL, 61UL,
        { 0x48U, 0x8BU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    },
    {
        26220UL, L"HalTranslateBusAddress", 0x00UL, 0x80UL, -0x38L,
        0x518UL, 61UL,
        { 0x48U, 0x8BU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    }
};

static const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR g_KswHalAcpiLocators[] = {
    {
        22000UL, NULL, 0x00UL, 0xC0UL, 0L,
        sizeof(KSW_PLATFORM_HAL_ACPI_VIEW), KSW_PLATFORM_HAL_ACPI_VERSION,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    },
    {
        22621UL, NULL, 0x00UL, 0xC0UL, 0L,
        sizeof(KSW_PLATFORM_HAL_ACPI_VIEW), KSW_PLATFORM_HAL_ACPI_VERSION,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    },
    {
        26100UL, NULL, 0x00UL, 0x80UL, 0L,
        sizeof(KSW_PLATFORM_HAL_ACPI_VIEW), KSW_PLATFORM_HAL_ACPI_VERSION,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    },
    {
        26220UL, NULL, 0x00UL, 0x80UL, 0L,
        sizeof(KSW_PLATFORM_HAL_ACPI_VIEW), KSW_PLATFORM_HAL_ACPI_VERSION,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    }
};

static const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR g_KswHalSubcomponentLocators[] = {
    {
        26100UL, L"HalInitSystem", 0x00UL, 0x90UL, 0L,
        sizeof(KSW_PLATFORM_HAL_SUBCOMPONENT) *
            KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT,
        KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT,
        { 0x48U, 0x8DU, 0x05U, 0U, 0U, 0U, 0U },
        { 0xF8U, 0xFFU, 0xC7U, 0U, 0U, 0U, 0U }
    },
    {
        26220UL, L"HalInitSystem", 0x70UL, 0x20UL, 0L,
        sizeof(KSW_PLATFORM_HAL_SUBCOMPONENT) *
            KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT,
        KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT,
        { 0x4CU, 0x8DU, 0x25U, 0U, 0U, 0U, 0U },
        { 0xFFU, 0xFFU, 0xFFU, 0U, 0U, 0U, 0U }
    }
};

static const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR*
KswPlatformFindRipLocator(
    _In_reads_(DescriptorCount) const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR* Descriptors,
    _In_ ULONG DescriptorCount,
    _In_ ULONG BuildNumber
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < DescriptorCount; ++index) {
        if (Descriptors[index].BuildNumber == BuildNumber) {
            return &Descriptors[index];
        }
    }
    return NULL;
}

static NTSTATUS
KswPlatformLocateRipTable(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PVOID Anchor,
    _In_ const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR* Locator,
    _In_ KSW_PLATFORM_VALIDATE_TABLE_ROUTINE ValidateCandidate,
    _Outptr_ PVOID* TableAddressOut
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* anchorOwner = NULL;
    ULONG offset = 0UL;
    ULONG uniqueCount = 0UL;
    PVOID uniqueCandidate = NULL;

    if (ModuleInfo == NULL || Anchor == NULL || Locator == NULL ||
        ValidateCandidate == NULL || TableAddressOut == NULL ||
        Locator->ScanBytes < RTL_NUMBER_OF(Locator->Bytes) ||
        Locator->ScanOffset > MAXULONG - Locator->ScanBytes ||
        Locator->TableByteSize == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TableAddressOut = NULL;
    anchorOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)Anchor);
    if (!KswPlatformIsExpectedHalOwner(anchorOwner) ||
        !KswPlatformRangeInSection(
            anchorOwner,
            (ULONG_PTR)Anchor,
            Locator->ScanOffset + Locator->ScanBytes,
            TRUE,
            FALSE)) {
        return STATUS_INVALID_ADDRESS;
    }

    // 中文说明：只检查 build descriptor 指定的小窗口，并要求完整结构验证后
    // 恰好产生一个候选；不会扫描内核映像的其它区域。
    for (offset = 0UL;
         offset + RTL_NUMBER_OF(Locator->Bytes) <= Locator->ScanBytes;
         ++offset) {
        UCHAR instruction[7];
        LONG displacement = 0;
        ULONG_PTR candidateAddress = 0U;
        ULONG64 candidateAddress64 = 0ULL;
        ULONG64 instructionEnd = 0ULL;
        PVOID candidate = NULL;

        RtlZeroMemory(instruction, sizeof(instruction));
        if (!KswordARKHookReadMemorySafe(
                (const UCHAR*)Anchor + Locator->ScanOffset + offset,
                instruction,
                sizeof(instruction)) ||
            !KswPlatformMaskedBytesMatch(
                instruction,
                Locator->Bytes,
                Locator->Mask,
                RTL_NUMBER_OF(Locator->Bytes))) {
            continue;
        }
        RtlCopyMemory(&displacement, instruction + 3UL, sizeof(displacement));
        if ((ULONG64)(ULONG_PTR)Anchor >
            MAXULONGLONG -
                (ULONG64)Locator->ScanOffset -
                (ULONG64)offset -
                (ULONG64)RTL_NUMBER_OF(Locator->Bytes)) {
            continue;
        }
        instructionEnd =
            (ULONG64)(ULONG_PTR)Anchor +
            (ULONG64)Locator->ScanOffset +
            (ULONG64)offset +
            (ULONG64)RTL_NUMBER_OF(Locator->Bytes);
        if (!KswPlatformAddSignedDisplacement(
                instructionEnd,
                (LONGLONG)displacement,
                &candidateAddress64) ||
            !KswPlatformAddSignedDisplacement(
                candidateAddress64,
                (LONGLONG)Locator->CandidateAdjustment,
                &candidateAddress64) ||
            candidateAddress64 > MAXULONG_PTR) {
            continue;
        }
        candidateAddress = (ULONG_PTR)candidateAddress64;
        candidate = (PVOID)candidateAddress;
        if (!ValidateCandidate(ModuleInfo, candidate, Locator)) {
            continue;
        }
        if (candidate == uniqueCandidate) {
            continue;
        }
        uniqueCandidate = candidate;
        uniqueCount += 1UL;
    }

    if (uniqueCount == 0UL) {
        return STATUS_NOT_FOUND;
    }
    if (uniqueCount != 1UL) {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    *TableAddressOut = uniqueCandidate;
    return STATUS_SUCCESS;
}

static BOOLEAN
KswPlatformValidateHalPrivateCandidate(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PVOID Candidate,
    _In_ const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR* Locator
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    ULONG version = 0UL;

    if (ModuleInfo == NULL || Candidate == NULL || Locator == NULL ||
        Locator->TableByteSize < sizeof(version)) {
        return FALSE;
    }
    tableOwner = KswordARKHookFindModuleForAddress(
        ModuleInfo,
        (ULONG_PTR)Candidate);
    return KswPlatformIsExpectedHalOwner(tableOwner) &&
        KswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)Candidate,
            Locator->TableByteSize,
            FALSE,
            FALSE) &&
        KswordARKHookReadMemorySafe(Candidate, &version, sizeof(version)) &&
        version == Locator->ExpectedVersion;
}

static NTSTATUS
KswPlatformLocateHalPrivateBySignature(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONG BuildNumber,
    _In_ const KSW_PLATFORM_PRIVATE_BUILD_DESCRIPTOR* Build,
    _Outptr_ PVOID* TableAddressOut,
    _Out_ ULONG* VersionOut
    )
{
    const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR* locator = NULL;
    PVOID anchor = NULL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (ModuleInfo == NULL || Build == NULL ||
        TableAddressOut == NULL || VersionOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *TableAddressOut = NULL;
    *VersionOut = 0UL;
    locator = KswPlatformFindRipLocator(
        g_KswHalPrivateLocators,
        RTL_NUMBER_OF(g_KswHalPrivateLocators),
        BuildNumber);
    if (locator == NULL ||
        locator->AnchorName == NULL ||
        locator->TableByteSize != Build->ByteSize ||
        locator->ExpectedVersion != Build->Version) {
        return STATUS_NOT_SUPPORTED;
    }
    anchor = KswPlatformGetRoutine(locator->AnchorName);
    if (anchor == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    status = KswPlatformLocateRipTable(
        ModuleInfo,
        anchor,
        locator,
        KswPlatformValidateHalPrivateCandidate,
        TableAddressOut);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!KswordARKHookReadMemorySafe(
            *TableAddressOut,
            VersionOut,
            sizeof(*VersionOut))) {
        *TableAddressOut = NULL;
        return STATUS_PARTIAL_COPY;
    }
    if (*VersionOut != Build->Version) {
        *TableAddressOut = NULL;
        return STATUS_REVISION_MISMATCH;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
KswPlatformHalAcpiIdentityMatches(
    _In_ const KSW_PLATFORM_HAL_ACPI_VIEW* View
    )
{
    return View != NULL &&
        View->Signature == KSW_PLATFORM_HAL_ACPI_SIGNATURE &&
        View->Version == KSW_PLATFORM_HAL_ACPI_VERSION;
}

static BOOLEAN
KswPlatformValidateHalAcpiCandidate(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PVOID Candidate,
    _In_ const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR* Locator
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    KSW_PLATFORM_HAL_ACPI_VIEW view;

    if (ModuleInfo == NULL || Candidate == NULL || Locator == NULL ||
        Locator->TableByteSize != sizeof(view) ||
        Locator->ExpectedVersion != KSW_PLATFORM_HAL_ACPI_VERSION) {
        return FALSE;
    }
    tableOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)Candidate);
    RtlZeroMemory(&view, sizeof(view));
    if (!KswPlatformIsExpectedHalOwner(tableOwner) ||
        !KswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)Candidate,
            sizeof(view),
            FALSE,
            TRUE) ||
        !KswordARKHookReadMemorySafe(Candidate, &view, sizeof(view)) ||
        !KswPlatformHalAcpiIdentityMatches(&view)) {
        return FALSE;
    }
    // 函数槽内容不是表身份条件：外部 owner、非执行地址或 NULL 正是需要
    // 逐行保留并报告的异常证据，不能让它们把整个候选吞成 locator-not-found。
    return TRUE;
}

static BOOLEAN
KswPlatformValidateBoundedWideName(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PCWSTR NameAddress,
    _In_z_ PCWSTR ExpectedName
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* owner = NULL;
    SIZE_T expectedChars = 0U;
    WCHAR buffer[32];

    if (ModuleInfo == NULL || NameAddress == NULL || ExpectedName == NULL) {
        return FALSE;
    }
    while (ExpectedName[expectedChars] != L'\0' &&
           expectedChars < RTL_NUMBER_OF(buffer) - 1U) {
        expectedChars += 1U;
    }
    if (ExpectedName[expectedChars] != L'\0') {
        return FALSE;
    }
    owner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)NameAddress);
    RtlZeroMemory(buffer, sizeof(buffer));
    if (!KswPlatformIsExpectedHalOwner(owner) ||
        !KswPlatformRangeInSection(
            owner,
            (ULONG_PTR)NameAddress,
            (expectedChars + 1U) * sizeof(WCHAR),
            FALSE,
            TRUE) ||
        !KswordARKHookReadMemorySafe(
            NameAddress,
            buffer,
            (expectedChars + 1U) * sizeof(WCHAR))) {
        return FALSE;
    }
    return RtlCompareMemory(
        buffer,
        ExpectedName,
        (expectedChars + 1U) * sizeof(WCHAR)) ==
        (expectedChars + 1U) * sizeof(WCHAR);
}

static BOOLEAN
KswPlatformHalSubcomponentIdentityMatches(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_reads_(KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT)
        const KSW_PLATFORM_HAL_SUBCOMPONENT* Entries
    )
{
    ULONG index = 0UL;

    if (ModuleInfo == NULL || Entries == NULL) {
        return FALSE;
    }
    for (index = 0UL;
         index < KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT;
         ++index) {
        if (!KswPlatformValidateBoundedWideName(
                ModuleInfo,
                Entries[index].Name,
                g_KswHalSubcomponentNames[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN
KswPlatformValidateHalSubcomponentCandidate(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ PVOID Candidate,
    _In_ const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR* Locator
    )
{
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    KSW_PLATFORM_HAL_SUBCOMPONENT entries[KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT];
    if (ModuleInfo == NULL || Candidate == NULL || Locator == NULL ||
        Locator->TableByteSize != sizeof(entries) ||
        Locator->ExpectedVersion != KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT) {
        return FALSE;
    }
    tableOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)Candidate);
    RtlZeroMemory(entries, sizeof(entries));
    if (!KswPlatformIsExpectedHalOwner(tableOwner) ||
        !KswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)Candidate,
            sizeof(entries),
            FALSE,
            TRUE) ||
        !KswordARKHookReadMemorySafe(Candidate, entries, sizeof(entries))) {
        return FALSE;
    }

    if (!KswPlatformHalSubcomponentIdentityMatches(ModuleInfo, entries)) {
        return FALSE;
    }
    // 22 个只读名称对和受界表范围负责候选身份；函数槽逐项分类。
    // 因此被替换到外部模块、未知地址或 NULL 的函数仍会作为对应行返回。
    return TRUE;
}

static BOOLEAN
KswPlatformGetHalPowerAnchor(
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _Outptr_ PVOID* AnchorOut
    )
{
    PVOID tableAddress = KswPlatformGetRoutine(L"HalDispatchTable");
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    ULONG version = 0UL;
    PVOID anchor = NULL;
    ULONG minimumBytes =
        FIELD_OFFSET(HAL_DISPATCH, HalInitPowerManagement) +
        sizeof(((PHAL_DISPATCH)0)->HalInitPowerManagement);

    if (AnchorOut == NULL) {
        return FALSE;
    }
    *AnchorOut = NULL;
    tableOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)tableAddress);
    if (tableAddress == NULL ||
        !KswPlatformIsExpectedHalOwner(tableOwner) ||
        !KswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)tableAddress,
            minimumBytes,
            FALSE,
            FALSE) ||
        !KswordARKHookReadMemorySafe(tableAddress, &version, sizeof(version)) ||
        version != HAL_DISPATCH_VERSION ||
        !KswordARKHookReadMemorySafe(
            (const UCHAR*)tableAddress +
                FIELD_OFFSET(HAL_DISPATCH, HalInitPowerManagement),
            &anchor,
            sizeof(anchor)) ||
        anchor == NULL) {
        return FALSE;
    }
    *AnchorOut = anchor;
    return TRUE;
}

static VOID
KswPlatformAddHalAcpi(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONG BuildNumber
    )
{
    const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR* locator =
        KswPlatformFindRipLocator(
            g_KswHalAcpiLocators,
            RTL_NUMBER_OF(g_KswHalAcpiLocators),
            BuildNumber);
    PVOID anchor = NULL;
    PVOID tableAddress = NULL;
    KSW_PLATFORM_HAL_ACPI_VIEW view;
    NTSTATUS locateStatus = STATUS_NOT_SUPPORTED;
    ULONG index = 0UL;

    if (locator == NULL ||
        !KswPlatformGetHalPowerAnchor(ModuleInfo, &anchor)) {
        if (KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
                ModuleInfo,
                L"HalAcpiGetTableEx",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)) {
            return;
        }
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_NOT_SUPPORTED,
            L"HalAcpiDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_BUILD_UNSUPPORTED,
            BuildNumber,
            0ULL);
        return;
    }
    locateStatus = KswPlatformLocateRipTable(
        ModuleInfo,
        anchor,
        locator,
        KswPlatformValidateHalAcpiCandidate,
        &tableAddress);
    if (!NT_SUCCESS(locateStatus)) {
        if (KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
                ModuleInfo,
                L"HalAcpiGetTableEx",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)) {
            return;
        }
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            locateStatus,
            L"HalAcpiDispatchTable",
            locateStatus == STATUS_OBJECT_NAME_COLLISION ?
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_UNIQUE :
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND,
            BuildNumber,
            (ULONGLONG)(ULONG_PTR)anchor);
        return;
    }

    RtlZeroMemory(&view, sizeof(view));
    if (!KswordARKHookReadMemorySafe(tableAddress, &view, sizeof(view))) {
        if (KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
                ModuleInfo,
                L"HalAcpiGetTableEx",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)) {
            return;
        }
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_PARTIAL_COPY,
            L"HalAcpiDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
            (ULONGLONG)(ULONG_PTR)tableAddress,
            sizeof(view));
        return;
    }
    if (!KswPlatformHalAcpiIdentityMatches(&view)) {
        if (KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
                ModuleInfo,
                L"HalAcpiGetTableEx",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI)) {
            return;
        }
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_REVISION_MISMATCH,
            L"HalAcpiDispatchTable",
            KSWORD_ARK_PLATFORM_DETAIL_TABLE_INVALID,
            view.Signature,
            view.Version);
        return;
    }

    for (index = 0UL; index < RTL_NUMBER_OF(view.Functions); ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        ULONG ownerPolicy =
            (index == 5UL || index == 6UL || index == 8UL) ?
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI :
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI;

        KswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI,
            KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION,
            KSWORD_ARK_PLATFORM_SIGNATURE_HAL_ACPI_V5,
            KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
            ownerPolicy,
            index,
            tableAddress,
            g_KswHalAcpiFunctionNames[index]);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_READ_ONLY_RANGE |
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
        if (view.Functions[index] == NULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                index,
                BuildNumber,
                KSW_PLATFORM_HAL_ACPI_VERSION,
                0ULL);
        }
        else {
            entry.liveAddress = (ULONGLONG)(ULONG_PTR)view.Functions[index];
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
            KswPlatformClassifyFunction(&entry, ModuleInfo, ownerPolicy);
        }
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

static VOID
KswPlatformAddHalSubcomponents(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONG BuildNumber
    )
{
    const KSW_PLATFORM_RIP_LOCATOR_DESCRIPTOR* locator =
        KswPlatformFindRipLocator(
            g_KswHalSubcomponentLocators,
            RTL_NUMBER_OF(g_KswHalSubcomponentLocators),
            BuildNumber);
    PVOID anchor = NULL;
    PVOID tableAddress = NULL;
    KSW_PLATFORM_HAL_SUBCOMPONENT entries[KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT];
    NTSTATUS locateStatus = STATUS_NOT_SUPPORTED;
    ULONG index = 0UL;

    if (locator == NULL) {
        if (KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
                ModuleInfo,
                L"HalInitSystem",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL)) {
            return;
        }
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_NOT_SUPPORTED,
            L"HalSubComponents",
            KSWORD_ARK_PLATFORM_DETAIL_BUILD_UNSUPPORTED,
            BuildNumber,
            26100ULL);
        return;
    }
    anchor = locator->AnchorName != NULL ?
        KswPlatformGetRoutine(locator->AnchorName) :
        NULL;
    locateStatus = KswPlatformLocateRipTable(
        ModuleInfo,
        anchor,
        locator,
        KswPlatformValidateHalSubcomponentCandidate,
        &tableAddress);
    if (!NT_SUCCESS(locateStatus)) {
        if (KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
                ModuleInfo,
                L"HalInitSystem",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL)) {
            return;
        }
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            locateStatus,
            L"HalSubComponents",
            locateStatus == STATUS_OBJECT_NAME_COLLISION ?
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_UNIQUE :
                KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND,
            BuildNumber,
            (ULONGLONG)(ULONG_PTR)anchor);
        return;
    }

    RtlZeroMemory(entries, sizeof(entries));
    if (!KswordARKHookReadMemorySafe(tableAddress, entries, sizeof(entries))) {
        if (KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
                ModuleInfo,
                L"HalInitSystem",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL)) {
            return;
        }
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_PARTIAL_COPY,
            L"HalSubComponents",
            KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
            (ULONGLONG)(ULONG_PTR)tableAddress,
            sizeof(entries));
        return;
    }
    if (!KswPlatformHalSubcomponentIdentityMatches(ModuleInfo, entries)) {
        if (KswPlatformAddExportedFunction(
                Response,
                Capacity,
                MaxRows,
                KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
                ModuleInfo,
                L"HalInitSystem",
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL)) {
            return;
        }
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            STATUS_REVISION_MISMATCH,
            L"HalSubComponents",
            KSWORD_ARK_PLATFORM_DETAIL_TABLE_INVALID,
            (ULONGLONG)(ULONG_PTR)tableAddress,
            KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT);
        return;
    }

    for (index = 0UL; index < RTL_NUMBER_OF(entries); ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

        KswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS,
            KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION,
            KSWORD_ARK_PLATFORM_SIGNATURE_HAL_SUBCOMPONENTS_22,
            KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
            KSWORD_ARK_PLATFORM_OWNER_NT_HAL,
            index,
            tableAddress,
            g_KswHalSubcomponentNames[index]);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
            KSWORD_ARK_PLATFORM_FIELD_READ_ONLY_RANGE |
            KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
        if (entries[index].Function == NULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                index,
                BuildNumber,
                KSW_PLATFORM_HAL_SUBCOMPONENT_COUNT,
                0ULL);
        }
        else {
            entry.liveAddress =
                (ULONGLONG)(ULONG_PTR)entries[index].Function;
            entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
            KswPlatformClassifyFunction(
                &entry,
                ModuleInfo,
                KSWORD_ARK_PLATFORM_OWNER_NT_HAL);
        }
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

static VOID
KswPlatformAddWdfFunctions(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo
    )
{
    const WDFFUNC* functionTable = WdfFunctions;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* tableOwner = NULL;
    ULONG index = 0UL;
    ULONG functionCount = (ULONG)WdfFunctionTableNumEntries;

    if (functionTable == NULL ||
        functionCount == 0UL ||
        functionCount > KSWORD_ARK_PLATFORM_HARD_MAX_ROWS) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED,
            STATUS_NOT_SUPPORTED,
            L"WdfFunctions",
            KSWORD_ARK_PLATFORM_DETAIL_WDF_TABLE_INVALID,
            functionCount,
            0ULL);
        return;
    }
    tableOwner = KswordARKHookFindModuleForAddress(ModuleInfo, (ULONG_PTR)functionTable);
    if (!KswPlatformModuleNameEquals(tableOwner, "Wdf01000.sys") ||
        !KswPlatformRangeInSection(
            tableOwner,
            (ULONG_PTR)functionTable,
            (SIZE_T)functionCount * sizeof(WDFFUNC),
            FALSE,
            FALSE)) {
        KswPlatformAddDiagnostic(
            Response, Capacity, MaxRows,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH,
            STATUS_DATA_ERROR,
            L"WdfFunctions",
            KSWORD_ARK_PLATFORM_DETAIL_WDF_TABLE_INVALID,
            (ULONGLONG)(ULONG_PTR)functionTable,
            functionCount);
        return;
    }

    for (index = 0UL; index < functionCount; ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;
        WDFFUNC functionAddress = NULL;
        WCHAR fallbackName[KSWORD_ARK_PLATFORM_NAME_CHARS];
        PCWSTR functionName =
            index < RTL_NUMBER_OF(g_KswWdfFunctionNames)
            ? g_KswWdfFunctionNames[index]
            : NULL;
        RtlZeroMemory(fallbackName, sizeof(fallbackName));
        if (functionName == NULL) {
            (VOID)RtlStringCchPrintfW(
                fallbackName,
                RTL_NUMBER_OF(fallbackName),
                L"WdfFunctions[%lu]",
                index);
            functionName = fallbackName;
        }

        KswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS,
            KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION,
            KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE,
            KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
            KSWORD_ARK_PLATFORM_OWNER_WDF,
            index,
            (PVOID)functionTable,
            functionName);
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED;

        if (!KswordARKHookReadMemorySafe(
                &functionTable[index],
                &functionAddress,
                sizeof(functionAddress))) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED;
            entry.lastStatus = STATUS_PARTIAL_COPY;
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED,
                index,
                functionCount,
                0ULL,
                0ULL);
            KswPlatformAppend(Response, Capacity, MaxRows, &entry);
            continue;
        }
        if (functionAddress == NULL) {
            entry.status = KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE;
            KswPlatformSetDetail(
                &entry,
                KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT,
                index,
                functionCount,
                0ULL,
                0ULL);
            KswPlatformAppend(Response, Capacity, MaxRows, &entry);
            continue;
        }
        entry.liveAddress = (ULONGLONG)(ULONG_PTR)functionAddress;
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
        KswPlatformClassifyFunction(
            &entry,
            ModuleInfo,
            KSWORD_ARK_PLATFORM_OWNER_WDF);
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

static VOID
KswPlatformAddWdfCallbacks(
    _Inout_ KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* Response,
    _In_ ULONG Capacity,
    _In_ ULONG MaxRows,
    _In_ const KSW_HOOK_SYSTEM_MODULE_INFORMATION* ModuleInfo
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < RTL_NUMBER_OF(g_KswWdfCallbacks); ++index) {
        KSWORD_ARK_PLATFORM_AUDIT_ENTRY entry;

        KswPlatformInitializeEntry(
            &entry,
            KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS,
            KSWORD_ARK_PLATFORM_AUDIT_ROW_CALLBACK,
            KSWORD_ARK_PLATFORM_SIGNATURE_X64_PROLOGUE,
            KSWORD_ARK_PLATFORM_SLOT_FUNCTION,
            KSWORD_ARK_PLATFORM_OWNER_KSWORD,
            index,
            NULL,
            g_KswWdfCallbacks[index].Name);
        entry.liveAddress = (ULONGLONG)(ULONG_PTR)g_KswWdfCallbacks[index].Address;
        entry.fieldFlags |= KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS;
        KswPlatformClassifyFunction(
            &entry,
            ModuleInfo,
            KSWORD_ARK_PLATFORM_OWNER_KSWORD);
        KswPlatformAppend(Response, Capacity, MaxRows, &entry);
    }
}

NTSTATUS
KswordARKPlatformAuditIoctlQuery(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST defaultRequest;
    const KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST* requestPacket = NULL;
    KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE* response = NULL;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputBytes = 0U;
    size_t actualOutputBytes = 0U;
    ULONG moduleInfoBytes = 0UL;
    ULONG capacity = 0UL;
    ULONG maxRows = KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS;
    ULONG scopeMask = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL;
    ULONG majorVersion = 0UL;
    ULONG minorVersion = 0UL;
    ULONG buildNumber = 0UL;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;
    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    defaultRequest.size = sizeof(defaultRequest);
    defaultRequest.version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
    defaultRequest.scopeMask = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL;
    defaultRequest.maxRows = KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS;

    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST),
        &inputBuffer,
        &actualInputBytes,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(actualInputBytes);
    requestPacket = hasInput ?
        (const KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST*)inputBuffer :
        &defaultRequest;
    if (requestPacket->size != sizeof(*requestPacket) ||
        requestPacket->version != KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION ||
        requestPacket->flags != 0UL ||
        requestPacket->reserved0 != 0UL ||
        (requestPacket->scopeMask & ~KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    scopeMask = requestPacket->scopeMask == 0UL ?
        KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL :
        requestPacket->scopeMask;
    maxRows = requestPacket->maxRows == 0UL ?
        KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS :
        requestPacket->maxRows;
    if (maxRows > KSWORD_ARK_PLATFORM_HARD_MAX_ROWS) {
        maxRows = KSWORD_ARK_PLATFORM_HARD_MAX_ROWS;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSW_PLATFORM_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outputBuffer, actualOutputBytes);
    response = (KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE*)outputBuffer;
    response->size = KSW_PLATFORM_RESPONSE_HEADER_SIZE;
    response->version = KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK;
    response->scopeMask = scopeMask;
    response->responseFlags = KSWORD_ARK_PLATFORM_RESPONSE_NO_PDB;
    response->entrySize = sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY);
    response->signaturePolicyFlags =
        KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT |
        KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED |
        KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED |
        KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT |
        KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED;
    response->lastStatus = STATUS_SUCCESS;
    capacity = KswPlatformOutputCapacity(actualOutputBytes);
    (VOID)PsGetVersion(&majorVersion, &minorVersion, &buildNumber, NULL);
    UNREFERENCED_PARAMETER(majorVersion);
    UNREFERENCED_PARAMETER(minorVersion);
    response->buildNumber = buildNumber;

    status = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status) || moduleInfo == NULL || moduleInfoBytes == 0UL) {
        if (NT_SUCCESS(status)) {
            status = STATUS_UNSUCCESSFUL;
        }
        KswPlatformAddDiagnostic(
            response, capacity, maxRows, scopeMask,
            KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED,
            status,
            L"LoadedModuleSnapshot",
            KSWORD_ARK_PLATFORM_DETAIL_MODULE_SNAPSHOT_FAILED,
            moduleInfoBytes,
            0ULL);
        if (moduleInfo != NULL) {
            ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
            moduleInfo = NULL;
        }
        *BytesReturned = KSW_PLATFORM_RESPONSE_HEADER_SIZE +
            ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
        return STATUS_SUCCESS;
    }

    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH) != 0UL) {
        KswPlatformAddHalDispatch(response, capacity, maxRows, moduleInfo);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE) != 0UL) {
        KswPlatformAddHalPrivate(
            response, capacity, maxRows, moduleInfo, buildNumber);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI) != 0UL) {
        KswPlatformAddHalAcpi(
            response, capacity, maxRows, moduleInfo, buildNumber);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS) != 0UL) {
        KswPlatformAddHalSubcomponents(
            response, capacity, maxRows, moduleInfo, buildNumber);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS) != 0UL) {
        KswPlatformAddWdfFunctions(response, capacity, maxRows, moduleInfo);
    }
    if ((scopeMask & KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS) != 0UL) {
        KswPlatformAddWdfCallbacks(response, capacity, maxRows, moduleInfo);
    }

    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    if ((response->responseFlags & KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED) != 0UL) {
        response->queryStatus = KSWORD_ARK_PLATFORM_AUDIT_STATUS_BUFFER_TRUNCATED;
    }
    *BytesReturned = KSW_PLATFORM_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PLATFORM_AUDIT_ENTRY));
    return STATUS_SUCCESS;
}
