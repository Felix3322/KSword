#pragma once

/*
 * The controller companion is a PnP function driver.  It may only operate a
 * controller that the operator has manually rebound away from the inbox
 * storage stack; it never attaches below storahci, stornvme, or atapi.
 */
#include <ntifs.h>
#include <wdf.h>
#include <wdmguid.h>
#include <ntstrsafe.h>

#include "..\shared\driver\KswordArkStorageControllerIoctl.h"

#define KSCC_POOL_TAG 'CCSK'
#define KSCC_MAX_BARS 6U
#define KSCC_MAX_PORT_RANGES 4U
#define KSCC_BACKUP_BYTES (256U * 1024U)

typedef struct _KSCC_DMA_REGION {
    WDFCOMMONBUFFER Object;
    PVOID Virtual;
    PHYSICAL_ADDRESS Logical;
    SIZE_T Length;
} KSCC_DMA_REGION;

typedef struct _KSCC_AUDIT_STATE {
    KSPIN_LOCK Lock;
    ULONG NextIndex;
    ULONG Count;
    ULONGLONG Sequence;
    KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROW Rows[
        KSWORD_ARK_STORAGE_CONTROLLER_AUDIT_ROWS];
} KSCC_AUDIT_STATE;

typedef struct _KSCC_DEVICE_CONTEXT {
    WDFDEVICE Device;
    WDFWAITLOCK IoLock;
    WDFDMAENABLER DmaEnabler;
    PUCHAR Bars[KSCC_MAX_BARS];
    ULONG BarLengths[KSCC_MAX_BARS];
    PHYSICAL_ADDRESS BarPhysical[KSCC_MAX_BARS];
    ULONG BarCount;
    ULONG RegisterBarIndex;
    PUCHAR IoPorts[KSCC_MAX_PORT_RANGES];
    ULONG IoPortLengths[KSCC_MAX_PORT_RANGES];
    ULONG IoPortCount;
    ULONG ControllerType;
    ULONG Capabilities;
    ULONG RiskFlags;
    ULONG Ownership;
    ULONG Coherency;
    ULONG Generation;
    ULONG PortOrNamespace;
    ULONG IdeControlPortIndex;
    ULONG LogicalSectorSize;
    ULONG PhysicalSectorSize;
    ULONG MaximumTransferBytes;
    ULONG PciSegment;
    ULONG PciBus;
    ULONG PciDevice;
    ULONG PciFunction;
    ULONG PciBarValues[KSCC_MAX_BARS];
    UCHAR PciProgIf;
    ULONG LastControllerStatus;
    NTSTATUS LastStatus;
    ULONGLONG CapacityBytes;
    ULONGLONG SessionId;
    BOOLEAN ResourcesPrepared;
    BOOLEAN Prepared;
    BOOLEAN HardwareActivated;
    BOOLEAN RequiresReset;
    BOOLEAN WriteObserved;
    BOOLEAN Acquired;
    BOOLEAN SystemDisk;
    WCHAR Model[KSWORD_ARK_STORAGE_CONTROLLER_MODEL_CHARS];
    WCHAR Serial[KSWORD_ARK_STORAGE_CONTROLLER_SERIAL_CHARS];
    WCHAR Detail[KSWORD_ARK_STORAGE_CONTROLLER_DETAIL_CHARS];
    KSCC_DMA_REGION Command;
    KSCC_DMA_REGION Completion;
    KSCC_DMA_REGION Data;
    KSCC_DMA_REGION Auxiliary;
    KSCC_DMA_REGION Prp;
    ULONG NvmeAdminTail;
    ULONG NvmeAdminHead;
    ULONG NvmeAdminPhase;
    ULONG NvmeIoTail;
    ULONG NvmeIoHead;
    ULONG NvmeIoPhase;
    PUCHAR Rollback;
    ULONG RollbackLength;
    ULONGLONG RollbackOffset;
    ULONGLONG RollbackSessionId;
    UCHAR RollbackBeforeHash[KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES];
    UCHAR RollbackAfterHash[KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES];
    BOOLEAN RollbackValid;
    KSCC_AUDIT_STATE Audit;
} KSCC_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(KSCC_DEVICE_CONTEXT, KsccGetContext);

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KsccEvtDeviceAdd;
EVT_WDF_DEVICE_PREPARE_HARDWARE KsccEvtPrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE KsccEvtReleaseHardware;
EVT_WDF_DEVICE_D0_ENTRY KsccEvtD0Entry;
EVT_WDF_DEVICE_D0_EXIT KsccEvtD0Exit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL KsccEvtIoDeviceControl;
EVT_WDF_OBJECT_CONTEXT_CLEANUP KsccEvtContextCleanup;

NTSTATUS KsccAllocateDmaRegion(
    _In_ KSCC_DEVICE_CONTEXT* Context,
    _Inout_ KSCC_DMA_REGION* Region,
    _In_ SIZE_T Length);
VOID KsccFreeDmaRegion(_Inout_ KSCC_DMA_REGION* Region);
VOID KsccResetIdentity(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccDetermineControllerType(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccValidatePciClass(_In_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccDetectAndInitialize(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccStopController(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccHardwareTransfer(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ BOOLEAN Write,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR* Buffer,
    _In_ ULONG Length,
    _In_ ULONG Flags,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus);
NTSTATUS KsccHardwareFlush(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus);

NTSTATUS KsccAhciInitialize(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccAhciStop(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccAhciTransfer(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ BOOLEAN Write,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR* Buffer,
    _In_ ULONG Length,
    _In_ ULONG Flags,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus);
NTSTATUS KsccAhciFlush(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus);

NTSTATUS KsccNvmeInitialize(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccNvmeStop(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccNvmeTransfer(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ BOOLEAN Write,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR* Buffer,
    _In_ ULONG Length,
    _In_ ULONG Flags,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus);
NTSTATUS KsccNvmeFlush(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus);

NTSTATUS KsccIdeInitialize(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccIdeStop(_Inout_ KSCC_DEVICE_CONTEXT* Context);
NTSTATUS KsccIdeTransfer(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ BOOLEAN Write,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR* Buffer,
    _In_ ULONG Length,
    _In_ ULONG Flags,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus);
NTSTATUS KsccIdeFlush(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus);

VOID KsccSha256(
    _In_reads_bytes_(Length) const UCHAR* Data,
    _In_ SIZE_T Length,
    _Out_writes_(KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES) UCHAR* Digest);
VOID KsccAuditAppend(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONGLONG SessionId,
    _In_ ULONGLONG Offset,
    _In_ ULONG Operation,
    _In_ ULONG Flags,
    _In_ ULONG RiskFlags,
    _In_ ULONG Length,
    _In_ ULONG BytesTransferred,
    _In_ ULONG Status,
    _In_ NTSTATUS LastStatus,
    _In_reads_(KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES) const UCHAR* BeforeHash,
    _In_reads_(KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES) const UCHAR* AfterHash);
VOID KsccHandleQuery(_In_ WDFREQUEST Request, _In_ KSCC_DEVICE_CONTEXT* Context);
VOID KsccHandleControl(_In_ WDFREQUEST Request, _Inout_ KSCC_DEVICE_CONTEXT* Context);
VOID KsccHandleTransfer(_In_ WDFREQUEST Request, _Inout_ KSCC_DEVICE_CONTEXT* Context);
VOID KsccHandleAudit(_In_ WDFREQUEST Request, _In_ KSCC_DEVICE_CONTEXT* Context);
