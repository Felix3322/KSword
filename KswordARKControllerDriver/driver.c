#include "controller.h"

/*
 * DriverEntry creates a normal PnP KMDF driver.  This is intentionally not a
 * filter: a successful start means PnP granted this driver the translated BAR
 * and port resources and therefore exclusive ownership of the device stack.
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;

    WDF_DRIVER_CONFIG_INIT(&config, KsccEvtDeviceAdd);
    return WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE);
}

/*
 * DeviceAdd installs PnP resource callbacks and one sequential IOCTL queue.
 * Sequential dispatch combines with IoLock to keep command queues single-owner.
 */
NTSTATUS
KsccEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpCallbacks;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFDEVICE device;
    KSCC_DEVICE_CONTEXT* context;
    static const GUID interfaceGuid =
        KSWORD_ARK_STORAGE_CONTROLLER_INTERFACE_GUID_INIT;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Driver);
    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(DeviceInit, TRUE);

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpCallbacks);
    pnpCallbacks.EvtDevicePrepareHardware = KsccEvtPrepareHardware;
    pnpCallbacks.EvtDeviceReleaseHardware = KsccEvtReleaseHardware;
    pnpCallbacks.EvtDeviceD0Entry = KsccEvtD0Entry;
    pnpCallbacks.EvtDeviceD0Exit = KsccEvtD0Exit;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpCallbacks);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, KSCC_DEVICE_CONTEXT);
    attributes.EvtCleanupCallback = KsccEvtContextCleanup;
    /*
     * Controller requests take a WDFWAITLOCK and audit the caller token.
     * Both operations require PASSIVE_LEVEL, so make the device callback
     * contract explicit instead of relying on the queue's caller IRQL.
     */
    attributes.ExecutionLevel = WdfExecutionLevelPassive;
    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    context = KsccGetContext(device);
    RtlZeroMemory(context, sizeof(*context));
    context->Device = device;
    context->Ownership = KSWORD_ARK_STORAGE_OWNERSHIP_NONE;
    context->Coherency = KSWORD_ARK_STORAGE_COHERENCY_UNKNOWN;
    context->RiskFlags =
        KSWORD_ARK_STORAGE_CONTROLLER_RISK_SYSTEM_DISK_UNKNOWN |
        KSWORD_ARK_STORAGE_CONTROLLER_RISK_LIVE_VOLUMES_UNKNOWN |
        KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE;
    context->LogicalSectorSize = 512U;
    context->PhysicalSectorSize = 512U;
    context->MaximumTransferBytes = KSWORD_ARK_STORAGE_CONTROLLER_MAX_TRANSFER_BYTES;
    context->PciSegment = MAXULONG;
    context->PciBus = MAXULONG;
    context->PciDevice = MAXULONG;
    context->PciFunction = MAXULONG;
    context->LastControllerStatus = MAXULONG;
    context->LastStatus = STATUS_NOT_FOUND;
    context->Rollback = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        KSCC_BACKUP_BYTES,
        KSCC_POOL_TAG);
    if (context->Rollback == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeInitializeSpinLock(&context->Audit.Lock);

    /*
     * Determine class/subclass/prog-if from PnP compatible IDs before
     * PrepareHardware is allowed to touch any translated register resource.
     */
    status = KsccDetermineControllerType(context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->IoLock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfDeviceCreateDeviceInterface(device, &interfaceGuid, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = KsccEvtIoDeviceControl;
    return WdfIoQueueCreate(
        device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE);
}

/* Release the non-WDF rollback snapshot when the PnP device object is deleted. */
VOID
KsccEvtContextCleanup(
    _In_ WDFOBJECT Object)
{
    KSCC_DEVICE_CONTEXT* context;

    context = KsccGetContext((WDFDEVICE)Object);
    if (context->Rollback != NULL) {
        RtlSecureZeroMemory(context->Rollback, KSCC_BACKUP_BYTES);
        ExFreePoolWithTag(context->Rollback, KSCC_POOL_TAG);
        context->Rollback = NULL;
    }
}
