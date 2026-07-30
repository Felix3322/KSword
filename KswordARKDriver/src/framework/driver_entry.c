/*++

Module Name:

    driver_entry.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "src/features/kernel/kernel_idt_baseline.h"
#include "src/features/hvm/hvm_runtime.h"
#include "driver_entry.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KswordARKDriverEvtDriverUnload)
#pragma alloc_text (PAGE, KswordARKDriverEvtDriverContextCleanup)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    DriverEntry initializes the driver and is the first routine called by the
    system after the driver is loaded.

Arguments:

    DriverObject - represents the instance of the function driver that is loaded
    into memory.
    RegistryPath - represents the driver specific path in the Registry.

Return Value:

    NTSTATUS

--*/
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driverHandle = WDF_NO_HANDLE;
    WDFDEVICE controlDevice = WDF_NO_HANDLE;

    // Initialize WPP tracing as soon as possible.
    WPP_INIT_TRACING(DriverObject, RegistryPath);
    KswordARKCapabilityInitialize();
    KswordARKTrustInitialize();
    KswordARKSafetyInitialize();
    // 在控制设备可见前捕获每 CPU 的不可变 IDT 基线；失败只禁用该诊断功能。
    status = KswordARKIdtBaselineInitialize();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKIdtBaselineInitialize unavailable %!STATUS!", status);
    }
    /*
     * HVM startup is read-only: capture CPU/MSR capability state now, while
     * all VMX/EPT allocations and tests remain explicit UI lifecycle actions.
     */
    status = KswordARKHvmInitialize();
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKHvmInitialize unavailable %!STATUS!", status);
    }
    // 在线程控制 IOCTL 可见前初始化 APC 注册表和卸载排空事件。
    KswordARKThreadApcInitialize();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    // 中文说明：必须在 WdfDriverCreate 安装框架 dispatch 前捕获 I/O 管理器的内核拒绝入口。
    status = KswordARKDriverCommunicationInitialize(DriverObject);
    // 中文说明：通信控制是可选功能；无法证明内核拒绝入口时只禁用该功能。
    if (!NT_SUCCESS(status)) {
        // 中文说明：保留其它 KSword 能力可用，同时让新 IOCTL 返回 DEVICE_NOT_READY。
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKDriverCommunicationInitialize unavailable %!STATUS!", status);
    }

    // Register cleanup callback for WPP_CLEANUP during framework teardown.
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = KswordARKDriverEvtDriverContextCleanup;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = KswordARKDriverEvtDriverUnload;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &config,
        &driverHandle);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        // 中文说明：框架创建失败时撤销通信控制状态和所有潜在引用。
        KswordARKDriverCommunicationUninitialize();
        // Release the optional HVM capability state on early framework failure.
        KswordARKHvmUninitialize();
        // Release the boot-captured IDT table when framework creation fails.
        KswordARKIdtBaselineUninitialize();
        // DriverEntry 失败时关闭 APC 接收状态，保持初始化与退出路径对称。
        KswordARKThreadApcUninitialize();
        WPP_CLEANUP(DriverObject);
        return status;
    }

    status = KswordARKDriverCreateControlDevice(driverHandle, &controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "KswordARKDriverCreateControlDevice failed %!STATUS!", status);
        // 中文说明：控制设备创建失败时不保留通信控制全局状态。
        KswordARKDriverCommunicationUninitialize();
        // Release the optional HVM capability state on early device failure.
        KswordARKHvmUninitialize();
        // Release the boot-captured IDT table when the control device is absent.
        KswordARKIdtBaselineUninitialize();
        // 控制设备不可用时不会接受线程请求，立即关闭 APC 生命周期管理。
        KswordARKThreadApcUninitialize();
        WPP_CLEANUP(DriverObject);
        return status;
    }

    status = KswordARKCallbackInitialize(controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "KswordARKCallbackInitialize failed %!STATUS!", status);
        WdfObjectDelete(controlDevice);
        // 中文说明：回调初始化失败返回前撤销通信控制状态。
        KswordARKDriverCommunicationUninitialize();
        // Release any explicit HVM resources before returning initialization failure.
        KswordARKHvmUninitialize();
        // Release the boot-captured IDT table on callback initialization rollback.
        KswordARKIdtBaselineUninitialize();
        // 初始化回滚必须排空潜在并发请求，防止失败返回后遗留回调。
        KswordARKThreadApcUninitialize();
        WPP_CLEANUP(DriverObject);
        return status;
    }

    status = KswordARKRedirectInitialize(DriverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKRedirectInitialize recorded failure %!STATUS!", status);
    }

    status = KswordARKNetworkInitialize(DriverObject, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKNetworkInitialize recorded failure %!STATUS!", status);
    }

    status = KswordARKFileMonitorInitialize(DriverObject, RegistryPath, controlDevice);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKFileMonitorInitialize recorded failure %!STATUS!", status);
    }

    // VMware bugcheck diagnostics are strictly optional. The initializer
    // returns without registering callbacks on every unsupported environment.
    (void)KswordARKBugcheckInitialize(DriverObject, controlDevice);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}

VOID
KswordARKDriverEvtDriverUnload(
    _In_ WDFDRIVER Driver
    )
/*++

Routine Description:

    Called when SCM requests to unload the non-PnP control driver.

Arguments:

    Driver - Handle to a WDF Driver object.

Return Value:

    VOID

--*/
{
    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    // 中文说明：最先恢复仍由本功能持有的 MajorFunction，并释放目标 DriverObject 引用。
    KswordARKDriverCommunicationUninitialize();
    // Release all VMX/VMCS/EPT pages before the driver image can leave memory.
    KswordARKHvmUninitialize();
    // IOCTL 已停止后释放只读 IDT 基线，避免卸载后保留本驱动分配。
    KswordARKIdtBaselineUninitialize();
    // 随后停止并排空所有可能回调到本驱动映像的线程终止 APC。
    KswordARKThreadApcUninitialize();

    // Stop crash callbacks before any other teardown can invalidate state used
    // by the nonpaged diagnostic path.
    KswordARKBugcheckUninitialize();

    // 必须先注销内核调试回调，防止后续卸载阶段再次进入本驱动代码。
    KswordARKDebugOutputUninitialize();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");
    KswordARKNetworkUninitialize();
    KswordARKRedirectUninitialize();
    KswordARKCallbackUninitialize();
    KswordARKFileMonitorUninitialize();
    KswordARKDynDataUninitialize();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
}

VOID
KswordARKDriverEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
/*++

Routine Description:

    Free all the resources allocated in DriverEntry.

Arguments:

    DriverObject - handle to a WDF Driver object.

Return Value:

    VOID.

--*/
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    // Stop WPP tracing.
    WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)DriverObject));
}
