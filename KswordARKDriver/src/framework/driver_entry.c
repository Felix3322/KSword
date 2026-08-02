/*++

Module Name:

    driver_entry.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_mutation.h"
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
    // 系统变速加载阶段只准备同步和 DPC，不会在用户确认前修改系统计时源。
    KswordARKSystemTimeInitialize();
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

    // 通用 IRP 编辑器不依赖 blind 的目标策略；只初始化事务表和自身身份。
    status = KswordARKDriverDispatchInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKDriverDispatchInitialize unavailable %!STATUS!", status);
    }

    // 驱动映像编辑器保存自身身份；DynData/加载器能力在每次请求时实时解析。
    status = KswordARKDriverImageInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_DRIVER, "KswordARKDriverImageInitialize unavailable %!STATUS!", status);
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
        // 框架失败时对称撤销系统变速状态，确保维护 DPC 不会残留。
        KswordARKSystemTimeUninitialize();
        // 中文说明：框架创建失败时撤销通信控制状态和所有潜在引用。
        // 先恢复映像字段和加载器链，再恢复 IRP/communication 槽位。
        KswordARKDriverImageUninitialize();
        KswordARKDriverDispatchUninitialize();
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
        // 控制设备不可见时不会有合法变速请求，立即释放其运行时状态。
        KswordARKSystemTimeUninitialize();
        // 中文说明：控制设备创建失败时不保留通信控制全局状态。
        // 映像事务可能持有其它 DriverObject 引用，必须在失败返回前释放。
        KswordARKDriverImageUninitialize();
        KswordARKDriverDispatchUninitialize();
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
        // 回调初始化回滚必须同时撤销可能的系统变速维护对象。
        KswordARKSystemTimeUninitialize();
        // 中文说明：回调初始化失败返回前撤销通信控制状态。
        // 对称恢复仍由映像事务拥有的字段和加载器链。
        KswordARKDriverImageUninitialize();
        KswordARKDriverDispatchUninitialize();
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

    // 最先停止系统计时钩子并恢复原始 HAL 槽，防止卸载后回调到本驱动映像。
    KswordARKSystemTimeUninitialize();
    // 中文说明：最先恢复仍由本功能持有的 MajorFunction，并释放目标 DriverObject 引用。
    // 先撤销任意槽位编辑，再恢复可能位于其下层的五槽 communication blind。
    // 映像字段或加载器链可能包含自身身份，必须在驱动映像离开前优先恢复。
    KswordARKDriverImageUninitialize();
    KswordARKDriverDispatchUninitialize();
    KswordARKDriverCommunicationUninitialize();
    // Release all VMX/VMCS/EPT pages before the driver image can leave memory.
    KswordARKHvmUninitialize();
    // IOCTL 已停止后释放只读 IDT 基线，避免卸载后保留本驱动分配。
    KswordARKIdtBaselineUninitialize();
    // 释放危险写事务为防 PID 复用而持有的请求进程对象引用。
    KswordARKMutationUninitialize();
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
    // 先注销会进入回调规则层的 minifilter，并等待其 post-operation 回调全部退出。
    KswordARKFileMonitorUninitialize();
    // minifilter 已停止后才销毁 callback runtime，避免 post-operation 路径访问已释放状态。
    KswordARKCallbackUninitialize();
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
