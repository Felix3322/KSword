/*++

Module Name:

    io_timer_ioctl.c

Abstract:

    User-confirmed IoTimer start/stop control with exact object identity checks.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

/* 中文说明：设备对象数组来自非分页池，并使用独立 tag 便于池泄漏定位。 */
#define KSW_IO_TIMER_DEVICE_LIST_TAG 'rTIK'
/* 中文说明：复杂度上限防止异常 DriverObject 让单次控制分配无界增长。 */
#define KSW_IO_TIMER_DEVICE_LIMIT 1024UL
/* 中文说明：设备创建竞态只进行有限次重试，超过后按身份不稳定拒绝修改。 */
#define KSW_IO_TIMER_ENUM_RETRY_LIMIT 3UL

/* 中文说明：按名称取得 DriverObject，避免直接解引用 R3 提供的内核地址。 */
NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );

/* 中文说明：I/O manager 导出的 DriverObject 对象类型。 */
extern POBJECT_TYPE* IoDriverObjectType;

/* 中文说明：释放 IoEnumerateDeviceObjectList 为每个返回对象增加的引用。 */
static VOID
KswordARKIoTimerReleaseDeviceList(
    _Inout_updates_(Capacity) PDEVICE_OBJECT* DeviceObjects,
    _In_ ULONG Capacity
    )
{
    ULONG deviceIndex = 0UL;

    /* 中文说明：失败清理路径允许传入空数组。 */
    if (DeviceObjects == NULL) {
        /* 中文说明：空数组不包含对象引用。 */
        return;
    }
    /* 中文说明：遍历容量可同时覆盖成功与 BUFFER_TOO_SMALL 的部分结果。 */
    for (deviceIndex = 0UL; deviceIndex < Capacity; ++deviceIndex) {
        /* 中文说明：零初始化后的空槽没有引用。 */
        if (DeviceObjects[deviceIndex] == NULL) {
            /* 中文说明：跳过未由枚举 API 填充的槽位。 */
            continue;
        }
        /* 中文说明：归还 IoEnumerateDeviceObjectList 增加的引用。 */
        ObDereferenceObject(DeviceObjects[deviceIndex]);
        /* 中文说明：清空槽位使清理保持幂等。 */
        DeviceObjects[deviceIndex] = NULL;
    }
}

/* 中文说明：用官方带引用快照查找精确 DeviceObject，不追逐不稳定 NextDevice。 */
static NTSTATUS
KswordARKIoTimerReferenceExpectedDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONGLONG ExpectedDeviceObjectAddress,
    _Outptr_ PDEVICE_OBJECT* DeviceObjectOut
    )
{
    PDEVICE_OBJECT* deviceObjects = NULL;
    ULONG requestedCount = 0UL;
    ULONG actualCount = 0UL;
    ULONG attemptIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：输出始终先置空，调用方只在成功时取得一个对象引用。 */
    if (DriverObject == NULL || DeviceObjectOut == NULL ||
        ExpectedDeviceObjectAddress == 0ULL) {
        /* 中文说明：缺少任一身份参数时拒绝枚举。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：默认失败路径不向调用方泄漏悬空指针。 */
    *DeviceObjectOut = NULL;

    /* 中文说明：第一次调用只查询 DriverObject 当前拥有的设备数量。 */
    status = IoEnumerateDeviceObjectList(
        DriverObject,
        NULL,
        0UL,
        &requestedCount);
    /* 中文说明：零容量探测通常返回 BUFFER_TOO_SMALL，其它失败直接上报。 */
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status)) {
        /* 中文说明：保留 I/O manager 的原始失败状态。 */
        return status;
    }
    /* 中文说明：没有设备对象时目标快照已失效。 */
    if (requestedCount == 0UL) {
        /* 中文说明：用 NOT_FOUND 区分“驱动存在但设备已消失”。 */
        return STATUS_NOT_FOUND;
    }

    /* 中文说明：设备创建竞态可让容量在两次调用之间增长，因此有限重试。 */
    for (attemptIndex = 0UL;
        attemptIndex < KSW_IO_TIMER_ENUM_RETRY_LIMIT;
        ++attemptIndex) {
        ULONG deviceIndex = 0UL;

        /* 中文说明：拒绝异常复杂对象，避免单个 IOCTL 无界分配。 */
        if (requestedCount > KSW_IO_TIMER_DEVICE_LIMIT) {
            /* 中文说明：UI 可刷新后缩小范围，但 R0 不做不完整控制。 */
            return STATUS_BUFFER_OVERFLOW;
        }

        /* 中文说明：官方 API 要求 DeviceObject 指针数组位于非分页内存。 */
        deviceObjects = (PDEVICE_OBJECT*)KswordARKAllocateNonPagedPool(
            (SIZE_T)requestedCount * sizeof(*deviceObjects),
            KSW_IO_TIMER_DEVICE_LIST_TAG);
        /* 中文说明：分配失败时不触发任何目标回调。 */
        if (deviceObjects == NULL) {
            /* 中文说明：向 R3 报告明确资源不足。 */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /* 中文说明：清零使部分填充后的引用释放可以按容量安全扫描。 */
        RtlZeroMemory(
            deviceObjects,
            (SIZE_T)requestedCount * sizeof(*deviceObjects));
        /* 中文说明：每轮都由 I/O manager 回填当前实际对象总数。 */
        actualCount = 0UL;
        /* 中文说明：成功返回的每个对象都持有引用，控制期间不会被释放。 */
        status = IoEnumerateDeviceObjectList(
            DriverObject,
            deviceObjects,
            requestedCount * (ULONG)sizeof(*deviceObjects),
            &actualCount);
        /* 中文说明：容量增长时先完整释放本轮的部分引用再重试。 */
        if (status == STATUS_BUFFER_TOO_SMALL) {
            /* 中文说明：归还本轮每个非空对象引用。 */
            KswordARKIoTimerReleaseDeviceList(
                deviceObjects,
                requestedCount);
            /* 中文说明：释放旧容量数组。 */
            ExFreePoolWithTag(deviceObjects, KSW_IO_TIMER_DEVICE_LIST_TAG);
            /* 中文说明：清空局部指针避免失败路径重复释放。 */
            deviceObjects = NULL;
            /* 中文说明：实际数量必须增长才构成可重试的有效竞态。 */
            if (actualCount <= requestedCount) {
                /* 中文说明：不一致结果表示对象拓扑正在异常变化。 */
                return STATUS_INVALID_DEVICE_STATE;
            }
            /* 中文说明：下一轮按 API 返回的新数量分配。 */
            requestedCount = actualCount;
            /* 中文说明：进入下一次有限重试。 */
            continue;
        }
        /* 中文说明：其它枚举失败也必须释放可能已填充的引用。 */
        if (!NT_SUCCESS(status)) {
            /* 中文说明：释放所有非空槽位。 */
            KswordARKIoTimerReleaseDeviceList(
                deviceObjects,
                requestedCount);
            /* 中文说明：释放指针数组本身。 */
            ExFreePoolWithTag(deviceObjects, KSW_IO_TIMER_DEVICE_LIST_TAG);
            /* 中文说明：保留精确失败状态。 */
            return status;
        }

        /* 中文说明：成功时 actualCount 不应超过已分配容量。 */
        if (actualCount > requestedCount) {
            /* 中文说明：先释放所有引用再报告不一致。 */
            KswordARKIoTimerReleaseDeviceList(
                deviceObjects,
                requestedCount);
            /* 中文说明：释放指针数组。 */
            ExFreePoolWithTag(deviceObjects, KSW_IO_TIMER_DEVICE_LIST_TAG);
            /* 中文说明：不在不完整快照上执行修改。 */
            return STATUS_INVALID_DEVICE_STATE;
        }

        /* 中文说明：只把用户地址与已引用对象指针做数值比较，绝不直接解引用用户地址。 */
        for (deviceIndex = 0UL; deviceIndex < actualCount; ++deviceIndex) {
            /* 中文说明：防御性跳过 API 返回的空槽。 */
            if (deviceObjects[deviceIndex] == NULL) {
                /* 中文说明：继续检查其它已引用对象。 */
                continue;
            }
            /* 中文说明：精确匹配刷新时记录的 DeviceObject 身份。 */
            if ((ULONGLONG)(ULONG_PTR)deviceObjects[deviceIndex] ==
                ExpectedDeviceObjectAddress) {
                /* 中文说明：把该引用转交调用方，释放函数不得再处理它。 */
                *DeviceObjectOut = deviceObjects[deviceIndex];
                /* 中文说明：清空槽位表示引用所有权已转移。 */
                deviceObjects[deviceIndex] = NULL;
                /* 中文说明：匹配成功后无需继续扫描。 */
                break;
            }
        }

        /* 中文说明：归还除目标外所有快照引用。 */
        KswordARKIoTimerReleaseDeviceList(deviceObjects, requestedCount);
        /* 中文说明：释放临时指针数组。 */
        ExFreePoolWithTag(deviceObjects, KSW_IO_TIMER_DEVICE_LIST_TAG);
        /* 中文说明：避免后续路径误用已释放数组。 */
        deviceObjects = NULL;
        /* 中文说明：命中时调用方持有目标引用。 */
        if (*DeviceObjectOut != NULL) {
            /* 中文说明：稳定身份快照已建立。 */
            return STATUS_SUCCESS;
        }
        /* 中文说明：完整快照中没有该地址，说明设备已删除或重建。 */
        return STATUS_NOT_FOUND;
    }

    /* 中文说明：连续增长超过重试预算时拒绝在不稳定拓扑上修改。 */
    return STATUS_RETRY;
}

/* 中文说明：验证固定请求中的版本、动作、确认令牌和名称终止符。 */
static NTSTATUS
KswordARKIoTimerValidateRequest(
    _In_ const KSWORD_ARK_CONTROL_IO_TIMER_REQUEST* Request,
    _Out_ size_t* DriverNameCharsOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：所有固定参数都必须存在。 */
    if (Request == NULL || DriverNameCharsOut == NULL) {
        /* 中文说明：缺少请求或长度输出属于编程错误。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：默认长度为零，失败时不使用未初始化值。 */
    *DriverNameCharsOut = 0U;
    /* 中文说明：只接受当前协议版本。 */
    if (Request->version != KSWORD_ARK_IO_TIMER_CONTROL_PROTOCOL_VERSION) {
        /* 中文说明：旧/未来请求不得被误解释。 */
        return STATUS_REVISION_MISMATCH;
    }
    /* 中文说明：只允许公开 WDM 定义的启动与停止动作。 */
    if (Request->action != KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START &&
        Request->action != KSWORD_ARK_IO_TIMER_CONTROL_ACTION_STOP) {
        /* 中文说明：未知动作绝不降级执行。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：未知 flags 可能改变安全语义，因此全部拒绝。 */
    if ((Request->flags & ~KSWORD_ARK_IO_TIMER_CONTROL_FLAG_UI_CONFIRMED) != 0UL) {
        /* 中文说明：仅当前定义的 UI 确认位有效。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：内核再次要求显式 UI 确认，不能只依赖按钮状态。 */
    if ((Request->flags & KSWORD_ARK_IO_TIMER_CONTROL_FLAG_UI_CONFIRMED) == 0UL ||
        Request->confirmationToken != KSWORD_ARK_IO_TIMER_CONTROL_CONFIRMATION_TOKEN) {
        /* 中文说明：令牌或确认位缺失时拒绝修改。 */
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
    /* 中文说明：三重身份快照全部必须非零。 */
    if (Request->expectedDriverObjectAddress == 0ULL ||
        Request->expectedDeviceObjectAddress == 0ULL ||
        Request->expectedTimerAddress == 0ULL) {
        /* 中文说明：不允许用通配或空地址控制。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：验证固定名称数组在边界内存在 NUL。 */
    status = RtlStringCchLengthW(
        Request->driverName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
        DriverNameCharsOut);
    /* 中文说明：未终止字符串不能传入对象管理器。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：保留 ntstrsafe 的精确状态。 */
        return status;
    }
    /* 中文说明：控制协议只接受对象命名空间绝对路径。 */
    if (*DriverNameCharsOut == 0U || Request->driverName[0] != L'\\') {
        /* 中文说明：禁止裸名称回退，避免同名对象解析歧义。 */
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }
    /* 中文说明：请求满足固定协议约束。 */
    return STATUS_SUCCESS;
}

/* 中文说明：处理 IoTimer 启动/停止；所有业务逻辑位于 feature handler。 */
NTSTATUS
KswordARKKernelIoctlControlIoTimer(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t driverNameChars = 0U;
    KSWORD_ARK_CONTROL_IO_TIMER_REQUEST requestSnapshot;
    KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE* response = NULL;
    UNICODE_STRING driverObjectName;
    PDRIVER_OBJECT driverObject = NULL;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* 中文说明：风险只由 R3 告知用户；R0 不按风险等级设置额外功能门槛。 */
    UNREFERENCED_PARAMETER(Device);
    /* 中文说明：调用方必须提供返回长度存储。 */
    if (BytesReturned == NULL) {
        /* 中文说明：无法安全完成 WDF 请求。 */
        return STATUS_INVALID_PARAMETER;
    }
    /* 中文说明：所有失败路径默认不返回未初始化数据。 */
    *BytesReturned = 0U;
    /* 中文说明：CTL_CODE 与请求句柄都必须具备写访问。 */
    status = KswordARKValidateDeviceIoControlWriteAccess(Request);
    /* 中文说明：访问拒绝发生在解析任何目标身份之前。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：保留 WDF/安全校验状态。 */
        return status;
    }
    /* 中文说明：取得完整固定请求缓冲。 */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_CONTROL_IO_TIMER_REQUEST),
        &inputBuffer,
        &actualInputLength);
    /* 中文说明：同时核对 dispatch 提供长度与 WDF 实际长度。 */
    if (!NT_SUCCESS(status) ||
        InputBufferLength < sizeof(KSWORD_ARK_CONTROL_IO_TIMER_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_CONTROL_IO_TIMER_REQUEST)) {
        /* 中文说明：成功但长度不足时统一返回结构长度不匹配。 */
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }
    /* 中文说明：取得完整固定响应缓冲。 */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    /* 中文说明：输出不足时不执行任何控制动作。 */
    if (!NT_SUCCESS(status) ||
        OutputBufferLength < sizeof(KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE)) {
        /* 中文说明：保留 WDF 状态或返回 BUFFER_TOO_SMALL。 */
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    /* 中文说明：METHOD_BUFFERED 输入输出可能共享 SystemBuffer，清零前先复制请求。 */
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
    /* 中文说明：响应只暴露本次重新观察到的身份与状态。 */
    response = (KSWORD_ARK_CONTROL_IO_TIMER_RESPONSE*)outputBuffer;
    /* 中文说明：清除共享缓冲中的旧请求与未初始化尾部。 */
    RtlZeroMemory(response, sizeof(*response));
    /* 中文说明：设置固定响应版本。 */
    response->version = KSWORD_ARK_IO_TIMER_CONTROL_PROTOCOL_VERSION;
    /* 中文说明：设置固定响应大小供 R3 校验。 */
    response->size = sizeof(*response);
    /* 中文说明：动作回显帮助 UI 对异步刷新后的结果归因。 */
    response->action = requestSnapshot.action;
    /* 中文说明：在完成固定响应后，语义失败也返回可解析状态包。 */
    *BytesReturned = sizeof(*response);

    /* 中文说明：先验证版本、动作、令牌、地址和对象名。 */
    status = KswordARKIoTimerValidateRequest(
        &requestSnapshot,
        &driverNameChars);
    /* 中文说明：格式错误不会进入对象管理器或触及目标对象。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：记录协议级失败。 */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_INVALID_REQUEST;
        /* 中文说明：保留精确 NTSTATUS 供 UI 诊断。 */
        response->lastStatus = status;
        /* 中文说明：传输成功使 R3 可以读取结构化语义错误。 */
        return STATUS_SUCCESS;
    }

    /* 中文说明：构造已验证、NUL 终止的对象名。 */
    RtlInitUnicodeString(&driverObjectName, requestSnapshot.driverName);
    /* 中文说明：对象类型导出不可用时不尝试无类型引用。 */
    if (IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        /* 中文说明：把平台缺失归类为驱动对象不可解析。 */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_NOT_FOUND;
        /* 中文说明：使用 NOT_SUPPORTED 表明并非用户地址错误。 */
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* 中文说明：固定响应可安全返回。 */
        return STATUS_SUCCESS;
    }
    /* 中文说明：按绝对名称取得受对象管理器保护的 DriverObject 引用。 */
    status = ObReferenceObjectByName(
        &driverObjectName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0UL,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)&driverObject);
    /* 中文说明：名称消失或类型不符时不使用 R3 地址回退。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：返回对象已消失的语义状态。 */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_NOT_FOUND;
        /* 中文说明：保留对象管理器失败状态。 */
        response->lastStatus = status;
        /* 中文说明：未取得引用，无需清理。 */
        return STATUS_SUCCESS;
    }

    /* 中文说明：响应记录由名称重新解析出的真实 DriverObject。 */
    response->observedDriverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
    /* 中文说明：地址与刷新快照不一致说明对象已卸载并可能复用了名称。 */
    if (response->observedDriverObjectAddress !=
        requestSnapshot.expectedDriverObjectAddress) {
        /* 中文说明：拒绝把旧快照应用到同名新驱动。 */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DRIVER_IDENTITY_CHANGED;
        /* 中文说明：使用重试状态提示用户刷新。 */
        response->lastStatus = STATUS_RETRY;
        /* 中文说明：归还按名称取得的 DriverObject 引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：结构化失败包正常返回。 */
        return STATUS_SUCCESS;
    }

    /* 中文说明：用官方快照 API 取得目标 DeviceObject 的独立引用。 */
    status = KswordARKIoTimerReferenceExpectedDevice(
        driverObject,
        requestSnapshot.expectedDeviceObjectAddress,
        &deviceObject);
    /* 中文说明：完整快照找不到目标时禁止修改。 */
    if (!NT_SUCCESS(status)) {
        /* 中文说明：NOT_FOUND 表示旧设备对象已消失，其它值表示枚举失败。 */
        response->status = status == STATUS_NOT_FOUND
            ? KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DEVICE_NOT_FOUND
            : KSWORD_ARK_IO_TIMER_CONTROL_STATUS_ENUMERATION_FAILED;
        /* 中文说明：保留精确枚举状态。 */
        response->lastStatus = status;
        /* 中文说明：设备引用未取得，只归还 DriverObject。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：结构化失败包正常返回。 */
        return STATUS_SUCCESS;
    }

    /* 中文说明：响应记录本次带引用快照中的真实 DeviceObject。 */
    response->observedDeviceObjectAddress = (ULONGLONG)(ULONG_PTR)deviceObject;
    /* 中文说明：再次校验对象归属，防御异常或损坏的设备列表。 */
    if (deviceObject->DriverObject != driverObject) {
        /* 中文说明：归属不一致时不能调用 IoStartTimer/IoStopTimer。 */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_DEVICE_IDENTITY_CHANGED;
        /* 中文说明：报告对象类型/归属不匹配。 */
        response->lastStatus = STATUS_OBJECT_TYPE_MISMATCH;
        /* 中文说明：归还目标 DeviceObject 引用。 */
        ObDereferenceObject(deviceObject);
        /* 中文说明：归还 DriverObject 引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：结构化失败包正常返回。 */
        return STATUS_SUCCESS;
    }

    /* 中文说明：只读取 WDK 公开 DEVICE_OBJECT.Timer 字段，不解引用 PIO_TIMER。 */
    response->observedTimerAddress = (ULONGLONG)(ULONG_PTR)deviceObject->Timer;
    /* 中文说明：空 Timer 表示驱动未注册或已清理 IoTimer。 */
    if (deviceObject->Timer == NULL) {
        /* 中文说明：明确区分没有计时器与地址变化。 */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_TIMER_NOT_PRESENT;
        /* 中文说明：使用 NOT_FOUND 表示公开字段已为空。 */
        response->lastStatus = STATUS_NOT_FOUND;
        /* 中文说明：归还 DeviceObject 引用。 */
        ObDereferenceObject(deviceObject);
        /* 中文说明：归还 DriverObject 引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：结构化失败包正常返回。 */
        return STATUS_SUCCESS;
    }
    /* 中文说明：计时器地址变化说明原计时器已被清理并重新初始化。 */
    if (response->observedTimerAddress != requestSnapshot.expectedTimerAddress) {
        /* 中文说明：拒绝把旧行控制动作应用到新计时器。 */
        response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_TIMER_IDENTITY_CHANGED;
        /* 中文说明：提示 R3 刷新后重新确认。 */
        response->lastStatus = STATUS_RETRY;
        /* 中文说明：归还 DeviceObject 引用。 */
        ObDereferenceObject(deviceObject);
        /* 中文说明：归还 DriverObject 引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：结构化失败包正常返回。 */
        return STATUS_SUCCESS;
    }

    /* 中文说明：风险告知后不再按高级模式或风险等级拒绝，直接调用公开 WDM API。 */
    if (requestSnapshot.action == KSWORD_ARK_IO_TIMER_CONTROL_ACTION_START) {
        /* 中文说明：启用已由目标驱动通过 IoInitializeTimer 注册的回调。 */
        IoStartTimer(deviceObject);
    }
    else {
        /* 中文说明：停止后可由同一公开 API 再次启用，不修改私有字段。 */
        IoStopTimer(deviceObject);
    }

    /* 中文说明：两个 WDM API 都返回 VOID，成功表示调用已被接受。 */
    response->status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_OK;
    /* 中文说明：VOID API 没有可返回的运行态，因此记录 STATUS_SUCCESS。 */
    response->lastStatus = STATUS_SUCCESS;
    /* 中文说明：归还控制期间持有的 DeviceObject 引用。 */
    ObDereferenceObject(deviceObject);
    /* 中文说明：归还按名称持有的 DriverObject 引用。 */
    ObDereferenceObject(driverObject);
    /* 中文说明：固定响应已完整写入。 */
    return STATUS_SUCCESS;
}
