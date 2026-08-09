#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkProcessProtectIoctl.h"

EXTERN_C_START

/*
 * KswordARKProcessProtectInitialize
 * Inputs:
 * - Device 是控制设备，用于把保护命中写进 R3 日志通道。
 * Processing:
 * - 分配并发布保护配置快照的宿主状态。必须在 KswordARKCallbackInitialize
 *   之前调用，保证句柄回调一旦挂上就能读到已初始化的状态。
 * Return behavior:
 * - 分配失败返回 STATUS_INSUFFICIENT_RESOURCES；此时保护能力关闭，但驱动
 *   其余功能照常加载。
 */
NTSTATUS
KswordARKProcessProtectInitialize(
    _In_ WDFDEVICE Device
    );

/*
 * KswordARKProcessProtectUninitialize
 * Processing:
 * - 释放配置快照。调用方必须先注销对象回调（KswordARKCallbackUninitialize），
 *   否则仍在执行的前置回调会访问已释放内存。
 */
VOID
KswordARKProcessProtectUninitialize(
    VOID
    );

/*
 * KswordArkProcessProtectNoteObjectCallbackState
 * Inputs:
 * - Registered 表示 ObRegisterCallbacks 当前是否处于已注册状态；
 * - RegisterStatus 是最近一次注册尝试的原始 NTSTATUS。
 * Processing:
 * - 由对象回调模块在注册/注销时回填，使 R3 能区分"没配规则"与"这台机器上
 *   句柄回调根本挂不上"。
 */
VOID
KswordArkProcessProtectNoteObjectCallbackState(
    _In_ BOOLEAN Registered,
    _In_ NTSTATUS RegisterStatus
    );

/*
 * KswordArkProcessProtectFilterHandleOperation
 * Inputs:
 * - TargetIsThreadObject 区分被打开的是进程对象还是线程对象；
 * - TargetProcess 是目标进程（线程对象时为其宿主进程），可为 NULL；
 * - TargetImagePath / InitiatorImagePath 是调用方已解析好的映像路径，允许为空串，
 *   复用它们可以避免在句柄热路径上重复调用 SeLocateProcessImageName；
 * - DesiredAccess 指向对象管理器的请求访问掩码，命中保护时就地削位。
 * Processing:
 * - 依次判定总开关、信任白名单、规则表，命中后从 DesiredAccess 中去掉危险位，
 *   并累加统计与"最近一次拦截"快照。
 * Return behavior:
 * - 返回 TRUE 表示确实削掉了至少一位权限；FALSE 表示未命中或无需改动。
 */
BOOLEAN
KswordArkProcessProtectFilterHandleOperation(
    _In_ BOOLEAN TargetIsThreadObject,
    _In_opt_ PEPROCESS TargetProcess,
    _In_opt_z_ PCWSTR TargetImagePath,
    _In_opt_z_ PCWSTR InitiatorImagePath,
    _Inout_ ACCESS_MASK* DesiredAccess
    );

/*
 * KswordArkProcessProtectNotifyProcessCreate
 * Inputs:
 * - ProcessObject / ProcessId 是新建进程；
 * - ImageFileName 是创建通知给出的映像 NT 路径，可为 NULL。
 * Processing:
 * - 由进程创建回调调用。匹配到带 kernelProtection 的规则时，在进程开始执行前
 *   就把 PP/PPL 打上——这是"目标进程重启后保护还在"的唯一时机。
 * Return behavior:
 * - 无返回值；失败只累加计数并写日志，绝不阻断进程创建。
 */
VOID
KswordArkProcessProtectNotifyProcessCreate(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ProcessId,
    _In_opt_ PCUNICODE_STRING ImageFileName
    );

/*
 * KswordArkProcessProtectNotifyProcessExit
 * Processing:
 * - 由进程退出通知调用，把该 PID 移出自愈台账。
 */
VOID
KswordArkProcessProtectNotifyProcessExit(
    _In_ ULONG ProcessId
    );

/*
 * KswordARKProcessProtectIoctlSetConfig
 * Processing:
 * - 校验并整体替换保护配置。配置是一次性全量替换，不做增量合并。
 */
NTSTATUS
KswordARKProcessProtectIoctlSetConfig(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

/*
 * KswordARKProcessProtectIoctlQueryState
 * Processing:
 * - 回读当前配置、能力状态与统计计数器，供 R3 展示与核对。
 */
NTSTATUS
KswordARKProcessProtectIoctlQueryState(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    );

EXTERN_C_END
