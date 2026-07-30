#pragma once

#include "ark/ark_driver.h"

/* 中文说明：最多同时保存三十二个按模块基址唯一标识的 DriverObject 状态。 */
#define KSW_DRIVER_COMMUNICATION_RECORD_LIMIT 32UL
/* 中文说明：本功能只覆盖五个通信入口，不触碰生命周期和 FastIo。 */
#define KSW_DRIVER_COMMUNICATION_SLOT_COUNT 5UL

/* 中文说明：一个固定槽把协议 mask 映射到公开 IRP major 索引。 */
typedef struct _KSW_DRIVER_COMMUNICATION_SLOT
{
    ULONG Mask;
    UCHAR MajorFunction;
} KSW_DRIVER_COMMUNICATION_SLOT, *PKSW_DRIVER_COMMUNICATION_SLOT;

/* 中文说明：一个记录保存一次可逆替换所需的完整目标身份和原入口。 */
typedef struct _KSW_DRIVER_COMMUNICATION_RECORD
{
    BOOLEAN InUse;
    UCHAR Padding[3];
    ULONG Generation;
    /* 中文说明：只包含本功能实际 CAS 安装且仍可安全恢复的槽。 */
    ULONG OwnedMask;
    /* 中文说明：表示五个目标槽中当前实际指向内核 reject 的集合。 */
    ULONG ActiveMask;
    /* 中文说明：永久锁存已观察 foreign/ABA 的槽，记录删除前不清除。 */
    ULONG ConflictMask;
    /* 中文说明：锁存本功能曾成功安装且仍需监控 ABA 的槽域。 */
    ULONG InstalledMask;
    /* 中文说明：使用请求提供且完成解析验证的不可变模块基址作为记录键。 */
    ULONGLONG TargetModuleBase;
    PDRIVER_OBJECT DriverObject;
    PDRIVER_DISPATCH OriginalDispatch[KSW_DRIVER_COMMUNICATION_SLOT_COUNT];
    WCHAR CanonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KSW_DRIVER_COMMUNICATION_RECORD, *PKSW_DRIVER_COMMUNICATION_RECORD;

/* 中文说明：全局状态只在 PASSIVE_LEVEL 控制路径和驱动卸载路径访问。 */
typedef struct _KSW_DRIVER_COMMUNICATION_STATE
{
    FAST_MUTEX Lock;
    volatile LONG Initialized;
    BOOLEAN ShuttingDown;
    UCHAR Padding[3];
    ULONG Generation;
    PDRIVER_OBJECT SelfDriverObject;
    PDRIVER_DISPATCH RejectDispatch;
    KSW_DRIVER_COMMUNICATION_RECORD Records[KSW_DRIVER_COMMUNICATION_RECORD_LIMIT];
} KSW_DRIVER_COMMUNICATION_STATE, *PKSW_DRIVER_COMMUNICATION_STATE;

/* 中文说明：动作后端只通过这些内部符号访问状态核心。 */
extern const KSW_DRIVER_COMMUNICATION_SLOT
g_KswordArkDriverCommunicationSlots[KSW_DRIVER_COMMUNICATION_SLOT_COUNT];
extern KSW_DRIVER_COMMUNICATION_STATE
g_KswordArkDriverCommunicationState;

PDRIVER_DISPATCH
KswordARKDriverCommunicationReadDispatch(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ UCHAR MajorFunction
    );

PDRIVER_DISPATCH
KswordARKDriverCommunicationCompareExchangeDispatch(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ UCHAR MajorFunction,
    _In_ PDRIVER_DISPATCH Exchange,
    _In_ PDRIVER_DISPATCH Expected
    );

VOID
KswordARKDriverCommunicationAdvanceGenerationLocked(
    _Inout_opt_ KSW_DRIVER_COMMUNICATION_RECORD* Record
    );

KSW_DRIVER_COMMUNICATION_RECORD*
KswordARKDriverCommunicationFindRecordLocked(
    _In_ ULONGLONG TargetModuleBase
    );

KSW_DRIVER_COMMUNICATION_RECORD*
KswordARKDriverCommunicationAllocateRecordLocked(
    VOID
    );

VOID
KswordARKDriverCommunicationRefreshRecordLocked(
    _Inout_ KSW_DRIVER_COMMUNICATION_RECORD* Record
    );

VOID
KswordARKDriverCommunicationFillResponse(
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response,
    _In_ ULONG Action,
    _In_ NTSTATUS Status,
    _In_ ULONG ChangedMask,
    _In_opt_ const KSW_DRIVER_COMMUNICATION_RECORD* Record,
    _In_opt_ PDRIVER_OBJECT DriverObject,
    _In_opt_z_ const WCHAR* CanonicalName
    );

NTSTATUS
KswordARKDriverCommunicationValidateTarget(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_z_ const WCHAR* CanonicalName
    );

NTSTATUS
KswordARKDriverCommunicationQuery(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response
    );

NTSTATUS
KswordARKDriverCommunicationBlind(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response
    );

NTSTATUS
KswordARKDriverCommunicationRestore(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* Request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* Response
    );
