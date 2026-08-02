#pragma once

#include <ntifs.h>

#include "ark/ark_driver.h"
#include "driver_integrity.h"

// 中文说明：事务表上限限制持有的 DriverObject 引用数量，避免无界内核池增长。
#define KSW_DRIVER_IMAGE_RECORD_LIMIT 128UL
// 中文说明：模块链遍历采用固定预算，损坏或成环时不会无限循环。
#define KSW_DRIVER_IMAGE_LIST_WALK_LIMIT 4096UL

// 中文说明：运行时描述保存身份匹配的 ntoskrnl、KLDR 偏移和两个精确导出地址。
typedef struct _KSW_DRIVER_IMAGE_RUNTIME
{
    KSW_DYN_STATE DynState;
    PLIST_ENTRY ListHead;
    PERESOURCE ListResource;
    ULONG LayoutFlags;
    BOOLEAN ResourceAcquired;
    BOOLEAN ResourceExclusive;
    UCHAR Reserved0[2];
} KSW_DRIVER_IMAGE_RUNTIME, *PKSW_DRIVER_IMAGE_RUNTIME;

// 中文说明：链视图只描述一次受 PsLoadedModuleResource 保护的观察结果。
typedef struct _KSW_DRIVER_IMAGE_LINK_VIEW
{
    BOOLEAN LoaderAvailable;
    BOOLEAN InList;
    BOOLEAN SelfLinked;
    BOOLEAN Malformed;
    ULONGLONG EntryAddress;
    ULONGLONG LinkAddress;
    ULONGLONG DllBase;
    ULONG SizeOfImage;
    ULONG Reserved0;
    PLIST_ENTRY Flink;
    PLIST_ENTRY Blink;
} KSW_DRIVER_IMAGE_LINK_VIEW, *PKSW_DRIVER_IMAGE_LINK_VIEW;

// 中文说明：单目标记录保存不可变原值、最近应用值和原始链邻居。
typedef struct _KSW_DRIVER_IMAGE_RECORD
{
    BOOLEAN InUse;
    BOOLEAN LinkManaged;
    BOOLEAN LinkOwned;
    BOOLEAN LinkConflict;
    ULONG Generation;
    ULONG OriginalFieldMask;
    ULONG ManagedFieldMask;
    ULONG OwnedFieldMask;
    ULONG ConflictFieldMask;
    ULONGLONG TargetModuleBase;
    PDRIVER_OBJECT DriverObject;
    PVOID LoaderEntry;
    PLIST_ENTRY LoaderLink;
    PLIST_ENTRY OriginalLinkFlink;
    PLIST_ENTRY OriginalLinkBlink;
    KSWORD_ARK_DRIVER_IMAGE_VALUES OriginalValues;
    KSWORD_ARK_DRIVER_IMAGE_VALUES AppliedValues;
    WCHAR CanonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KSW_DRIVER_IMAGE_RECORD, *PKSW_DRIVER_IMAGE_RECORD;

// 中文说明：全局事务表使用 FAST_MUTEX 串行化记录代次和多字段回滚。
typedef struct _KSW_DRIVER_IMAGE_STATE
{
    FAST_MUTEX Lock;
    volatile LONG Initialized;
    BOOLEAN ShuttingDown;
    UCHAR Reserved0[3];
    ULONG Generation;
    PDRIVER_OBJECT SelfDriverObject;
    KSW_DRIVER_IMAGE_RECORD Records[KSW_DRIVER_IMAGE_RECORD_LIMIT];
} KSW_DRIVER_IMAGE_STATE, *PKSW_DRIVER_IMAGE_STATE;

// 中文说明：响应上下文把一次动作结果和受锁快照集中传给统一序列化器。
typedef struct _KSW_DRIVER_IMAGE_RESPONSE_CONTEXT
{
    const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request;
    const KSW_DRIVER_IMAGE_RECORD* Record;
    const KSW_DRIVER_IMAGE_RUNTIME* Runtime;
    NTSTATUS LastStatus;
    NTSTATUS LoaderStatus;
    ULONG ChangedFieldMask;
    BOOLEAN RecordPresent;
    BOOLEAN LinkChanged;
    BOOLEAN RestoredOriginalPosition;
    BOOLEAN RestoredListTail;
} KSW_DRIVER_IMAGE_RESPONSE_CONTEXT, *PKSW_DRIVER_IMAGE_RESPONSE_CONTEXT;

// 中文说明：解析器只接受当前 ntoskrnl 精确导出的链头和资源锁。
NTSTATUS
KswordARKDriverImageResolveRuntime(
    _Out_ KSW_DRIVER_IMAGE_RUNTIME* Runtime
    );

// 中文说明：调用方在 PASSIVE/APC_LEVEL 进入临界区后取得共享或独占资源。
NTSTATUS
KswordARKDriverImageAcquireRuntime(
    _Inout_ KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ BOOLEAN Exclusive
    );

// 中文说明：释放函数与 AcquireRuntime 严格成对，并恢复普通内核 APC。
VOID
KswordARKDriverImageReleaseRuntime(
    _Inout_ KSW_DRIVER_IMAGE_RUNTIME* Runtime
    );

// 中文说明：初次事务按精确 DllBase 定位 KLDR 项并核验当前链状态。
NTSTATUS
KswordARKDriverImageLocateLoaderLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ ULONGLONG DriverStart,
    _Out_ KSW_DRIVER_IMAGE_LINK_VIEW* View
    );

// 中文说明：已有事务使用保存的 loader/link 地址刷新成员关系与 KLDR 值。
NTSTATUS
KswordARKDriverImageInspectRecordLinkLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ const KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ KSW_DRIVER_IMAGE_LINK_VIEW* View
    );

// 中文说明：摘链前要求精确 Flink/Blink 期望值，成功后把目标项自环。
NTSTATUS
KswordARKDriverImageHideLinkLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ PLIST_ENTRY ExpectedFlink,
    _In_ PLIST_ENTRY ExpectedBlink,
    _Out_ BOOLEAN* Changed
    );

// 中文说明：恢复优先插回原邻居；原邻居消失时在同一资源锁下插入链尾。
NTSTATUS
KswordARKDriverImageRestoreLinkLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ BOOLEAN* Changed,
    _Out_ BOOLEAN* OriginalPosition
    );

// 中文说明：字段读取始终原子采样；KLDR 字段还要求持有真实模块资源。
NTSTATUS
KswordARKDriverImageReadValuesLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ const KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_VALUES* Values,
    _Out_ ULONG* AvailableFieldMask
    );

// 中文说明：多字段应用使用逐字段 CAS；中途失败会反向 CAS 回滚已写字段。
NTSTATUS
KswordARKDriverImageApplyFieldsLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ ULONG FieldMask,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* ExpectedValues,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* DesiredValues,
    _Out_ ULONG* ChangedFieldMask,
    _Out_ ULONG* RollbackConflictMask
    );

// 中文说明：恢复只把仍等于本事务 applied 值的字段 CAS 回不可变 original 值。
NTSTATUS
KswordARKDriverImageRestoreFieldsLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ ULONG FieldMask,
    _Out_ ULONG* ChangedFieldMask,
    _Out_ ULONG* FailedFieldMask
    );

// 中文说明：刷新只观察并更新所有权/冲突位，不覆盖任何第三方当前值。
NTSTATUS
KswordARKDriverImageRefreshFieldsLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ BOOLEAN* StateChanged
    );

// 中文说明：协议名字必须在固定数组内终止，避免 RtlInitUnicodeString 越界。
BOOLEAN
KswordARKDriverImageHasTerminatedName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* DriverName
    );

// 中文说明：驱动对象名字按对象管理器惯例执行不区分大小写比较。
BOOLEAN
KswordARKDriverImageNamesEqual(
    _In_z_ const WCHAR* Left,
    _In_z_ const WCHAR* Right
    );

// 中文说明：目标可按对象名或初始模块基址解析，变更动作还核验精确对象地址。
NTSTATUS
KswordARKDriverImageResolveTarget(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* Request,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR CanonicalNameOut,
    _In_ ULONG NameChars,
    _Out_ ULONGLONG* TargetModuleBaseOut
    );

// 中文说明：运行时打开统一执行精确导出解析、临界区和共享/独占资源获取。
NTSTATUS
KswordARKDriverImageOpenRuntime(
    _Out_ KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ BOOLEAN Exclusive
    );

// 中文说明：记录首次需要 KLDR 时按冻结模块基址绑定 loader 项并保存 link 身份。
NTSTATUS
KswordARKDriverImageAttachLoaderLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ BOOLEAN* StateChanged
    );

// 中文说明：刷新字段和链所有权；Runtime 可缺失，此时 KLDR/link 保守进入冲突态。
NTSTATUS
KswordARKDriverImageRefreshRecordLocked(
    _In_opt_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ BOOLEAN* StateChanged
    );

// 中文说明：统一响应序列化器只观察受锁记录和受资源保护的链，不执行写入。
VOID
KswordARKDriverImageFillResponseLocked(
    _In_ const KSW_DRIVER_IMAGE_STATE* State,
    _In_ const KSW_DRIVER_IMAGE_RESPONSE_CONTEXT* Context,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* Response
    );
