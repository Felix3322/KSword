/*++

Module Name:

    thread_apc.c

Abstract:

    管理用于终止系统线程的 Kernel APC 生命周期，并在驱动卸载前取消和排空。

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../platform/pool_compat.h"

#define KSWORD_ARK_THREAD_APC_POOL_TAG 'pAsK'
#define KSWORD_ARK_APC_ENVIRONMENT_ORIGINAL 0L

typedef VOID(NTAPI* KSWORD_APC_NORMAL_ROUTINE)(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

typedef VOID(NTAPI* KSWORD_APC_KERNEL_ROUTINE)(
    _In_ PKAPC Apc,
    _Inout_ KSWORD_APC_NORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
    );

typedef VOID(NTAPI* KSWORD_APC_RUNDOWN_ROUTINE)(
    _In_ PKAPC Apc
    );

typedef VOID(NTAPI* KSWORD_KE_INITIALIZE_APC_FN)(
    _Out_ PKAPC Apc,
    _In_ PKTHREAD Thread,
    _In_ LONG Environment,
    _In_ KSWORD_APC_KERNEL_ROUTINE KernelRoutine,
    _In_opt_ KSWORD_APC_RUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ KSWORD_APC_NORMAL_ROUTINE NormalRoutine,
    _In_ KPROCESSOR_MODE ApcMode,
    _In_opt_ PVOID NormalContext
    );

typedef BOOLEAN(NTAPI* KSWORD_KE_INSERT_QUEUE_APC_FN)(
    _Inout_ PKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment
    );

typedef BOOLEAN(NTAPI* KSWORD_KE_REMOVE_QUEUE_APC_FN)(
    _Inout_ PKAPC Apc
    );

typedef struct _KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT
{
    LIST_ENTRY RegistryLink;
    KAPC SpecialApc;
    KAPC NormalApc;
    WORK_QUEUE_ITEM ReaperWorkItem;
    KEVENT NormalRoutineCompletedEvent;
    PETHREAD ThreadObject;
    KSWORD_KE_INITIALIZE_APC_FN KeInitializeApc;
    KSWORD_KE_INSERT_QUEUE_APC_FN KeInsertQueueApc;
    KSWORD_KE_REMOVE_QUEUE_APC_FN KeRemoveQueueApc;
    PVOID volatile ActiveApc;
    volatile LONG ReferenceCount;
    volatile LONG Registered;
    volatile LONG Released;
    volatile LONG CancelVisited;
} KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT;

// 注册表自旋锁保护 APC 上下文链表、计数以及停止接收标志。
static KSPIN_LOCK g_KswordARKThreadApcRegistryLock;
// 注册表链表保存所有可能回调到本驱动映像的 APC 上下文。
static LIST_ENTRY g_KswordARKThreadApcRegistry;
// 排空事件在注册表为空时保持有信号，卸载路径据此等待全部回调退出。
static KEVENT g_KswordARKThreadApcDrainEvent;
// 未完成上下文计数只在注册表自旋锁保护下读写。
static ULONG g_KswordARKThreadApcOutstandingCount = 0UL;
// 停止标志阻止卸载开始后继续排入新的 APC。
static volatile LONG g_KswordARKThreadApcStopping = 1L;

static KSWORD_KE_INITIALIZE_APC_FN
KswordARKResolveKeInitializeApc(
    VOID
    )
/*++

Routine Description:

    解析 KeInitializeApc，避免直接依赖不同 WDK 版本的导入声明。

Arguments:

    无。

Return Value:

    成功返回函数地址，不可用时返回 NULL。

--*/
{
    UNICODE_STRING routineName;

    // 使用公开系统例程名称初始化查询字符串。
    RtlInitUnicodeString(&routineName, L"KeInitializeApc");
    // 返回内核导出的例程地址，调用方负责检查 NULL。
    return (KSWORD_KE_INITIALIZE_APC_FN)MmGetSystemRoutineAddress(&routineName);
}

static KSWORD_KE_INSERT_QUEUE_APC_FN
KswordARKResolveKeInsertQueueApc(
    VOID
    )
/*++

Routine Description:

    解析 KeInsertQueueApc，供受注册表保护的排队函数调用。

Arguments:

    无。

Return Value:

    成功返回函数地址，不可用时返回 NULL。

--*/
{
    UNICODE_STRING routineName;

    // 使用公开系统例程名称初始化查询字符串。
    RtlInitUnicodeString(&routineName, L"KeInsertQueueApc");
    // 返回内核导出的例程地址，调用方负责检查 NULL。
    return (KSWORD_KE_INSERT_QUEUE_APC_FN)MmGetSystemRoutineAddress(&routineName);
}

static KSWORD_KE_REMOVE_QUEUE_APC_FN
KswordARKResolveKeRemoveQueueApc(
    VOID
    )
/*++

Routine Description:

    解析 KeRemoveQueueApc，卸载路径用它取消尚未投递的 APC。

Arguments:

    无。

Return Value:

    成功返回函数地址，不可用时返回 NULL。

--*/
{
    UNICODE_STRING routineName;

    // 使用公开导出名称初始化系统例程查询字符串。
    RtlInitUnicodeString(&routineName, L"KeRemoveQueueApc");
    // 返回内核导出的取消例程地址，创建上下文前必须确认其可用。
    return (KSWORD_KE_REMOVE_QUEUE_APC_FN)MmGetSystemRoutineAddress(&routineName);
}

static VOID
KswordARKReferenceThreadTerminateApcContext(
    _In_ KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* Context
    )
/*++

Routine Description:

    为卸载取消路径临时增加 APC 上下文引用。

Arguments:

    Context - 要保活的 APC 上下文。

Return Value:

    无返回值。

--*/
{
    // 调用方仅在注册表锁保护下引用仍在链表中的上下文。
    (VOID)InterlockedIncrement(&Context->ReferenceCount);
}

static VOID
KswordARKDereferenceThreadTerminateApcContext(
    _In_ KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* Context
    )
/*++

Routine Description:

    释放 APC 上下文引用，并在最后一个引用离开时释放非分页内存。

Arguments:

    Context - 要释放引用的 APC 上下文。

Return Value:

    无返回值。

--*/
{
    // 只有最后一个引用负责释放上下文，避免取消与回调并发造成重复释放。
    if (InterlockedDecrement(&Context->ReferenceCount) == 0L) {
        // 上下文来自带固定标签的非分页池，必须使用相同标签释放。
        ExFreePoolWithTag(Context, KSWORD_ARK_THREAD_APC_POOL_TAG);
    }
}

static BOOLEAN
KswordARKRegisterThreadTerminateApcContext(
    _Inout_ KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* Context
    )
/*++

Routine Description:

    在停止标志仍关闭时把 APC 上下文加入全局注册表。

Arguments:

    Context - 已完成基础初始化但尚未排队的 APC 上下文。

Return Value:

    注册成功返回 TRUE；驱动正在卸载时返回 FALSE。

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    BOOLEAN registered = FALSE;

    // 获取全局自旋锁，使停止标志检查与链表插入形成一个原子事务。
    KeAcquireSpinLock(&g_KswordARKThreadApcRegistryLock, &oldIrql);
    // 卸载尚未开始且上下文未释放时才允许注册。
    if (g_KswordARKThreadApcStopping == 0L &&
        Context->Released == 0L) {
        // 第一个上下文进入时清除排空事件，阻止卸载提前完成。
        if (g_KswordARKThreadApcOutstandingCount == 0UL) {
            KeClearEvent(&g_KswordARKThreadApcDrainEvent);
        }
        // 链表持有上下文的初始引用，直到统一释放函数移除节点。
        InsertTailList(&g_KswordARKThreadApcRegistry, &Context->RegistryLink);
        // 标记节点已经进入注册表，释放函数据此执行对称移除。
        Context->Registered = 1L;
        // 记录当前可能回调到驱动映像的上下文总数。
        ++g_KswordARKThreadApcOutstandingCount;
        // 返回值向调用方确认后续可以初始化并排入 APC。
        registered = TRUE;
    }
    // 释放注册表锁并恢复调用方原 IRQL。
    KeReleaseSpinLock(&g_KswordARKThreadApcRegistryLock, oldIrql);
    // 返回原子注册操作的最终结果。
    return registered;
}

static VOID
KswordARKClearActiveThreadTerminateApc(
    _Inout_ KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* Context,
    _In_ PKAPC Apc
    )
/*++

Routine Description:

    仅当给定 APC 仍是当前排队实例时清除活动指针。

Arguments:

    Context - APC 所属上下文。
    Apc - 正在执行、被 rundown 或被取消的 APC。

Return Value:

    无返回值。

--*/
{
    // 比较交换避免旧阶段回调误清除 Special-to-Normal 转换后的新 APC。
    (VOID)InterlockedCompareExchangePointer(
        &Context->ActiveApc,
        NULL,
        Apc);
}

static VOID
KswordARKReleaseThreadTerminateApcContext(
    _In_opt_ KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* Context
    )
/*++

Routine Description:

    从全局注册表移除 APC 上下文、释放线程引用并递减基础引用。

Arguments:

    Context - 已注册 APC 上下文，可为 NULL。

Return Value:

    无返回值。

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    PETHREAD threadObject = NULL;

    // NULL 或已由其他并发路径释放的上下文不再重复处理。
    if (Context == NULL ||
        InterlockedCompareExchange(&Context->Released, 1L, 0L) != 0L) {
        return;
    }

    // 获取注册表锁，使链表移除、计数更新和排空事件设置保持一致。
    KeAcquireSpinLock(&g_KswordARKThreadApcRegistryLock, &oldIrql);
    // 只有成功注册过的上下文才拥有链表节点和基础注册引用。
    if (Context->Registered != 0L) {
        // 从全局链表摘除节点，后续卸载遍历不会再次选择该上下文。
        RemoveEntryList(&Context->RegistryLink);
        // 将节点恢复成自环，方便调试器识别其已离开注册表。
        InitializeListHead(&Context->RegistryLink);
        // 清除注册标志，防止任何异常重复释放再次操作链表。
        Context->Registered = 0L;
        // 防御性检查计数，避免损坏状态下发生无符号下溢。
        if (g_KswordARKThreadApcOutstandingCount != 0UL) {
            // 对称扣减注册时增加的未完成上下文计数。
            --g_KswordARKThreadApcOutstandingCount;
        }
        // 最后一个上下文离开时唤醒等待排空的卸载线程。
        if (g_KswordARKThreadApcOutstandingCount == 0UL) {
            (VOID)KeSetEvent(
                &g_KswordARKThreadApcDrainEvent,
                IO_NO_INCREMENT,
                FALSE);
        }
    }
    // 取出线程对象并清空字段，确保后续不再重复解引用。
    threadObject = Context->ThreadObject;
    Context->ThreadObject = NULL;
    // 释放注册表锁并恢复调用方原 IRQL。
    KeReleaseSpinLock(&g_KswordARKThreadApcRegistryLock, oldIrql);

    // 在线程对象脱离共享结构后释放其引用。
    if (threadObject != NULL) {
        // PsLookup/ObReference 获得的 ETHREAD 引用必须在最终释放路径对称归还。
        ObDereferenceObject(threadObject);
    }
    // 释放注册表持有的基础引用；临时取消引用可能继续保活内存。
    KswordARKDereferenceThreadTerminateApcContext(Context);
}

static BOOLEAN
KswordARKQueueTrackedThreadTerminateApc(
    _Inout_ KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* Context,
    _Inout_ PKAPC Apc
    )
/*++

Routine Description:

    在注册表锁保护下检查卸载状态、发布活动 APC 指针并执行排队。

Arguments:

    Context - 已注册且持有目标线程引用的上下文。
    Apc - 已由 KeInitializeApc 初始化的 Special 或 Normal APC。

Return Value:

    成功排队返回 TRUE；卸载开始、上下文释放或内核拒绝排队时返回 FALSE。

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    BOOLEAN inserted = FALSE;

    // 注册表锁让停止标志与“活动指针已对应一个已排队 APC”保持原子。
    KeAcquireSpinLock(&g_KswordARKThreadApcRegistryLock, &oldIrql);
    // 仅在上下文仍注册且驱动未停止接收时调用内核排队例程。
    if (g_KswordARKThreadApcStopping == 0L &&
        Context->Registered != 0L &&
        Context->Released == 0L) {
        // 先发布活动 APC，回调即使立即执行也能安全清除同一指针。
        (VOID)InterlockedExchangePointer(&Context->ActiveApc, Apc);
        // 在停止状态不能插入的同一个锁窗口内完成实际排队。
        inserted = Context->KeInsertQueueApc(Apc, NULL, NULL, 0);
        // 排队失败时撤销活动指针，调用方随后释放整个上下文。
        if (!inserted) {
            KswordARKClearActiveThreadTerminateApc(Context, Apc);
        }
    }
    // 释放注册表锁后，卸载路径即可取消刚刚确认排队的 APC。
    KeReleaseSpinLock(&g_KswordARKThreadApcRegistryLock, oldIrql);
    // 返回内核排队操作的最终结果。
    return inserted;
}

static VOID
NTAPI
KswordARKTerminateSystemThreadReaperWorker(
    _In_ PVOID Parameter
    )
/*++

Routine Description:

    等待目标线程终止或 NormalRoutine 返回，再释放 APC 上下文。

Arguments:

    Parameter - KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT 指针。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* context =
        (KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT*)Parameter;
    PVOID waitObjects[2];

    // 第一个等待对象是 ETHREAD，线程完全退出时由内核置为有信号。
    waitObjects[0] = context->ThreadObject;
    // 第二个等待对象覆盖 PsTerminateSystemThread 意外返回的失败路径。
    waitObjects[1] = &context->NormalRoutineCompletedEvent;
    // 任一对象有信号都表示目标线程不再执行本驱动的 NormalRoutine 主体。
    (VOID)KeWaitForMultipleObjects(
        RTL_NUMBER_OF(waitObjects),
        waitObjects,
        WaitAny,
        Executive,
        KernelMode,
        FALSE,
        NULL,
        NULL);
    // 释放动作必须位于 worker 尾部，使卸载等待覆盖整个执行窗口。
    KswordARKReleaseThreadTerminateApcContext(context);
}

static VOID
NTAPI
KswordARKTerminateSystemThreadNormalRoutine(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++

Routine Description:

    在目标系统线程 PASSIVE_LEVEL 上排入回收 worker，然后终止当前线程。

Arguments:

    NormalContext - KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT 指针。
    SystemArgument1 - 未使用的 APC 系统参数。
    SystemArgument2 - 未使用的 APC 系统参数。

Return Value:

    正常成功时 PsTerminateSystemThread 不返回；失败返回时唤醒回收 worker。

--*/
{
    KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* context =
        (KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT*)NormalContext;

    // 两个系统参数由排队方固定传入 NULL，本实现不读取它们。
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // 在终止当前线程前准备等待型 worker，确保线程退出后有人释放上下文。
    ExInitializeWorkItem(
        &context->ReaperWorkItem,
        KswordARKTerminateSystemThreadReaperWorker,
        context);
    // 系统 worker 将等待 ETHREAD 有信号，不会抢先释放仍在执行的上下文。
    ExQueueWorkItem(&context->ReaperWorkItem, DelayedWorkQueue);
    // 公开 API 只终止当前系统线程，成功路径不会返回到本驱动代码。
    (VOID)PsTerminateSystemThread(STATUS_CANCELLED);
    // 若 API 异常返回，通知 worker 当前 NormalRoutine 已完成且可以释放上下文。
    (VOID)KeSetEvent(
        &context->NormalRoutineCompletedEvent,
        IO_NO_INCREMENT,
        FALSE);
}

static VOID
NTAPI
KswordARKTerminateSystemThreadNormalKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ KSWORD_APC_NORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
    )
/*++

Routine Description:

    标记 Normal APC 已离开队列；卸载期间抑制 NormalRoutine 并释放上下文。

Arguments:

    Apc - 正在投递的 Normal APC。
    NormalRoutine - 可取消后续 NormalRoutine 的函数指针槽。
    NormalContext - NormalRoutine 上下文槽。
    SystemArgument1 - 未使用的系统参数槽。
    SystemArgument2 - 未使用的系统参数槽。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* context =
        CONTAINING_RECORD(Apc, KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT, NormalApc);

    // 两个系统参数始终为 NULL，本例程不修改它们。
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    // APC 已被内核取出队列，取消路径不应再调用 KeRemoveQueueApc。
    KswordARKClearActiveThreadTerminateApc(context, Apc);
    // 卸载开始后不再进入新的驱动 NormalRoutine。
    if (InterlockedCompareExchange(&g_KswordARKThreadApcStopping, 0L, 0L) != 0L) {
        // 清空函数指针阻止 APC dispatcher 调用本驱动的 NormalRoutine。
        *NormalRoutine = NULL;
        // 清空上下文槽，避免下游保留已经释放的上下文地址。
        *NormalContext = NULL;
        // 释放动作位于 kernel routine 尾部，卸载等待覆盖此前全部逻辑。
        KswordARKReleaseThreadTerminateApcContext(context);
    }
}

static VOID
NTAPI
KswordARKTerminateSystemThreadNormalRundownRoutine(
    _In_ PKAPC Apc
    )
/*++

Routine Description:

    在线程退出导致 Normal APC 未投递时清除活动指针并释放上下文。

Arguments:

    Apc - 被内核 rundown 的 Normal APC。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* context =
        CONTAINING_RECORD(Apc, KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT, NormalApc);

    // APC 已不在目标线程队列，先撤销可取消指针。
    KswordARKClearActiveThreadTerminateApc(context, Apc);
    // rundown 尾部释放注册上下文并唤醒可能等待的卸载线程。
    KswordARKReleaseThreadTerminateApcContext(context);
}

static VOID
NTAPI
KswordARKTerminateSystemThreadSpecialRundownRoutine(
    _In_ PKAPC Apc
    )
/*++

Routine Description:

    在线程退出导致 Special APC 未投递时释放注册上下文。

Arguments:

    Apc - 被内核 rundown 的 Special APC。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* context =
        CONTAINING_RECORD(Apc, KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT, SpecialApc);

    // APC 已离开目标线程队列，先清除当前活动指针。
    KswordARKClearActiveThreadTerminateApc(context, Apc);
    // rundown 尾部释放注册上下文并唤醒可能等待的卸载线程。
    KswordARKReleaseThreadTerminateApcContext(context);
}

static VOID
NTAPI
KswordARKTerminateSystemThreadSpecialKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ KSWORD_APC_NORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
    )
/*++

Routine Description:

    将已投递的 Special APC 转换为受同一注册表追踪的 Normal APC。

Arguments:

    Apc - 正在投递的 Special APC。
    NormalRoutine - Special APC 未配置 NormalRoutine，参数仅用于签名兼容。
    NormalContext - Special APC 未配置 NormalContext，参数仅用于签名兼容。
    SystemArgument1 - 未使用的系统参数槽。
    SystemArgument2 - 未使用的系统参数槽。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* context =
        CONTAINING_RECORD(Apc, KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT, SpecialApc);

    // Special APC 没有 NormalRoutine，这两个槽位不参与转换逻辑。
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    // 两个系统参数由排队方固定传入 NULL，本例程不读取它们。
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    // Special APC 已被内核取出队列，撤销其活动指针。
    KswordARKClearActiveThreadTerminateApc(context, Apc);
    // 卸载开始时禁止进入第二阶段并在 kernel routine 尾部释放上下文。
    if (InterlockedCompareExchange(&g_KswordARKThreadApcStopping, 0L, 0L) != 0L) {
        // 统一释放函数会从注册表移除上下文并唤醒卸载线程。
        KswordARKReleaseThreadTerminateApcContext(context);
        return;
    }

    // 初始化第二阶段 Normal APC，使 PsTerminateSystemThread 在 PASSIVE_LEVEL 执行。
    context->KeInitializeApc(
        &context->NormalApc,
        (PKTHREAD)context->ThreadObject,
        KSWORD_ARK_APC_ENVIRONMENT_ORIGINAL,
        KswordARKTerminateSystemThreadNormalKernelRoutine,
        KswordARKTerminateSystemThreadNormalRundownRoutine,
        KswordARKTerminateSystemThreadNormalRoutine,
        KernelMode,
        context);
    // 通过统一排队函数原子检查停止标志并发布新的活动 APC。
    if (!KswordARKQueueTrackedThreadTerminateApc(context, &context->NormalApc)) {
        // 排队失败或卸载已开始时立即释放上下文。
        KswordARKReleaseThreadTerminateApcContext(context);
    }
}

VOID
KswordARKThreadApcInitialize(
    VOID
    )
/*++

Routine Description:

    初始化 APC 注册表、排空事件和接收状态；由 DriverEntry 调用一次。

Arguments:

    无。

Return Value:

    无返回值。

--*/
{
    // 初始化保护全局 APC 注册表的自旋锁。
    KeInitializeSpinLock(&g_KswordARKThreadApcRegistryLock);
    // 初始化空链表，所有后续上下文都通过统一注册函数进入。
    InitializeListHead(&g_KswordARKThreadApcRegistry);
    // 空注册表对应有信号状态，使无待处理 APC 的卸载无需等待。
    KeInitializeEvent(
        &g_KswordARKThreadApcDrainEvent,
        NotificationEvent,
        TRUE);
    // 初始化计数为零，与空链表和有信号事件保持一致。
    g_KswordARKThreadApcOutstandingCount = 0UL;
    // 所有共享对象完成初始化后才开放 APC 排队。
    (VOID)InterlockedExchange(&g_KswordARKThreadApcStopping, 0L);
}

VOID
KswordARKThreadApcUninitialize(
    VOID
    )
/*++

Routine Description:

    停止接收新 APC、取消所有仍在队列中的 APC，并等待执行中回调排空。

Arguments:

    无。

Return Value:

    无返回值；返回时不再存在可调用本驱动代码的线程终止 APC。

--*/
{
    KIRQL oldIrql = PASSIVE_LEVEL;

    // 卸载回调位于 PASSIVE_LEVEL，等待排空前显式验证调用环境。
    PAGED_CODE();
    // 在注册表锁内发布停止状态，阻止注册和阶段转换继续排队。
    KeAcquireSpinLock(&g_KswordARKThreadApcRegistryLock, &oldIrql);
    // 停止标志一旦置位，在本次驱动实例生命周期内不再清除。
    (VOID)InterlockedExchange(&g_KswordARKThreadApcStopping, 1L);
    // 释放注册表锁，让回调尾部能够继续完成并移除自身。
    KeReleaseSpinLock(&g_KswordARKThreadApcRegistryLock, oldIrql);

    // 每轮选择一个尚未访问的上下文，避免锁外取消期间持有失效指针。
    for (;;) {
        KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* context = NULL;
        PVOID activeApc = NULL;
        PLIST_ENTRY entry = NULL;

        // 在链表锁下选择上下文并增加临时引用。
        KeAcquireSpinLock(&g_KswordARKThreadApcRegistryLock, &oldIrql);
        // 从头遍历仍注册的上下文，寻找本轮尚未请求取消的节点。
        for (entry = g_KswordARKThreadApcRegistry.Flink;
             entry != &g_KswordARKThreadApcRegistry;
             entry = entry->Flink) {
            KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* candidate =
                CONTAINING_RECORD(
                    entry,
                    KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT,
                    RegistryLink);

            // 已释放或已访问的节点由其现有回调/取消路径完成，不重复处理。
            if (candidate->Released != 0L ||
                candidate->CancelVisited != 0L) {
                continue;
            }
            // 标记本轮已经处理该上下文，后续循环将推进到其他节点。
            candidate->CancelVisited = 1L;
            // 临时引用保证锁外调用 KeRemoveQueueApc 时上下文内存仍有效。
            KswordARKReferenceThreadTerminateApcContext(candidate);
            // 原子读取当前实际排队阶段；NULL 表示回调正在执行或尚未排队。
            activeApc = InterlockedCompareExchangePointer(
                &candidate->ActiveApc,
                NULL,
                NULL);
            // 保存候选指针后退出锁内遍历。
            context = candidate;
            break;
        }
        // 释放注册表锁后再进入目标线程的 APC 队列锁，避免锁顺序反转。
        KeReleaseSpinLock(&g_KswordARKThreadApcRegistryLock, oldIrql);

        // 没有未访问节点说明取消请求已覆盖当前注册表。
        if (context == NULL) {
            break;
        }
        // 活动 APC 仍在队列时尝试原子移除；成功后内核不会调用 rundown。
        if (activeApc != NULL &&
            context->KeRemoveQueueApc((PKAPC)activeApc)) {
            // 撤销活动指针，避免诊断状态仍显示已经移除的 APC。
            KswordARKClearActiveThreadTerminateApc(
                context,
                (PKAPC)activeApc);
            // 取消成功路径必须自行释放上下文，因为内核不会再回调。
            KswordARKReleaseThreadTerminateApcContext(context);
        }
        // 归还锁内取得的临时引用；基础注册引用由回调或取消路径持有。
        KswordARKDereferenceThreadTerminateApcContext(context);
    }

    // 等待执行中 kernel/normal/rundown/worker 路径全部从注册表离开。
    (VOID)KeWaitForSingleObject(
        &g_KswordARKThreadApcDrainEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL);
}

NTSTATUS
KswordARKDriverQueueTerminateSystemThreadApc(
    _In_ PETHREAD ThreadObject,
    _In_ BOOLEAN SpecialToNormal
    )
/*++

Routine Description:

    创建受全局生命周期注册表追踪的线程终止 APC，并排入目标系统线程。

Arguments:

    ThreadObject - 已由调用方引用的目标 ETHREAD；本函数会增加独立引用。
    SpecialToNormal - TRUE 时先排 Special APC，再转换为 Normal APC。

Return Value:

    返回参数、系统例程解析、内存、卸载状态或实际排队结果。

--*/
{
    KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT* context = NULL;
    KSWORD_KE_INITIALIZE_APC_FN keInitializeApc = NULL;
    KSWORD_KE_INSERT_QUEUE_APC_FN keInsertQueueApc = NULL;
    KSWORD_KE_REMOVE_QUEUE_APC_FN keRemoveQueueApc = NULL;
    PKAPC firstApc = NULL;

    // 线程对象不能为空，调用方仍负责此前的目标身份和安全策略检查。
    if (ThreadObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 解析当前内核导出的 APC 初始化例程。
    keInitializeApc = KswordARKResolveKeInitializeApc();
    // 解析当前内核导出的 APC 排队例程。
    keInsertQueueApc = KswordARKResolveKeInsertQueueApc();
    // 解析卸载时取消未投递 APC 所需的内核例程。
    keRemoveQueueApc = KswordARKResolveKeRemoveQueueApc();
    // 任一例程不可用时不创建无法管理的半成品上下文。
    if (keInitializeApc == NULL ||
        keInsertQueueApc == NULL ||
        keRemoveQueueApc == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // APC、注册节点、事件和 worker 都必须位于非分页池。
    context = (KSWORD_ARK_THREAD_TERMINATE_APC_CONTEXT*)KswordARKAllocateNonPagedPool(
        sizeof(*context),
        KSWORD_ARK_THREAD_APC_POOL_TAG);
    // 分配失败时向调用方返回标准资源不足状态。
    if (context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // 清零整个上下文，确保所有并发标志从确定状态开始。
    RtlZeroMemory(context, sizeof(*context));
    // 初始化独立链表节点，注册前保持自环状态。
    InitializeListHead(&context->RegistryLink);
    // NormalRoutine 返回事件初始无信号，仅覆盖 PsTerminate 意外返回路径。
    KeInitializeEvent(
        &context->NormalRoutineCompletedEvent,
        NotificationEvent,
        FALSE);
    // 初始引用由全局注册表所有，释放函数最终归还。
    context->ReferenceCount = 1L;
    // 增加目标线程对象引用，使 APC、worker 与卸载期间地址始终有效。
    ObReferenceObject(ThreadObject);
    // 保存目标线程对象供 APC 初始化和回收 worker 等待。
    context->ThreadObject = ThreadObject;
    // 保存解析后的初始化例程，Special-to-Normal 阶段转换继续使用。
    context->KeInitializeApc = keInitializeApc;
    // 保存解析后的排队例程，所有阶段都经统一原子排队函数调用。
    context->KeInsertQueueApc = keInsertQueueApc;
    // 保存解析后的取消例程，卸载遍历无需再次查询系统导出。
    context->KeRemoveQueueApc = keRemoveQueueApc;

    // 在初始化可回调对象前加入全局注册表，确保卸载可以发现上下文。
    if (!KswordARKRegisterThreadTerminateApcContext(context)) {
        // 卸载已开始时归还独立线程对象引用。
        ObDereferenceObject(context->ThreadObject);
        // 清空字段，防止调试器误认为未注册上下文仍持有对象。
        context->ThreadObject = NULL;
        // 归还尚未交给注册表的初始引用并释放内存。
        KswordARKDereferenceThreadTerminateApcContext(context);
        return STATUS_DELETE_PENDING;
    }

    // 根据用户选择初始化第一阶段 Special 或 Normal APC。
    if (SpecialToNormal) {
        // Special 模式的第一阶段仅在 APC_LEVEL 初始化第二阶段。
        firstApc = &context->SpecialApc;
        // 初始化 Special APC，并提供线程退出时的 rundown 释放路径。
        keInitializeApc(
            firstApc,
            (PKTHREAD)ThreadObject,
            KSWORD_ARK_APC_ENVIRONMENT_ORIGINAL,
            KswordARKTerminateSystemThreadSpecialKernelRoutine,
            KswordARKTerminateSystemThreadSpecialRundownRoutine,
            NULL,
            KernelMode,
            NULL);
    }
    else {
        // Normal 模式直接在目标线程 PASSIVE_LEVEL 执行终止例程。
        firstApc = &context->NormalApc;
        // 初始化 Normal APC，并提供 kernel、rundown 与 normal 三条完整路径。
        keInitializeApc(
            firstApc,
            (PKTHREAD)ThreadObject,
            KSWORD_ARK_APC_ENVIRONMENT_ORIGINAL,
            KswordARKTerminateSystemThreadNormalKernelRoutine,
            KswordARKTerminateSystemThreadNormalRundownRoutine,
            KswordARKTerminateSystemThreadNormalRoutine,
            KernelMode,
            context);
    }

    // 原子排队失败时统一从注册表释放上下文。
    if (!KswordARKQueueTrackedThreadTerminateApc(context, firstApc)) {
        // 释放函数对称移除注册节点、线程引用和基础内存引用。
        KswordARKReleaseThreadTerminateApcContext(context);
        return STATUS_UNSUCCESSFUL;
    }

    // 排队成功表示 APC 已进入全局可取消、可排空的生命周期管理。
    return STATUS_SUCCESS;
}
