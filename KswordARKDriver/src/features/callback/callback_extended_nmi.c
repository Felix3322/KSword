/*++

Module Name:

    callback_extended_nmi.c

Abstract:

    Enumerates KeRegisterNmiCallback registrations from the bounded private list.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"
#include "callback_extended_kernel.h"

#define KSWORD_ARK_CALLBACK_NMI_CODE_SCAN_BYTES 0x200UL
#define KSWORD_ARK_CALLBACK_NMI_WALK_LIMIT 512UL
#define KSWORD_ARK_CALLBACK_NMI_SNAPSHOT_TAG 'mNbK'

#if defined(_M_AMD64)

// Windows AMD64 当前 NMI 私有节点布局；每次读取后仍需验证自句柄与 next 指针。
typedef struct _KSWORD_ARK_CALLBACK_NMI_REGISTRATION
{
    ULONG64 Next;
    ULONG64 CallbackRoutine;
    ULONG64 CallbackContext;
    ULONG64 Handle;
} KSWORD_ARK_CALLBACK_NMI_REGISTRATION;

// 锁内只保存 NMI 节点标量，模块解析、字符串和响应构建全部延迟到锁外。
typedef struct _KSWORD_ARK_CALLBACK_NMI_SNAPSHOT
{
    ULONG TraversalIndex;
    ULONG64 NodeAddress;
    ULONG64 CallbackRoutine;
    ULONG64 CallbackContext;
    ULONG64 Handle;
    ULONG64 Next;
} KSWORD_ARK_CALLBACK_NMI_SNAPSHOT;

static NTSTATUS
KswordArkCallbackExtendedLocateNmiList(
    _Out_ ULONG64* HeadStorageAddressOut,
    _Out_ ULONG64* LockAddressOut
    )
/*++

Routine Description:

    在 KeRegisterNmiCallback 的有限代码窗口内定位 NMI 私有链表头存储和配套
    自旋锁。定位同时要求出现对同一链头的读取与回写，并验证两个全局地址的
    内核可访问性与对齐；节点布局只在持有锁后验证。

Arguments:

    HeadStorageAddressOut - 接收保存首节点指针的内核全局地址。
    LockAddressOut - 接收保护链表的相邻 KSPIN_LOCK 地址。

Return Value:

    成功返回 STATUS_SUCCESS；无法安全定位时返回对应失败状态。

--*/
{
    // 只复制导出例程的固定前缀，禁止无边界扫描可执行内存。
    UCHAR codeBytes[KSWORD_ARK_CALLBACK_NMI_CODE_SCAN_BYTES];
    // offset 指向候选的 MOV/LEA 指令对。
    ULONG offset = 0UL;
    // 导出例程地址只通过 MmGetSystemRoutineAddress 的封装获得。
    ULONG64 routineAddress = 0ULL;

    // 两个结果均为必需，避免返回部分定位信息。
    if (HeadStorageAddressOut == NULL ||
        LockAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 失败路径统一保持输出为零，调用方不会误用旧值。
    *HeadStorageAddressOut = 0ULL;
    *LockAddressOut = 0ULL;
    // 使用公开导出作为版本自适应扫描锚点。
    routineAddress = (ULONG64)(ULONG_PTR)
        KswordArkCallbackExtendedGetSystemRoutine(L"KeRegisterNmiCallback");
    // 不存在导出时当前系统不支持该枚举路径。
    if (routineAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // 预清零本地副本，确保短读不会留下未初始化字节。
    RtlZeroMemory(codeBytes, sizeof(codeBytes));
    // 安全读取封装负责捕获无效内核地址访问。
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)routineAddress,
            codeBytes,
            sizeof(codeBytes))) {
        return STATUS_ACCESS_VIOLATION;
    }

    // 搜索相邻的 RIP 相对 MOV 链头读取和 LEA 锁地址组合。
    for (offset = 0UL; offset + 14UL <= sizeof(codeBytes); ++offset) {
        // storeOffset 用于寻找稍后对同一链头全局量的回写。
        ULONG storeOffset = 0UL;
        // 每个候选都独立解析，失败时不泄漏上一候选结果。
        ULONG64 headStorageAddress = 0ULL;
        ULONG64 lockAddress = 0ULL;
        ULONG64 addressDistance = 0ULL;
        BOOLEAN foundHeadStore = FALSE;

        // 仅接受 `mov reg,[rip+disp32]` 紧跟 `lea reg,[rip+disp32]` 的形态。
        if (codeBytes[offset] != 0x48U ||
            codeBytes[offset + 1UL] != 0x8BU ||
            (codeBytes[offset + 2UL] & 0xC7U) != 0x05U ||
            codeBytes[offset + 7UL] != 0x48U ||
            codeBytes[offset + 8UL] != 0x8DU ||
            (codeBytes[offset + 9UL] & 0xC7U) != 0x05U) {
            continue;
        }
        // 分别解析链头存储和锁的绝对内核地址。
        if (!KswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset,
                3UL,
                7UL,
                &headStorageAddress) ||
            !KswordArkCallbackExtendedResolveRipRelative(
                routineAddress + offset + 7UL,
                3UL,
                7UL,
                &lockAddress)) {
            continue;
        }

        // 当前实现中锁与链头相邻；较大距离说明命中了无关全局量。
        addressDistance = (headStorageAddress > lockAddress)
            ? (headStorageAddress - lockAddress)
            : (lockAddress - headStorageAddress);
        if (headStorageAddress == lockAddress || addressDistance > 0x40ULL) {
            continue;
        }
        // 链头指针槽和 KSPIN_LOCK 必须按指针宽度对齐且当前可由内核访问。
        if ((headStorageAddress & ((ULONG64)sizeof(PVOID) - 1ULL)) != 0ULL ||
            (lockAddress & ((ULONG64)sizeof(PVOID) - 1ULL)) != 0ULL ||
            !MmIsAddressValid((PVOID)(ULONG_PTR)headStorageAddress) ||
            !MmIsAddressValid((PVOID)(ULONG_PTR)lockAddress)) {
            continue;
        }
        // 在有限后续窗口内要求存在对同一链头地址的 RIP 相对写回。
        for (storeOffset = offset + 14UL;
             storeOffset + 7UL <= sizeof(codeBytes) &&
                 storeOffset < offset + 48UL;
             ++storeOffset) {
            // 保存本条写指令解析出的全局目标。
            ULONG64 storeTarget = 0ULL;

            // 仅匹配 `mov [rip+disp32],reg`，忽略立即数或不同宽度写入。
            if (codeBytes[storeOffset] != 0x48U ||
                codeBytes[storeOffset + 1UL] != 0x89U ||
                (codeBytes[storeOffset + 2UL] & 0xC7U) != 0x05U) {
                continue;
            }
            // 写回目标必须与前面的读取目标完全一致。
            if (KswordArkCallbackExtendedResolveRipRelative(
                    routineAddress + storeOffset,
                    3UL,
                    7UL,
                    &storeTarget) &&
                storeTarget == headStorageAddress) {
                foundHeadStore = TRUE;
                break;
            }
        }
        // 缺少成对回写时拒绝该候选，降低版本漂移下的误识别风险。
        if (!foundHeadStore) {
            continue;
        }
        // 所有代码形态和地址检查都通过后一次性发布结果。
        *HeadStorageAddressOut = headStorageAddress;
        *LockAddressOut = lockAddress;
        return STATUS_SUCCESS;
    }

    // 有限窗口内没有满足完整证据链的候选。
    return STATUS_NOT_FOUND;
}

static VOID
KswordArkCallbackExtendedWalkNmiList(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 HeadStorageAddress,
    _In_ ULONG64 LockAddress
    )
/*++

Routine Description:

    获取 NMI 私有链表的 KSPIN_LOCK，在锁内读取链头并复制有界标量快照；
    释放锁后再验证模块归属、格式化文本并生成统一回调枚举行。

Arguments:

    Builder - 当前 IOCTL 的枚举构建器。
    ModuleCache - 本次 NMI 枚举使用的模块归属缓存。
    HeadStorageAddress - 保存首节点指针的全局地址。
    LockAddress - 保护私有链表的 KSPIN_LOCK 地址。

Return Value:

    无返回值。

--*/
{
    // index 同时用于安全上限和用户可见的稳定序号。
    ULONG index = 0UL;
    // snapshotCount 记录锁内成功复制的稳定节点数量。
    ULONG snapshotCount = 0UL;
    // snapshotIndex 用于锁外逐条生成响应。
    ULONG snapshotIndex = 0UL;
    // currentAddress 始终指向锁保护下的下一待验证节点。
    ULONG64 currentAddress = 0ULL;
    // failureAddress 记录损坏或超限发生处，供锁外诊断行使用。
    ULONG64 failureAddress = 0ULL;
    // snapshotStatus 汇总链头读取、节点验证和安全上限状态。
    NTSTATUS snapshotStatus = STATUS_SUCCESS;
    // oldIrql 保存获取 NMI 私有自旋锁前的调用方 IRQL。
    KIRQL oldIrql = PASSIVE_LEVEL;
    // snapshots 指向锁前分配的非分页标量数组。
    KSWORD_ARK_CALLBACK_NMI_SNAPSHOT* snapshots = NULL;

    // 参数地址必须来自严格定位器，并再次满足非零和指针对齐。
    if (Builder == NULL ||
        ModuleCache == NULL ||
        HeadStorageAddress == 0ULL ||
        LockAddress == 0ULL ||
        (LockAddress & ((ULONG64)sizeof(PVOID) - 1ULL)) != 0ULL) {
        return;
    }

    // 在获取私有自旋锁前分配非分页快照，锁内禁止内存分配和字符串处理。
    snapshots = (KSWORD_ARK_CALLBACK_NMI_SNAPSHOT*)KswordArkAllocateNonPaged(
        sizeof(*snapshots) * KSWORD_ARK_CALLBACK_NMI_WALK_LIMIT,
        KSWORD_ARK_CALLBACK_NMI_SNAPSHOT_TAG);
    // 内存不足时输出可见诊断，而不是无声漏掉全部 NMI 回调。
    if (snapshots == NULL) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_INSUFFICIENT_RESOURCES,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            LockAddress,
            HeadStorageAddress,
            0UL,
            L"KeRegisterNmiCallback snapshot allocation failed",
            L"无法分配 NMI 注册链非分页快照，未进入私有自旋锁。");
        return;
    }
    // 清零固定容量数组，确保异常读取后不会暴露未初始化字段。
    RtlZeroMemory(
        snapshots,
        sizeof(*snapshots) * KSWORD_ARK_CALLBACK_NMI_WALK_LIMIT);

    // 使用定位器解析出的真实 KSPIN_LOCK 阻止并发注销释放节点。
    KeAcquireSpinLock(
        (PKSPIN_LOCK)(ULONG_PTR)LockAddress,
        &oldIrql);
    // 链头必须在同一锁保护窗口内读取，不能沿用定位阶段的易失值。
    if (!KswordArkCallbackExtendedReadPointer(
            HeadStorageAddress,
            &currentAddress)) {
        snapshotStatus = STATUS_ACCESS_VIOLATION;
        failureAddress = HeadStorageAddress;
    }

    // 双重条件同时防止空终止链和损坏循环导致无限遍历。
    while (NT_SUCCESS(snapshotStatus) &&
        currentAddress != 0ULL &&
        index < KSWORD_ARK_CALLBACK_NMI_WALK_LIMIT) {
        // 每个私有节点先复制到栈上，再压缩成仅含标量的稳定快照。
        KSWORD_ARK_CALLBACK_NMI_REGISTRATION registration;

        // 节点读取前清零，异常路径不会使用栈残留。
        RtlZeroMemory(&registration, sizeof(registration));
        // 锁内验证读取、回调地址、自句柄、非自环和 next 指针对齐。
        if (!KswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &registration,
                sizeof(registration)) ||
            registration.CallbackRoutine == 0ULL ||
            registration.Handle != currentAddress ||
            registration.Next == currentAddress ||
            (registration.Next != 0ULL &&
             (registration.Next & ((ULONG64)sizeof(PVOID) - 1ULL)) != 0ULL)) {
            snapshotStatus = STATUS_DATA_ERROR;
            failureAddress = currentAddress;
            break;
        }

        // 保存原始遍历序号，锁外名称仍能对应链表顺序。
        snapshots[snapshotCount].TraversalIndex = index;
        // 保存节点地址用于诊断，不在锁外再次解引用该地址。
        snapshots[snapshotCount].NodeAddress = currentAddress;
        // 保存回调函数标量，锁外再验证所属内核模块。
        snapshots[snapshotCount].CallbackRoutine = registration.CallbackRoutine;
        // 保存回调上下文标量，锁外只作为响应元数据使用。
        snapshots[snapshotCount].CallbackContext = registration.CallbackContext;
        // 保存公开句柄标量，锁外详情不需要访问原节点。
        snapshots[snapshotCount].Handle = registration.Handle;
        // 保存下一节点标量，锁外详情可以显示一致性窗口内的链路。
        snapshots[snapshotCount].Next = registration.Next;
        // 增加已完成快照数量，容量与遍历上限严格一致。
        ++snapshotCount;
        // 仅使用已经验证过的本地 next 值推进遍历。
        currentAddress = registration.Next;
        ++index;
    }

    // 非空尾地址表示到达安全上限，而不是正常链尾。
    if (NT_SUCCESS(snapshotStatus) && currentAddress != 0ULL) {
        snapshotStatus = STATUS_BUFFER_OVERFLOW;
        failureAddress = currentAddress;
    }
    // 完成所有节点复制后立即释放私有自旋锁并恢复原 IRQL。
    KeReleaseSpinLock(
        (PKSPIN_LOCK)(ULONG_PTR)LockAddress,
        oldIrql);

    // 空链表不是错误，锁外返回一行明确的未注册状态。
    if (snapshotCount == 0UL && NT_SUCCESS(snapshotStatus)) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED,
            STATUS_NOT_FOUND,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            LockAddress,
            HeadStorageAddress,
            0UL,
            L"KeRegisterNmiCallback list (empty)",
            L"NMI 注册链已在自旋锁保护下确认为空。");
    }

    // 锁外逐条验证模块归属并生成用户可见行。
    for (snapshotIndex = 0UL;
         snapshotIndex < snapshotCount;
         ++snapshotIndex) {
        // snapshot 仅指向非分页本地数组，不依赖私有链节点继续存活。
        const KSWORD_ARK_CALLBACK_NMI_SNAPSHOT* snapshot =
            &snapshots[snapshotIndex];
        // 名称和详情写入固定大小的协议字段。
        WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
        WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

        // 模块缓存可能执行复杂查询，必须位于释放 NMI 自旋锁之后。
        if (!KswordArkCallbackEnumIsKernelModuleAddress(
                ModuleCache,
                snapshot->CallbackRoutine)) {
            snapshotStatus = STATUS_DATA_ERROR;
            failureAddress = snapshot->NodeAddress;
            break;
        }
        // 所有输出缓冲在格式化前清零。
        RtlZeroMemory(nameText, sizeof(nameText));
        RtlZeroMemory(detailText, sizeof(detailText));
        // 使用锁内记录的序号生成稳定、可读的注册项名称。
        (VOID)RtlStringCbPrintfW(
            nameText,
            sizeof(nameText),
            L"KeRegisterNmiCallback[%lu]",
            (unsigned long)snapshot->TraversalIndex);
        // 详情完全由标量快照构建，不解引用可能已注销的节点。
        (VOID)RtlStringCbPrintfW(
            detailText,
            sizeof(detailText),
            L"NMI callback；headStorage=0x%p，lock=0x%p，node=0x%p，handle=0x%p，next=0x%p。",
            (PVOID)(ULONG_PTR)HeadStorageAddress,
            (PVOID)(ULONG_PTR)LockAddress,
            (PVOID)(ULONG_PTR)snapshot->NodeAddress,
            (PVOID)(ULONG_PTR)snapshot->Handle,
            (PVOID)(ULONG_PTR)snapshot->Next);
        // 统一行构建器会补全模块归属、信任和分页元数据。
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_OK,
            STATUS_SUCCESS,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            snapshot->CallbackRoutine,
            snapshot->CallbackContext,
            snapshot->NodeAddress,
            0UL,
            nameText,
            detailText);
    }

    // 任何链头、节点、模块或上限失败都在锁外输出一条统一诊断。
    if (!NT_SUCCESS(snapshotStatus)) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            snapshotStatus,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            LockAddress,
            failureAddress,
            0UL,
            snapshotStatus == STATUS_BUFFER_OVERFLOW
                ? L"KeRegisterNmiCallback walk limit reached"
                : L"KeRegisterNmiCallback node validation failed",
            snapshotStatus == STATUS_BUFFER_OVERFLOW
                ? L"NMI 私有链超过安全遍历上限，已在释放自旋锁后停止输出。"
                : L"NMI 私有链未通过链头、布局、句柄、模块归属或 next 指针验证。");
    }

    // 释放锁前分配的非分页快照数组。
    ExFreePoolWithTag(
        snapshots,
        KSWORD_ARK_CALLBACK_NMI_SNAPSHOT_TAG);
}

#endif

VOID
KswordArkCallbackExtendedAddNmiCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    NMI 回调枚举入口。初始化模块缓存、定位当前系统的私有注册链并执行有界
    遍历；任何不受支持或无法验证的情况都会转换为可见诊断行。

Arguments:

    Builder - 当前 IOCTL 请求使用的枚举构建器。

Return Value:

    无返回值。

--*/
{
    // 模块缓存让每个 NMI 回调地址可以解析到拥有者映像。
    KSWORD_ARK_CALLBACK_MODULE_CACHE moduleCache;
    // 非 AMD64 架构默认明确报告不支持。
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    // 定位结果在成功前保持为零。
    ULONG64 headStorageAddress = 0ULL;
    ULONG64 lockAddress = 0ULL;

    // 构建器是必需的输出上下文。
    if (Builder == NULL) {
        return;
    }

    // 缓存生命周期严格限制在本类回调枚举期间。
    KswordArkCallbackEnumInitModuleCache(&moduleCache);
    // NMI 私有节点必须把回调函数解析到已加载内核模块，防止接受伪造代码地址。
    status = KswordArkCallbackEnumEnsureModuleCache(&moduleCache);
    if (!NT_SUCCESS(status)) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"NMI callback module inventory unavailable",
            L"无法取得已加载内核模块清单，已停止 NMI 私有链枚举以避免接受未验证的函数地址。");
        KswordArkCallbackEnumFreeModuleCache(&moduleCache);
        return;
    }
#if defined(_M_AMD64)
    // AMD64 使用导出例程的受限代码形态定位私有链。
    status = KswordArkCallbackExtendedLocateNmiList(
        &headStorageAddress,
        &lockAddress);
    // 仅定位成功时允许在持有私有自旋锁的条件下读取并遍历节点。
    if (NT_SUCCESS(status)) {
        KswordArkCallbackExtendedWalkNmiList(
            Builder,
            &moduleCache,
            headStorageAddress,
            lockAddress);
    }
    else
#else
    // 非 AMD64 构建中显式标记占位变量，保持 /W4 /WX 无警告。
    UNREFERENCED_PARAMETER(headStorageAddress);
    UNREFERENCED_PARAMETER(lockAddress);
#endif
    {
        // 定位失败也必须成为一行可诊断结果，而不是静默漏报。
        KswordArkCallbackExtendedAddRow(
            Builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            status,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            0ULL,
            0ULL,
            0UL,
            L"KeRegisterNmiCallback list unavailable",
            L"无法从当前架构的 KeRegisterNmiCallback 导出代码安全定位 NMI 注册链。");
    }
    // 无论成功或失败都释放系统模块快照缓存。
    KswordArkCallbackEnumFreeModuleCache(&moduleCache);
}
