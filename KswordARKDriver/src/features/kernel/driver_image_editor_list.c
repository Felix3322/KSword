/*++

Module Name:

    driver_image_editor_list.c

Abstract:

    Resolves the exact ntoskrnl module-list exports, holds the real loader
    resource, validates reciprocal LIST_ENTRY links, and performs reversible
    PsLoadedModuleList unlink/reinsert operations.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL transaction path.

--*/

#include "driver_image_editor_internal.h"

// 中文说明：仓库现有 fallback 已使用该 ntoskrnl 导出解析器；这里同样只解析精确数据导出名。
NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,
    _In_ PCCH RoutineName
    );

// 中文说明：确认导出变量完整落在身份匹配的 ntoskrnl 映像范围内。
static BOOLEAN
KswordARKDriverImageAddressInNtos(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* Identity,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T RequiredBytes
    )
{
    ULONG_PTR imageBase = 0U;
    ULONG_PTR imageEnd = 0U;

    // 中文说明：缺少当前内核身份时不把任意地址当成加载器同步对象。
    if (Identity == NULL || Identity->present == 0UL ||
        Identity->imageBase == 0ULL || Identity->sizeOfImage == 0UL) {
        return FALSE;
    }
    // 中文说明：先检查映像区间加法，避免地址回绕造成伪范围命中。
    imageBase = (ULONG_PTR)Identity->imageBase;
    if (imageBase > MAXULONG_PTR - Identity->sizeOfImage) {
        return FALSE;
    }
    imageEnd = imageBase + Identity->sizeOfImage;
    // 中文说明：要求完整对象范围都位于映像内，不能只验证首地址。
    if (Address < imageBase || Address >= imageEnd ||
        RequiredBytes > imageEnd - Address) {
        return FALSE;
    }
    return TRUE;
}

// 中文说明：所有链和 KLDR 小字段读取都经过异常边界，损坏地址只返回状态。
static BOOLEAN
KswordARKDriverImageReadMemory(
    _In_ const VOID* Address,
    _Out_writes_bytes_(Size) VOID* Buffer,
    _In_ SIZE_T Size
    )
{
    // 中文说明：拒绝空地址、空输出和零长度，避免掩盖调用方协议错误。
    if (Address == NULL || Buffer == NULL || Size == 0U) {
        return FALSE;
    }
    __try {
        // 中文说明：事务仅复制固定宽度的常驻内核标量或 LIST_ENTRY。
        RtlCopyMemory(Buffer, Address, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 中文说明：页错误或无效映射转成可诊断失败，不继续解引用相邻节点。
        return FALSE;
    }
    return TRUE;
}

// 中文说明：运行时解析同时证明 DynData 布局、链头导出与资源锁导出属于同一 ntoskrnl。
NTSTATUS
KswordARKDriverImageResolveRuntime(
    _Out_ KSW_DRIVER_IMAGE_RUNTIME* Runtime
    )
{
    PVOID imageBase = NULL;
    PLIST_ENTRY exportedListHead = NULL;
    PERESOURCE exportedResource = NULL;
    ULONGLONG dynDataListHead = 0ULL;

    // 中文说明：输出先清零，失败响应不会携带上一次查询的内核地址。
    if (Runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Runtime, sizeof(*Runtime));
    // 中文说明：快照复制已经由 DynData 模块内部同步，不持有其全局锁跨模块操作。
    KswordARKDynDataSnapshot(&Runtime->DynState);
    if (!Runtime->DynState.Initialized || !Runtime->DynState.NtosActive ||
        Runtime->DynState.Ntoskrnl.imageBase == 0ULL ||
        Runtime->DynState.Ntoskrnl.sizeOfImage == 0UL) {
        return STATUS_NOT_SUPPORTED;
    }
    // 中文说明：KLDR 私有字段必须来自 PDB 或逐字段实时验证过的 fallback。
    if ((Runtime->DynState.CapabilityMask &
        KSW_CAP_KERNEL_MODULE_LIST_FIELDS) == 0ULL ||
        !KswordARKDriverIntegrityOffsetPresent(
            Runtime->DynState.Kernel.KldrInLoadOrderLinks) ||
        !KswordARKDriverIntegrityOffsetPresent(
            Runtime->DynState.Kernel.KldrDllBase) ||
        !KswordARKDriverIntegrityOffsetPresent(
            Runtime->DynState.Kernel.KldrSizeOfImage)) {
        return STATUS_NOT_SUPPORTED;
    }

    // 中文说明：直接从身份匹配的活动映像解析数据导出，不使用用户传入的地址。
    imageBase = (PVOID)(ULONG_PTR)Runtime->DynState.Ntoskrnl.imageBase;
    exportedListHead = (PLIST_ENTRY)RtlFindExportedRoutineByName(
        imageBase,
        "PsLoadedModuleList");
    exportedResource = (PERESOURCE)RtlFindExportedRoutineByName(
        imageBase,
        "PsLoadedModuleResource");
    if (exportedListHead == NULL || exportedResource == NULL) {
        return STATUS_NOT_SUPPORTED;
    }
    // 中文说明：两个变量本体都必须完整位于当前 ntoskrnl 映像数据区间。
    if (!KswordARKDriverImageAddressInNtos(
            &Runtime->DynState.Ntoskrnl,
            (ULONG_PTR)exportedListHead,
            sizeof(*exportedListHead)) ||
        !KswordARKDriverImageAddressInNtos(
            &Runtime->DynState.Ntoskrnl,
            (ULONG_PTR)exportedResource,
            sizeof(*exportedResource))) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    // 中文说明：DynData 的 PsLoadedModuleList RVA 必须与 PE 精确导出指向同一地址。
    dynDataListHead = KswordARKDriverIntegrityNtosAddressFromRva(
        &Runtime->DynState,
        Runtime->DynState.KernelGlobals.PsLoadedModuleList,
        sizeof(LIST_ENTRY));
    if (dynDataListHead == 0ULL ||
        dynDataListHead != (ULONGLONG)(ULONG_PTR)exportedListHead) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    // 中文说明：发布运行时对象后，调用方仍必须显式 AcquireRuntime 才能读写链。
    Runtime->ListHead = exportedListHead;
    Runtime->ListResource = exportedResource;
    Runtime->LayoutFlags =
        KSWORD_ARK_DRIVER_IMAGE_LAYOUT_FLAG_DYNDATA_VALIDATED |
        KSWORD_ARK_DRIVER_IMAGE_LAYOUT_FLAG_LIST_EXPORT |
        KSWORD_ARK_DRIVER_IMAGE_LAYOUT_FLAG_RESOURCE_EXPORT;
    return STATUS_SUCCESS;
}

// 中文说明：资源锁调用遵循微软 ERESOURCE 约定，等待期间保持普通内核 APC 禁用。
NTSTATUS
KswordARKDriverImageAcquireRuntime(
    _Inout_ KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ BOOLEAN Exclusive
    )
{
    BOOLEAN acquired = FALSE;

    // 中文说明：重复获取和高 IRQL 调用会破坏资源配对，因此直接拒绝。
    if (Runtime == NULL || Runtime->ListResource == NULL ||
        Runtime->ResourceAcquired != FALSE ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    // 中文说明：ERESOURCE 等待要求禁用普通内核 APC，释放时严格对称恢复。
    KeEnterCriticalRegion();
    if (Exclusive != FALSE) {
        acquired = ExAcquireResourceExclusiveLite(
            Runtime->ListResource,
            TRUE);
    }
    else {
        acquired = ExAcquireResourceSharedLite(
            Runtime->ListResource,
            TRUE);
    }
    if (acquired == FALSE) {
        // 中文说明：Wait=TRUE 理论上应成功；仍保留确定的异常退出路径。
        KeLeaveCriticalRegion();
        return STATUS_DEVICE_BUSY;
    }
    Runtime->ResourceAcquired = TRUE;
    Runtime->ResourceExclusive = Exclusive;
    return STATUS_SUCCESS;
}

// 中文说明：统一释放避免任何错误路径遗漏 ExReleaseResourceLite/KeLeaveCriticalRegion。
VOID
KswordARKDriverImageReleaseRuntime(
    _Inout_ KSW_DRIVER_IMAGE_RUNTIME* Runtime
    )
{
    // 中文说明：未成功获取时不触碰不属于当前线程的系统资源。
    if (Runtime == NULL || Runtime->ResourceAcquired == FALSE ||
        Runtime->ListResource == NULL) {
        return;
    }
    ExReleaseResourceLite(Runtime->ListResource);
    Runtime->ResourceAcquired = FALSE;
    Runtime->ResourceExclusive = FALSE;
    KeLeaveCriticalRegion();
}

// 中文说明：在已持有模块资源时完整遍历一次链，并返回目标 link 的成员状态。
static NTSTATUS
KswordARKDriverImageInspectLinkLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ PLIST_ENTRY TargetLink,
    _Inout_ KSW_DRIVER_IMAGE_LINK_VIEW* View
    )
{
    LIST_ENTRY headSnapshot;
    LIST_ENTRY targetSnapshot;
    PLIST_ENTRY current = NULL;
    PLIST_ENTRY previous = NULL;
    ULONG visited = 0UL;

    // 中文说明：链读取必须发生在真实 PsLoadedModuleResource 的共享或独占持有期。
    if (Runtime == NULL || View == NULL || TargetLink == NULL ||
        Runtime->ListHead == NULL || Runtime->ResourceAcquired == FALSE ||
        TargetLink == Runtime->ListHead) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&headSnapshot, sizeof(headSnapshot));
    RtlZeroMemory(&targetSnapshot, sizeof(targetSnapshot));
    if (!KswordARKDriverImageReadMemory(
            Runtime->ListHead,
            &headSnapshot,
            sizeof(headSnapshot)) ||
        !KswordARKDriverImageReadMemory(
            TargetLink,
            &targetSnapshot,
            sizeof(targetSnapshot))) {
        View->Malformed = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }
    // 中文说明：自环且未出现在主链中是本事务定义的隐藏表示。
    if (targetSnapshot.Flink == TargetLink &&
        targetSnapshot.Blink == TargetLink) {
        View->SelfLinked = TRUE;
    }
    if (headSnapshot.Flink == NULL || headSnapshot.Blink == NULL) {
        View->Malformed = TRUE;
        return STATUS_DATA_ERROR;
    }

    // 中文说明：从链头开始核对每一项的 Blink 与上一项互为反向关系。
    current = headSnapshot.Flink;
    previous = Runtime->ListHead;
    while (current != Runtime->ListHead && visited < KSW_DRIVER_IMAGE_LIST_WALK_LIMIT) {
        LIST_ENTRY currentSnapshot;

        if (current == NULL) {
            View->Malformed = TRUE;
            return STATUS_DATA_ERROR;
        }
        RtlZeroMemory(&currentSnapshot, sizeof(currentSnapshot));
        if (!KswordARKDriverImageReadMemory(
                current,
                &currentSnapshot,
                sizeof(currentSnapshot)) ||
            currentSnapshot.Flink == NULL ||
            currentSnapshot.Blink != previous) {
            View->Malformed = TRUE;
            return STATUS_DATA_ERROR;
        }
        // 中文说明：命中目标时保存受锁保护的当前邻居，不直接信任 R3 地址。
        if (current == TargetLink) {
            View->InList = TRUE;
            View->Flink = currentSnapshot.Flink;
            View->Blink = currentSnapshot.Blink;
        }
        previous = current;
        current = currentSnapshot.Flink;
        ++visited;
    }
    // 中文说明：超预算或未回到链头都表示循环/断链，禁止任何写操作。
    if (current != Runtime->ListHead ||
        visited >= KSW_DRIVER_IMAGE_LIST_WALK_LIMIT ||
        headSnapshot.Blink != previous) {
        View->Malformed = TRUE;
        return STATUS_DATA_ERROR;
    }
    // 中文说明：目标不在主链时只接受明确自环；悬空到其它节点视为外部冲突。
    if (View->InList == FALSE && View->SelfLinked == FALSE) {
        View->Malformed = TRUE;
        View->Flink = targetSnapshot.Flink;
        View->Blink = targetSnapshot.Blink;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (View->InList == FALSE) {
        View->Flink = targetSnapshot.Flink;
        View->Blink = targetSnapshot.Blink;
    }
    return STATUS_SUCCESS;
}

// 中文说明：按精确 DriverStart/DllBase 定位初始 loader 项，不接受仅落在模块区间内的模糊命中。
NTSTATUS
KswordARKDriverImageLocateLoaderLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ ULONGLONG DriverStart,
    _Out_ KSW_DRIVER_IMAGE_LINK_VIEW* View
    )
{
    KSW_DRIVER_INTEGRITY_LDR_TARGET target;
    NTSTATUS status = STATUS_SUCCESS;

    // 中文说明：DriverStart 为零时没有可证明的 KLDR 映像身份。
    if (Runtime == NULL || View == NULL || DriverStart == 0ULL ||
        Runtime->ResourceAcquired == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(View, sizeof(*View));
    RtlZeroMemory(&target, sizeof(target));
    status = KswordARKDriverIntegrityFindLoadedModule(
        &Runtime->DynState,
        DriverStart,
        &target);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // 中文说明：完整相等比“地址位于映像范围”更强，防止选择错误 loader 记录。
    if (!target.Found || target.DllBase != DriverStart ||
        target.EntryAddress == 0ULL || target.LinkAddress == 0ULL ||
        target.ListHeadAddress != (ULONGLONG)(ULONG_PTR)Runtime->ListHead) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    View->LoaderAvailable = TRUE;
    View->EntryAddress = target.EntryAddress;
    View->LinkAddress = target.LinkAddress;
    View->DllBase = target.DllBase;
    View->SizeOfImage = target.SizeOfImage;
    status = KswordARKDriverImageInspectLinkLocked(
        Runtime,
        (PLIST_ENTRY)(ULONG_PTR)target.LinkAddress,
        View);
    return status;
}

// 中文说明：已有记录从保存的 loader 项读取字段，并重新证明 link 与活动布局一致。
NTSTATUS
KswordARKDriverImageInspectRecordLinkLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ const KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ KSW_DRIVER_IMAGE_LINK_VIEW* View
    )
{
    ULONGLONG dllBase = 0ULL;
    ULONG sizeOfImage = 0UL;
    ULONGLONG expectedLink = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Runtime == NULL || Record == NULL || View == NULL ||
        Record->LoaderEntry == NULL || Record->LoaderLink == NULL ||
        Runtime->ResourceAcquired == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(View, sizeof(*View));
    // 中文说明：保存的 link 必须仍等于 loader 基址加实时验证偏移。
    expectedLink = (ULONGLONG)(ULONG_PTR)Record->LoaderEntry +
        (ULONGLONG)Runtime->DynState.Kernel.KldrInLoadOrderLinks;
    if (expectedLink != (ULONGLONG)(ULONG_PTR)Record->LoaderLink) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    // 中文说明：KLDR 字段地址来自活动 DynData，读取失败时不继续链写入。
    if (!KswordARKDriverImageReadMemory(
            (const UCHAR*)Record->LoaderEntry +
                Runtime->DynState.Kernel.KldrDllBase,
            &dllBase,
            sizeof(dllBase)) ||
        !KswordARKDriverImageReadMemory(
            (const UCHAR*)Record->LoaderEntry +
                Runtime->DynState.Kernel.KldrSizeOfImage,
            &sizeOfImage,
            sizeof(sizeOfImage))) {
        return STATUS_ACCESS_VIOLATION;
    }
    View->LoaderAvailable = TRUE;
    View->EntryAddress = (ULONGLONG)(ULONG_PTR)Record->LoaderEntry;
    View->LinkAddress = (ULONGLONG)(ULONG_PTR)Record->LoaderLink;
    View->DllBase = dllBase;
    View->SizeOfImage = sizeOfImage;
    status = KswordARKDriverImageInspectLinkLocked(
        Runtime,
        Record->LoaderLink,
        View);
    return status;
}

// 中文说明：摘链在系统资源独占持有期执行，并在返回前验证目标已经自环。
NTSTATUS
KswordARKDriverImageHideLinkLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ PLIST_ENTRY ExpectedFlink,
    _In_ PLIST_ENTRY ExpectedBlink,
    _Out_ BOOLEAN* Changed
    )
{
    KSW_DRIVER_IMAGE_LINK_VIEW beforeView;
    KSW_DRIVER_IMAGE_LINK_VIEW afterView;
    NTSTATUS status = STATUS_SUCCESS;

    if (Runtime == NULL || Record == NULL || Changed == NULL ||
        Runtime->ResourceAcquired == FALSE ||
        Runtime->ResourceExclusive == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    *Changed = FALSE;
    RtlZeroMemory(&beforeView, sizeof(beforeView));
    RtlZeroMemory(&afterView, sizeof(afterView));
    status = KswordARKDriverImageInspectRecordLinkLocked(
        Runtime,
        Record,
        &beforeView);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // 中文说明：本事务已经拥有自环时，HIDE 是幂等成功，不重写邻居。
    if (beforeView.SelfLinked != FALSE && Record->LinkOwned != FALSE) {
        return STATUS_SUCCESS;
    }
    if (beforeView.InList == FALSE || beforeView.Malformed != FALSE ||
        beforeView.Flink != ExpectedFlink ||
        beforeView.Blink != ExpectedBlink) {
        return STATUS_RETRY;
    }

    // 中文说明：首次摘链保存精确原邻居，后续恢复优先使用该位置。
    Record->OriginalLinkFlink = beforeView.Flink;
    Record->OriginalLinkBlink = beforeView.Blink;
    __try {
        // 中文说明：RemoveEntryList 只改相邻节点；InitializeListHead 明确标记隐藏所有权。
        (VOID)RemoveEntryList(Record->LoaderLink);
        InitializeListHead(Record->LoaderLink);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Record->LinkConflict = TRUE;
        return GetExceptionCode();
    }
    status = KswordARKDriverImageInspectRecordLinkLocked(
        Runtime,
        Record,
        &afterView);
    if (!NT_SUCCESS(status) || afterView.SelfLinked == FALSE ||
        afterView.InList != FALSE) {
        Record->LinkConflict = TRUE;
        return NT_SUCCESS(status) ? STATUS_DATA_ERROR : status;
    }
    Record->LinkManaged = TRUE;
    Record->LinkOwned = TRUE;
    Record->LinkConflict = FALSE;
    *Changed = TRUE;
    return STATUS_SUCCESS;
}

// 中文说明：检查候选邻居是否仍在受锁主链中，并返回其当前 LIST_ENTRY 快照。
static BOOLEAN
KswordARKDriverImageFindLiveLinkLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ PLIST_ENTRY Candidate,
    _Out_ LIST_ENTRY* Snapshot
    )
{
    LIST_ENTRY headSnapshot;
    PLIST_ENTRY current = NULL;
    ULONG visited = 0UL;

    if (Runtime == NULL || Candidate == NULL || Snapshot == NULL ||
        Runtime->ResourceAcquired == FALSE) {
        return FALSE;
    }
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    RtlZeroMemory(&headSnapshot, sizeof(headSnapshot));
    if (!KswordARKDriverImageReadMemory(
            Runtime->ListHead,
            &headSnapshot,
            sizeof(headSnapshot))) {
        return FALSE;
    }
    // 中文说明：链头本身是合法恢复邻居，直接返回其受锁快照。
    if (Candidate == Runtime->ListHead) {
        *Snapshot = headSnapshot;
        return TRUE;
    }
    current = headSnapshot.Flink;
    while (current != NULL && current != Runtime->ListHead &&
        visited < KSW_DRIVER_IMAGE_LIST_WALK_LIMIT) {
        LIST_ENTRY currentSnapshot;

        RtlZeroMemory(&currentSnapshot, sizeof(currentSnapshot));
        if (!KswordARKDriverImageReadMemory(
                current,
                &currentSnapshot,
                sizeof(currentSnapshot))) {
            return FALSE;
        }
        if (current == Candidate) {
            *Snapshot = currentSnapshot;
            return TRUE;
        }
        current = currentSnapshot.Flink;
        ++visited;
    }
    return FALSE;
}

// 中文说明：插入函数在独占资源下写四个指针，并把异常转换成可诊断状态。
static NTSTATUS
KswordARKDriverImageInsertBetweenLocked(
    _In_ PLIST_ENTRY Link,
    _In_ PLIST_ENTRY Previous,
    _In_ PLIST_ENTRY Next
    )
{
    if (Link == NULL || Previous == NULL || Next == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        // 中文说明：先准备目标项，再发布前向和后向邻居，受资源锁的读者不会见到半成品。
        Link->Blink = Previous;
        Link->Flink = Next;
        Previous->Flink = Link;
        Next->Blink = Link;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

// 中文说明：恢复链成员身份；原邻居不再存在时使用当前链尾，绝不写入失效旧邻居。
NTSTATUS
KswordARKDriverImageRestoreLinkLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ BOOLEAN* Changed,
    _Out_ BOOLEAN* OriginalPosition
    )
{
    KSW_DRIVER_IMAGE_LINK_VIEW beforeView;
    KSW_DRIVER_IMAGE_LINK_VIEW afterView;
    LIST_ENTRY previousSnapshot;
    LIST_ENTRY nextSnapshot;
    LIST_ENTRY headSnapshot;
    LIST_ENTRY tailSnapshot;
    PLIST_ENTRY previous = NULL;
    PLIST_ENTRY next = NULL;
    PLIST_ENTRY tail = NULL;
    BOOLEAN useOriginalPosition = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (Runtime == NULL || Record == NULL || Changed == NULL ||
        OriginalPosition == NULL || Runtime->ResourceAcquired == FALSE ||
        Runtime->ResourceExclusive == FALSE) {
        return STATUS_INVALID_PARAMETER;
    }
    *Changed = FALSE;
    *OriginalPosition = FALSE;
    RtlZeroMemory(&beforeView, sizeof(beforeView));
    RtlZeroMemory(&afterView, sizeof(afterView));
    RtlZeroMemory(&previousSnapshot, sizeof(previousSnapshot));
    RtlZeroMemory(&nextSnapshot, sizeof(nextSnapshot));
    RtlZeroMemory(&headSnapshot, sizeof(headSnapshot));
    RtlZeroMemory(&tailSnapshot, sizeof(tailSnapshot));

    status = KswordARKDriverImageInspectRecordLinkLocked(
        Runtime,
        Record,
        &beforeView);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    // 中文说明：已经在主链中时不再次插入；调用方会据当前位置判断外部恢复或冲突。
    if (beforeView.InList != FALSE) {
        return STATUS_SUCCESS;
    }
    if (beforeView.SelfLinked == FALSE || Record->LinkOwned == FALSE ||
        Record->OriginalLinkFlink == NULL ||
        Record->OriginalLinkBlink == NULL) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    // 中文说明：只有原前后邻居仍在主链且彼此相邻时才写回原位置。
    previous = Record->OriginalLinkBlink;
    next = Record->OriginalLinkFlink;
    if (KswordARKDriverImageFindLiveLinkLocked(
            Runtime,
            previous,
            &previousSnapshot) &&
        KswordARKDriverImageFindLiveLinkLocked(
            Runtime,
            next,
            &nextSnapshot) &&
        previousSnapshot.Flink == next &&
        nextSnapshot.Blink == previous) {
        useOriginalPosition = TRUE;
    }
    if (useOriginalPosition == FALSE) {
        // 中文说明：旧邻居可能已卸载；只从当前链头取得受保护的有效尾节点。
        if (!KswordARKDriverImageReadMemory(
                Runtime->ListHead,
                &headSnapshot,
                sizeof(headSnapshot)) ||
            headSnapshot.Blink == NULL) {
            return STATUS_DATA_ERROR;
        }
        tail = headSnapshot.Blink;
        if (!KswordARKDriverImageFindLiveLinkLocked(
                Runtime,
                tail,
                &tailSnapshot) ||
            tailSnapshot.Flink != Runtime->ListHead) {
            return STATUS_DATA_ERROR;
        }
        previous = tail;
        next = Runtime->ListHead;
    }

    status = KswordARKDriverImageInsertBetweenLocked(
        Record->LoaderLink,
        previous,
        next);
    if (!NT_SUCCESS(status)) {
        Record->LinkConflict = TRUE;
        return status;
    }
    status = KswordARKDriverImageInspectRecordLinkLocked(
        Runtime,
        Record,
        &afterView);
    if (!NT_SUCCESS(status) || afterView.InList == FALSE ||
        afterView.SelfLinked != FALSE) {
        Record->LinkConflict = TRUE;
        return NT_SUCCESS(status) ? STATUS_DATA_ERROR : status;
    }
    Record->LinkManaged = FALSE;
    Record->LinkOwned = FALSE;
    Record->LinkConflict = FALSE;
    *Changed = TRUE;
    *OriginalPosition = useOriginalPosition;
    return STATUS_SUCCESS;
}
