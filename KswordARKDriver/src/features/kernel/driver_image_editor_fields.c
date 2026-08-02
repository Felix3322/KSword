/*++

Module Name:

    driver_image_editor_fields.c

Abstract:

    Atomic DriverObject/KLDR field transaction helpers with multi-field
    compare-and-swap, reverse rollback, conservative ownership refresh, and
    restore-to-original semantics.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include "driver_image_editor_internal.h"

// 中文说明：字段按固定次序应用，回滚时严格反向遍历，避免部分事务次序不确定。
static const ULONG g_KswordArkDriverImageFields[] = {
    KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START,
    KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE,
    KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION,
    KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE,
    KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE
};

C_ASSERT(sizeof(PVOID) == sizeof(ULONGLONG));

// 中文说明：KLDR 两字段依赖活动布局和 PsLoadedModuleResource，DriverObject 三字段不依赖。
static BOOLEAN
KswordARKDriverImageIsLoaderField(
    _In_ ULONG Field
    )
{
    return Field == KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE ||
        Field == KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE;
}

// 中文说明：两个 size 字段物理宽度均为 ULONG，协议中的高位不能静默截断。
static BOOLEAN
KswordARKDriverImageValuesFitFieldWidths(
    _In_ ULONG FieldMask,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* Values
    )
{
    if (Values == NULL) {
        return FALSE;
    }
    if ((FieldMask & KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE) != 0UL &&
        Values->driverSize > MAXULONG) {
        return FALSE;
    }
    if ((FieldMask & KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE) != 0UL &&
        Values->kldrSizeOfImage > MAXULONG) {
        return FALSE;
    }
    return TRUE;
}

// 中文说明：协议值按单字段位取出，调用方只传入五个合法单比特常量。
static ULONGLONG
KswordARKDriverImageGetValue(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* Values,
    _In_ ULONG Field
    )
{
    switch (Field) {
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START:
        return Values->driverStart;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE:
        return Values->driverSize;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION:
        return Values->driverSection;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE:
        return Values->kldrDllBase;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE:
        return Values->kldrSizeOfImage;
    default:
        return 0ULL;
    }
}

// 中文说明：字段写入事务快照时保持原始位模式，不解释任意指针值。
static VOID
KswordARKDriverImageSetValue(
    _Inout_ KSWORD_ARK_DRIVER_IMAGE_VALUES* Values,
    _In_ ULONG Field,
    _In_ ULONGLONG Value
    )
{
    switch (Field) {
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START:
        Values->driverStart = Value;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE:
        Values->driverSize = Value;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION:
        Values->driverSection = Value;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE:
        Values->kldrDllBase = Value;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE:
        Values->kldrSizeOfImage = Value;
        break;
    default:
        break;
    }
}

// 中文说明：解析真实字段地址时只使用 WDK DriverObject 成员或实时验证过的 KLDR 偏移。
static NTSTATUS
KswordARKDriverImageResolveFieldAddress(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ const KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ ULONG Field,
    _Outptr_ PVOID* Address,
    _Out_ BOOLEAN* PointerSized
    )
{
    ULONG_PTR loaderBase = 0U;
    ULONG offset = 0UL;

    if (Record == NULL || Record->DriverObject == NULL ||
        Address == NULL || PointerSized == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Address = NULL;
    *PointerSized = FALSE;

    // 中文说明：公开 DRIVER_OBJECT 字段直接由 WDK 布局给出，不接受 R3 偏移。
    switch (Field) {
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_START:
        *Address = &Record->DriverObject->DriverStart;
        *PointerSized = TRUE;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SIZE:
        *Address = &Record->DriverObject->DriverSize;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_DRIVER_SECTION:
        *Address = &Record->DriverObject->DriverSection;
        *PointerSized = TRUE;
        break;
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE:
    case KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_SIZE_OF_IMAGE:
        // 中文说明：KLDR 地址只有在真实资源持有期和保存 loader 身份存在时才可形成。
        if (Runtime == NULL || Runtime->ResourceAcquired == FALSE ||
            Record->LoaderEntry == NULL) {
            return STATUS_NOT_SUPPORTED;
        }
        offset = Field == KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE
            ? Runtime->DynState.Kernel.KldrDllBase
            : Runtime->DynState.Kernel.KldrSizeOfImage;
        if (!KswordARKDriverIntegrityOffsetPresent(offset)) {
            return STATUS_NOT_SUPPORTED;
        }
        loaderBase = (ULONG_PTR)Record->LoaderEntry;
        if (loaderBase > MAXULONG_PTR - offset) {
            return STATUS_INTEGER_OVERFLOW;
        }
        *Address = (PVOID)(loaderBase + offset);
        *PointerSized =
            Field == KSWORD_ARK_DRIVER_IMAGE_FIELD_KLDR_DLL_BASE;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    // 中文说明：Interlocked 原语要求自然对齐；布局异常时拒绝产生不可预测总线访问。
    if (*Address == NULL ||
        (*PointerSized != FALSE &&
         ((ULONG_PTR)*Address % TYPE_ALIGNMENT(PVOID)) != 0U) ||
        (*PointerSized == FALSE &&
         ((ULONG_PTR)*Address % TYPE_ALIGNMENT(ULONG)) != 0U)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    return STATUS_SUCCESS;
}

// 中文说明：原子读取对无效/已释放地址增加 SEH 边界，失败不会继续邻接写入。
static NTSTATUS
KswordARKDriverImageReadField(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ const KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ ULONG Field,
    _Out_ ULONGLONG* Value
    )
{
    PVOID address = NULL;
    BOOLEAN pointerSized = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (Value == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Value = 0ULL;
    status = KswordARKDriverImageResolveFieldAddress(
        Runtime,
        Record,
        Field,
        &address,
        &pointerSized);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        if (pointerSized != FALSE) {
            PVOID current = InterlockedCompareExchangePointer(
                (PVOID volatile*)address,
                NULL,
                NULL);
            *Value = (ULONGLONG)(ULONG_PTR)current;
        }
        else {
            LONG current = InterlockedCompareExchange(
                (volatile LONG*)address,
                0L,
                0L);
            *Value = (ULONGLONG)(ULONG)current;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return (NTSTATUS)GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

// 中文说明：单字段 CAS 返回实际观察值，调用方据此区分成功、竞争和异常。
static NTSTATUS
KswordARKDriverImageCompareExchangeField(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ const KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ ULONG Field,
    _In_ ULONGLONG Desired,
    _In_ ULONGLONG Expected,
    _Out_ ULONGLONG* Observed
    )
{
    PVOID address = NULL;
    BOOLEAN pointerSized = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (Observed == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Observed = 0ULL;
    status = KswordARKDriverImageResolveFieldAddress(
        Runtime,
        Record,
        Field,
        &address,
        &pointerSized);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (pointerSized == FALSE &&
        (Desired > MAXULONG || Expected > MAXULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        if (pointerSized != FALSE) {
            PVOID previous = InterlockedCompareExchangePointer(
                (PVOID volatile*)address,
                (PVOID)(ULONG_PTR)Desired,
                (PVOID)(ULONG_PTR)Expected);
            *Observed = (ULONGLONG)(ULONG_PTR)previous;
        }
        else {
            LONG previous = InterlockedCompareExchange(
                (volatile LONG*)address,
                (LONG)(ULONG)Desired,
                (LONG)(ULONG)Expected);
            *Observed = (ULONGLONG)(ULONG)previous;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return (NTSTATUS)GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

// 中文说明：采样函数总能返回三个 DriverObject 字段；KLDR 可用性由位掩码显式表达。
NTSTATUS
KswordARKDriverImageReadValuesLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _In_ const KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_VALUES* Values,
    _Out_ ULONG* AvailableFieldMask
    )
{
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Record == NULL || Values == NULL || AvailableFieldMask == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Values, sizeof(*Values));
    *AvailableFieldMask = 0UL;

    for (index = 0UL;
        index < RTL_NUMBER_OF(g_KswordArkDriverImageFields);
        ++index) {
        ULONG field = g_KswordArkDriverImageFields[index];
        ULONGLONG value = 0ULL;

        status = KswordARKDriverImageReadField(
            Runtime,
            Record,
            field,
            &value);
        if (!NT_SUCCESS(status)) {
            // 中文说明：DriverObject 字段失败代表对象不再可靠；KLDR 缺失仅形成部分视图。
            if (KswordARKDriverImageIsLoaderField(field) == FALSE) {
                return status;
            }
            continue;
        }
        KswordARKDriverImageSetValue(Values, field, value);
        *AvailableFieldMask |= field;
    }
    return STATUS_SUCCESS;
}

// 中文说明：应用五字段中的任意组合；任何中途竞争都反向回滚已成功 CAS 的字段。
NTSTATUS
KswordARKDriverImageApplyFieldsLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ ULONG FieldMask,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* ExpectedValues,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* DesiredValues,
    _Out_ ULONG* ChangedFieldMask,
    _Out_ ULONG* RollbackConflictMask
    )
{
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    ULONG appliedMask = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Record == NULL || ExpectedValues == NULL || DesiredValues == NULL ||
        ChangedFieldMask == NULL || RollbackConflictMask == NULL ||
        FieldMask == 0UL ||
        (FieldMask & ~KSWORD_ARK_DRIVER_IMAGE_FIELD_ALL) != 0UL ||
        !KswordARKDriverImageValuesFitFieldWidths(FieldMask, ExpectedValues) ||
        !KswordARKDriverImageValuesFitFieldWidths(FieldMask, DesiredValues)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&currentValues, sizeof(currentValues));
    *ChangedFieldMask = 0UL;
    *RollbackConflictMask = 0UL;

    status = KswordARKDriverImageReadValuesLocked(
        Runtime,
        Record,
        &currentValues,
        &availableMask);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if ((availableMask & FieldMask) != FieldMask) {
        return STATUS_NOT_SUPPORTED;
    }

    // 中文说明：先验证完整 expected 快照，再进行第一个写，避免已知陈旧请求产生部分修改。
    for (index = 0UL;
        index < RTL_NUMBER_OF(g_KswordArkDriverImageFields);
        ++index) {
        ULONG field = g_KswordArkDriverImageFields[index];

        if ((FieldMask & field) != 0UL &&
            KswordARKDriverImageGetValue(&currentValues, field) !=
                KswordARKDriverImageGetValue(ExpectedValues, field)) {
            return STATUS_RETRY;
        }
    }

    // 中文说明：每个字段第一次进入事务时单独冻结原值，后续编辑不改变恢复基准。
    for (index = 0UL;
        index < RTL_NUMBER_OF(g_KswordArkDriverImageFields);
        ++index) {
        ULONG field = g_KswordArkDriverImageFields[index];

        if ((FieldMask & field) != 0UL &&
            (Record->OriginalFieldMask & field) == 0UL) {
            KswordARKDriverImageSetValue(
                &Record->OriginalValues,
                field,
                KswordARKDriverImageGetValue(ExpectedValues, field));
            Record->OriginalFieldMask |= field;
        }
    }

    // 中文说明：即使 desired 等于 expected 也执行同值 CAS，建立同一时刻的所有权证据。
    for (index = 0UL;
        index < RTL_NUMBER_OF(g_KswordArkDriverImageFields);
        ++index) {
        ULONG field = g_KswordArkDriverImageFields[index];
        ULONGLONG expected = 0ULL;
        ULONGLONG desired = 0ULL;
        ULONGLONG observed = 0ULL;

        if ((FieldMask & field) == 0UL) {
            continue;
        }
        expected = KswordARKDriverImageGetValue(ExpectedValues, field);
        desired = KswordARKDriverImageGetValue(DesiredValues, field);
        status = KswordARKDriverImageCompareExchangeField(
            Runtime,
            Record,
            field,
            desired,
            expected,
            &observed);
        if (!NT_SUCCESS(status) || observed != expected) {
            if (NT_SUCCESS(status)) {
                status = STATUS_RETRY;
            }
            break;
        }
        appliedMask |= field;
        if (desired != expected) {
            *ChangedFieldMask |= field;
        }
    }

    if (!NT_SUCCESS(status)) {
        // 中文说明：反向回滚只在当前值仍等于本轮 desired 时写回 expected，绝不覆盖竞争者。
        while (index > 0UL) {
            ULONG rollbackField = 0UL;
            ULONGLONG expected = 0ULL;
            ULONGLONG desired = 0ULL;
            ULONGLONG observed = 0ULL;
            NTSTATUS rollbackStatus = STATUS_SUCCESS;

            --index;
            rollbackField = g_KswordArkDriverImageFields[index];
            if ((appliedMask & rollbackField) == 0UL) {
                continue;
            }
            expected = KswordARKDriverImageGetValue(
                ExpectedValues,
                rollbackField);
            desired = KswordARKDriverImageGetValue(
                DesiredValues,
                rollbackField);
            rollbackStatus = KswordARKDriverImageCompareExchangeField(
                Runtime,
                Record,
                rollbackField,
                expected,
                desired,
                &observed);
            if (!NT_SUCCESS(rollbackStatus) || observed != desired) {
                *RollbackConflictMask |= rollbackField;
                Record->ManagedFieldMask |= rollbackField;
                Record->OwnedFieldMask &= ~rollbackField;
                Record->ConflictFieldMask |= rollbackField;
                KswordARKDriverImageSetValue(
                    &Record->AppliedValues,
                    rollbackField,
                    desired);
            }
        }
        // 中文说明：成功回滚的字段没有净变化；冲突位单独报告可能遗留的本轮写入。
        *ChangedFieldMask &= *RollbackConflictMask;
        return status;
    }

    // 中文说明：全部 CAS 成功后一次性发布事务元数据，恢复到 original 的字段随即退出管理。
    for (index = 0UL;
        index < RTL_NUMBER_OF(g_KswordArkDriverImageFields);
        ++index) {
        ULONG field = g_KswordArkDriverImageFields[index];
        ULONGLONG desired = 0ULL;
        ULONGLONG original = 0ULL;

        if ((FieldMask & field) == 0UL) {
            continue;
        }
        desired = KswordARKDriverImageGetValue(DesiredValues, field);
        original = KswordARKDriverImageGetValue(
            &Record->OriginalValues,
            field);
        KswordARKDriverImageSetValue(
            &Record->AppliedValues,
            field,
            desired);
        if (desired == original) {
            Record->ManagedFieldMask &= ~field;
            Record->OwnedFieldMask &= ~field;
            Record->ConflictFieldMask &= ~field;
        }
        else {
            Record->ManagedFieldMask |= field;
            Record->OwnedFieldMask |= field;
            Record->ConflictFieldMask &= ~field;
        }
    }
    return STATUS_SUCCESS;
}

// 中文说明：恢复可以部分成功；零掩码表示只恢复链，不会隐式扩大到全部字段。
// 每个失败字段保留记录与冲突信息，便于后续查询或放弃。
NTSTATUS
KswordARKDriverImageRestoreFieldsLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _In_ ULONG FieldMask,
    _Out_ ULONG* ChangedFieldMask,
    _Out_ ULONG* FailedFieldMask
    )
{
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG availableMask = 0UL;
    ULONG selectedMask = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Record == NULL || ChangedFieldMask == NULL ||
        FailedFieldMask == NULL ||
        (FieldMask & ~KSWORD_ARK_DRIVER_IMAGE_FIELD_ALL) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&currentValues, sizeof(currentValues));
    *ChangedFieldMask = 0UL;
    *FailedFieldMask = 0UL;
    selectedMask = FieldMask & Record->ManagedFieldMask;
    if (selectedMask == 0UL) {
        return STATUS_SUCCESS;
    }

    status = KswordARKDriverImageReadValuesLocked(
        Runtime,
        Record,
        &currentValues,
        &availableMask);
    if (!NT_SUCCESS(status)) {
        *FailedFieldMask = selectedMask;
        return status;
    }

    for (index = 0UL;
        index < RTL_NUMBER_OF(g_KswordArkDriverImageFields);
        ++index) {
        ULONG field = g_KswordArkDriverImageFields[index];
        ULONGLONG current = 0ULL;
        ULONGLONG original = 0ULL;
        ULONGLONG applied = 0ULL;

        if ((selectedMask & field) == 0UL) {
            continue;
        }
        if ((availableMask & field) == 0UL) {
            // 中文说明：布局暂时不可用时保留 owned，不把“未知”误判成第三方竞争。
            *FailedFieldMask |= field;
            continue;
        }
        if ((Record->OriginalFieldMask & field) == 0UL) {
            Record->OwnedFieldMask &= ~field;
            Record->ConflictFieldMask |= field;
            *FailedFieldMask |= field;
            continue;
        }

        current = KswordARKDriverImageGetValue(&currentValues, field);
        original = KswordARKDriverImageGetValue(
            &Record->OriginalValues,
            field);
        applied = KswordARKDriverImageGetValue(
            &Record->AppliedValues,
            field);
        if (current == original) {
            // 中文说明：外部已恢复到原值时直接退役该字段，不再进行冗余写入。
            Record->ManagedFieldMask &= ~field;
            Record->OwnedFieldMask &= ~field;
            Record->ConflictFieldMask &= ~field;
            continue;
        }
        if ((Record->OwnedFieldMask & field) != 0UL &&
            current == applied) {
            ULONGLONG observed = 0ULL;
            NTSTATUS restoreStatus =
                KswordARKDriverImageCompareExchangeField(
                    Runtime,
                    Record,
                    field,
                    original,
                    applied,
                    &observed);

            if (NT_SUCCESS(restoreStatus) && observed == applied) {
                Record->ManagedFieldMask &= ~field;
                Record->OwnedFieldMask &= ~field;
                Record->ConflictFieldMask &= ~field;
                if (original != applied) {
                    *ChangedFieldMask |= field;
                }
                continue;
            }
        }

        // 中文说明：任意第三方当前值都保留原样，只把字段标成冲突供用户决定放弃。
        Record->OwnedFieldMask &= ~field;
        Record->ConflictFieldMask |= field;
        *FailedFieldMask |= field;
    }

    if (*FailedFieldMask != 0UL) {
        return (availableMask & *FailedFieldMask) == *FailedFieldMask
            ? STATUS_OBJECT_TYPE_MISMATCH
            : STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

// 中文说明：刷新所有已管理字段，生成保守的 owned/conflict 视图而不做任何写入。
NTSTATUS
KswordARKDriverImageRefreshFieldsLocked(
    _In_ const KSW_DRIVER_IMAGE_RUNTIME* Runtime,
    _Inout_ KSW_DRIVER_IMAGE_RECORD* Record,
    _Out_ BOOLEAN* StateChanged
    )
{
    KSWORD_ARK_DRIVER_IMAGE_VALUES currentValues;
    ULONG oldManagedMask = 0UL;
    ULONG oldOwnedMask = 0UL;
    ULONG oldConflictMask = 0UL;
    ULONG availableMask = 0UL;
    ULONG unavailableMask = 0UL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Record == NULL || StateChanged == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *StateChanged = FALSE;
    oldManagedMask = Record->ManagedFieldMask;
    oldOwnedMask = Record->OwnedFieldMask;
    oldConflictMask = Record->ConflictFieldMask;
    if (Record->ManagedFieldMask == 0UL) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&currentValues, sizeof(currentValues));
    status = KswordARKDriverImageReadValuesLocked(
        Runtime,
        Record,
        &currentValues,
        &availableMask);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (index = 0UL;
        index < RTL_NUMBER_OF(g_KswordArkDriverImageFields);
        ++index) {
        ULONG field = g_KswordArkDriverImageFields[index];
        ULONGLONG current = 0ULL;
        ULONGLONG original = 0ULL;
        ULONGLONG applied = 0ULL;

        if ((Record->ManagedFieldMask & field) == 0UL) {
            continue;
        }
        if ((availableMask & field) == 0UL) {
            unavailableMask |= field;
            continue;
        }
        if ((Record->OriginalFieldMask & field) == 0UL) {
            Record->OwnedFieldMask &= ~field;
            Record->ConflictFieldMask |= field;
            continue;
        }
        current = KswordARKDriverImageGetValue(&currentValues, field);
        original = KswordARKDriverImageGetValue(
            &Record->OriginalValues,
            field);
        applied = KswordARKDriverImageGetValue(
            &Record->AppliedValues,
            field);

        if (current == original) {
            Record->ManagedFieldMask &= ~field;
            Record->OwnedFieldMask &= ~field;
            Record->ConflictFieldMask &= ~field;
        }
        else if ((Record->OwnedFieldMask & field) != 0UL &&
            current == applied) {
            Record->ConflictFieldMask &= ~field;
        }
        else {
            Record->OwnedFieldMask &= ~field;
            Record->ConflictFieldMask |= field;
        }
    }

    *StateChanged =
        oldManagedMask != Record->ManagedFieldMask ||
        oldOwnedMask != Record->OwnedFieldMask ||
        oldConflictMask != Record->ConflictFieldMask;
    return unavailableMask != 0UL
        ? STATUS_NOT_SUPPORTED
        : STATUS_SUCCESS;
}
