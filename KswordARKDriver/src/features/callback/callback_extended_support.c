/*++

Module Name:

    callback_extended_support.c

Abstract:

    为扩展内核回调枚举器提供只读内存、RIP 相对地址和统一行构建帮助函数。

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_extended_internal.h"

PVOID
KswordArkCallbackExtendedGetSystemRoutine(
    _In_z_ PCWSTR RoutineName
    )
/*++

Routine Description:

    解析一个 ntoskrnl 导出例程。中文说明：所有私有链定位都从公开导出入口
    起步，避免在整个内核映像中无边界搜索。

Arguments:

    RoutineName - 以零结尾的导出名称。

Return Value:

    成功返回例程地址；参数无效或导出不存在返回 NULL。

--*/
{
    UNICODE_STRING routineName;

    if (RoutineName == NULL || RoutineName[0] == L'\0') {
        return NULL;
    }

    RtlInitUnicodeString(&routineName, RoutineName);
    return MmGetSystemRoutineAddress(&routineName);
}

BOOLEAN
KswordArkCallbackExtendedResolveRipRelative(
    _In_ ULONG64 InstructionAddress,
    _In_ ULONG DisplacementOffset,
    _In_ ULONG InstructionLength,
    _Out_ ULONG64* TargetAddressOut
    )
/*++

Routine Description:

    解析 x64 RIP-relative 指令目标。中文说明：位移读取使用统一异常保护，
    并检查正负位移计算，防止损坏代码字节产生整数回绕。

Arguments:

    InstructionAddress - 指令起始地址。
    DisplacementOffset - disp32 在指令中的偏移。
    InstructionLength - 指令总长度。
    TargetAddressOut - 输出解析后的虚拟地址。

Return Value:

    成功返回 TRUE；读取失败或算术无效返回 FALSE。

--*/
{
    LONG displacement = 0L;
    ULONG64 nextInstruction = 0ULL;

    if (TargetAddressOut == NULL ||
        InstructionAddress == 0ULL ||
        InstructionLength < (DisplacementOffset + sizeof(displacement))) {
        return FALSE;
    }

    *TargetAddressOut = 0ULL;
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)(InstructionAddress + DisplacementOffset),
            &displacement,
            sizeof(displacement))) {
        return FALSE;
    }

    nextInstruction = InstructionAddress + InstructionLength;
    if (displacement < 0) {
        const ULONG64 backwardBytes = (ULONG64)(-(LONG64)displacement);
        if (nextInstruction < backwardBytes) {
            return FALSE;
        }
        *TargetAddressOut = nextInstruction - backwardBytes;
    }
    else {
        *TargetAddressOut = nextInstruction + (ULONG64)displacement;
    }
    return *TargetAddressOut != 0ULL;
}

BOOLEAN
KswordArkCallbackExtendedReadPointer(
    _In_ ULONG64 Address,
    _Out_ ULONG64* ValueOut
    )
/*++

Routine Description:

    读取一个本机指针宽度的内核值。

Arguments:

    Address - 待读取地址。
    ValueOut - 输出 64 位指针值。

Return Value:

    成功返回 TRUE；参数或读取失败返回 FALSE。

--*/
{
    ULONG_PTR value = 0U;

    if (Address == 0ULL || ValueOut == NULL) {
        return FALSE;
    }

    *ValueOut = 0ULL;
    if (!KswordArkCallbackEnumReadMemory(
            (const VOID*)(ULONG_PTR)Address,
            &value,
            sizeof(value))) {
        return FALSE;
    }

    *ValueOut = (ULONG64)value;
    return TRUE;
}

BOOLEAN
KswordArkCallbackExtendedReadListEntry(
    _In_ ULONG64 Address,
    _Out_ LIST_ENTRY* EntryOut
    )
/*++

Routine Description:

    读取一个 LIST_ENTRY 快照。

Arguments:

    Address - LIST_ENTRY 地址。
    EntryOut - 输出链表指针快照。

Return Value:

    成功返回 TRUE；参数或读取失败返回 FALSE。

--*/
{
    if (Address == 0ULL || EntryOut == NULL) {
        return FALSE;
    }

    RtlZeroMemory(EntryOut, sizeof(*EntryOut));
    return KswordArkCallbackEnumReadMemory(
        (const VOID*)(ULONG_PTR)Address,
        EntryOut,
        sizeof(*EntryOut));
}

VOID
KswordArkCallbackExtendedAddRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_opt_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG CallbackClass,
    _In_ ULONG Source,
    _In_ ULONG Status,
    _In_ NTSTATUS LastStatus,
    _In_ ULONG RegistrationType,
    _In_ ULONG OperationMask,
    _In_ ULONG ObjectTypeMask,
    _In_ ULONG64 CallbackAddress,
    _In_ ULONG64 ContextAddress,
    _In_ ULONG64 RegistrationAddress,
    _In_ ULONG ExtraFieldFlags,
    _In_opt_z_ PCWSTR NameText,
    _In_opt_z_ PCWSTR DetailText
    )
/*++

Routine Description:

    写入一条扩展回调行。中文说明：该函数统一维护有效字段、来源可信度和
    模块归属，避免多个链表枚举器产生互相矛盾的 R3 语义。

Arguments:

    Builder - 响应构建器。
    ModuleCache - 可选模块缓存。
    CallbackClass - 回调类别。
    Source - 枚举来源。
    Status - 行状态。
    LastStatus - 底层 NTSTATUS。
    RegistrationType - 具体注册 API 类型。
    OperationMask - 可选操作掩码。
    ObjectTypeMask - 可选对象类型掩码。
    CallbackAddress - 回调函数地址。
    ContextAddress - 回调上下文或诊断值。
    RegistrationAddress - 注册记录、设备对象或链表节点。
    ExtraFieldFlags - 调用方补充的字段标志。
    NameText - 可选行名称。
    DetailText - 可选详情。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    if (Builder == NULL) {
        return;
    }

    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = CallbackClass;
    entry->source = Source;
    entry->status = Status;
    entry->lastStatus = LastStatus;
    entry->registrationType = RegistrationType;
    entry->operationMask = OperationMask;
    entry->objectTypeMask = ObjectTypeMask;
    entry->callbackAddress = CallbackAddress;
    entry->contextAddress = ContextAddress;
    entry->registrationAddress = RegistrationAddress;
    entry->fieldFlags = ExtraFieldFlags;

    if (CallbackAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS;
    }
    if (ContextAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS;
    }
    if (RegistrationAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
            KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    }
    if (RegistrationType != KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    if (OperationMask != 0UL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK;
    }
    if (ObjectTypeMask != 0UL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK;
    }
    if (NameText != NULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
        KswordArkCallbackEnumCopyWide(
            entry->name,
            RTL_NUMBER_OF(entry->name),
            NameText);
    }

    KswordArkCallbackEnumCopyWide(
        entry->detail,
        RTL_NUMBER_OF(entry->detail),
        DetailText);

    if (Source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD;
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API;
    }
    else if (Source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API ||
        Source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_DRIVER_OBJECT_SCAN ||
        Source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL) {
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API;
        if (Source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL &&
            Status == KSWORD_ARK_CALLBACK_ENUM_STATUS_OK &&
            RegistrationType == KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT &&
            (ExtraFieldFlags &
                KSWORD_ARK_CALLBACK_ENUM_FIELD_CLASS_INIT_DATA_VALIDATED) != 0UL) {
            entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_STRUCTURE_SIGNATURE;
        }
    }
    else {
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN;
    }

    if (ModuleCache != NULL && CallbackAddress != 0ULL) {
        KswordArkCallbackEnumFinalizeModuleCached(ModuleCache, entry);
    }
}
