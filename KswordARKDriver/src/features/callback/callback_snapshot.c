/*++

Module Name:

    callback_snapshot.c

Abstract:

    Builds stable callback-row identities and an ordered enumeration snapshot hash.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"

#define KSWORD_ARK_CALLBACK_FNV64_OFFSET 14695981039346656037ULL
#define KSWORD_ARK_CALLBACK_FNV64_PRIME 1099511628211ULL

static ULONG64
KswordArkCallbackEnumHashBytes(
    _In_ ULONG64 InitialHash,
    _In_reads_bytes_(ByteCount) const VOID* Bytes,
    _In_ SIZE_T ByteCount
    )
/*++

Routine Description:

    使用固定参数的 FNV-1a 64 算法增量计算字节序列哈希。该函数只处理已经
    读取到受控缓冲区中的数据，不直接解引用未经验证的内核地址。

Arguments:

    InitialHash - 上一段数据的哈希状态。
    Bytes - 本次参与哈希的字节序列。
    ByteCount - 字节序列长度。

Return Value:

    返回更新后的哈希值；空输入保持原值。

--*/
{
    // 把只读输入转换为逐字节视图，避免依赖结构体字段类型。
    const UCHAR* currentByte = (const UCHAR*)Bytes;
    // 从调用方传入的状态继续计算，以便组合多个稳定字段。
    ULONG64 hashValue = InitialHash;
    // 使用显式索引保证内核编译器不会引入未定义的指针步进。
    SIZE_T index = 0U;

    // 空输入不参与哈希，并且不得被解引用。
    if (Bytes == NULL) {
        return hashValue;
    }

    // 按协议中的原始字节顺序执行标准 FNV-1a 更新。
    for (index = 0U; index < ByteCount; ++index) {
        hashValue ^= (ULONG64)currentByte[index];
        hashValue *= KSWORD_ARK_CALLBACK_FNV64_PRIME;
    }

    // 返回可继续用于下一字段的增量状态。
    return hashValue;
}

static ULONG64
KswordArkCallbackEnumBuildIdentityHash(
    _In_ const KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entry
    )
/*++

Routine Description:

    从回调行的稳定语义字段生成身份哈希。分页位置、枚举代次和身份哈希自身
    不进入输入，因此同一注册项在不同页面中保持相同身份。

Arguments:

    Entry - 已完成填充并经过读取校验的回调枚举行。

Return Value:

    返回非零的稳定身份哈希；无效输入返回零。

--*/
{
    // 单独规范化 fieldFlags，排除由本函数及最终化阶段写入的派生标记。
    ULONG stableFieldFlags = 0UL;
    // 所有回调行使用相同的公开 FNV-1a 初始状态。
    ULONG64 hashValue = KSWORD_ARK_CALLBACK_FNV64_OFFSET;

    // 调用约定要求有效行，防御性检查避免异常路径解引用空指针。
    if (Entry == NULL) {
        return 0ULL;
    }

    // 派生哈希字段不能反向影响身份，否则重复枚举将无法稳定比较。
    stableFieldFlags = Entry->fieldFlags &
        ~(KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH |
          KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION);
    // 该局部宏统一字段地址和字段宽度，避免不同调用点发生长度漂移。
#define KSWORD_ARK_CALLBACK_HASH_FIELD(FieldName) \
    hashValue = KswordArkCallbackEnumHashBytes( \
        hashValue, \
        &Entry->FieldName, \
        sizeof(Entry->FieldName))

    // 基础分类、来源和查询状态决定一行的语义身份。
    KSWORD_ARK_CALLBACK_HASH_FIELD(callbackClass);
    KSWORD_ARK_CALLBACK_HASH_FIELD(source);
    KSWORD_ARK_CALLBACK_HASH_FIELD(status);
    // 使用剔除派生位后的字段标志，保留其他数据有效性差异。
    hashValue = KswordArkCallbackEnumHashBytes(
        hashValue,
        &stableFieldFlags,
        sizeof(stableFieldFlags));
    // 操作、对象和底层状态字段参与身份区分。
    KSWORD_ARK_CALLBACK_HASH_FIELD(operationMask);
    KSWORD_ARK_CALLBACK_HASH_FIELD(objectTypeMask);
    KSWORD_ARK_CALLBACK_HASH_FIELD(lastStatus);
    // 地址、上下文和原始存储值用于区分并列注册项。
    KSWORD_ARK_CALLBACK_HASH_FIELD(callbackAddress);
    KSWORD_ARK_CALLBACK_HASH_FIELD(contextAddress);
    KSWORD_ARK_CALLBACK_HASH_FIELD(registrationAddress);
    KSWORD_ARK_CALLBACK_HASH_FIELD(rawStorageValue);
    // 信任、移除策略及模块归属决定该行的安全语义。
    KSWORD_ARK_CALLBACK_HASH_FIELD(trustFlags);
    KSWORD_ARK_CALLBACK_HASH_FIELD(removeBehavior);
    KSWORD_ARK_CALLBACK_HASH_FIELD(moduleBase);
    KSWORD_ARK_CALLBACK_HASH_FIELD(moduleSize);
    KSWORD_ARK_CALLBACK_HASH_FIELD(ownerRangeState);
    KSWORD_ARK_CALLBACK_HASH_FIELD(registrationType);
    // 名称和高度可区分同一地址下具有不同注册元数据的条目。
    KSWORD_ARK_CALLBACK_HASH_FIELD(name);
    KSWORD_ARK_CALLBACK_HASH_FIELD(altitude);

    // 宏只在本函数内有效，防止污染后续驱动源码。
#undef KSWORD_ARK_CALLBACK_HASH_FIELD

    // 协议以零表示“未提供”，因此把理论上的零哈希映射到一。
    return (hashValue != 0ULL) ? hashValue : 1ULL;
}

VOID
KswordArkCallbackEnumSnapshotBegin(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    初始化一次完整回调枚举的快照聚合状态。

Arguments:

    Builder - 当前 IOCTL 请求使用的枚举构建器。

Return Value:

    无返回值。

--*/
{
    // 无构建器时不能写入任何快照状态。
    if (Builder == NULL) {
        return;
    }

    // 行数从零开始，并使用协议固定的 FNV-1a 初始值。
    Builder->SnapshotRowCount = 0UL;
    Builder->SnapshotHash = KSWORD_ARK_CALLBACK_FNV64_OFFSET;
    // 当前尚无等待提交的分页行。
    Builder->PendingEntry = NULL;
}

VOID
KswordArkCallbackEnumSnapshotCommitPending(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    在枚举器完成一行字段填充后提交该行：生成身份哈希，并按全局行序把身份
    合并到完整快照哈希。仅当前分页实际返回的行会写回身份字段，但全部逻辑行
    都会参与快照聚合。

Arguments:

    Builder - 当前 IOCTL 请求使用的枚举构建器。

Return Value:

    无返回值。

--*/
{
    // 保存当前待提交行，提交完成后立即清空。
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;
    // 身份哈希使用非零值表示已经计算。
    ULONG64 identityHash = 0ULL;
    // 全局行序参与快照哈希，防止相同行集合被不同顺序误判为同一快照。
    ULONG rowIndex = 0UL;

    // 没有待提交行时保持构建器状态不变。
    if (Builder == NULL || Builder->PendingEntry == NULL) {
        return;
    }

    // 枚举器已经完成该行所有稳定字段的填充。
    entry = Builder->PendingEntry;
    // 先计算身份，再写入协议行及快照聚合器。
    identityHash = KswordArkCallbackEnumBuildIdentityHash(entry);
    entry->identityHash = identityHash;
    entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH;

    // 使用提交前的行数作为零基全局行序。
    rowIndex = Builder->SnapshotRowCount;
    // 先混入行序，再混入身份，明确区分重复行和重排行。
    Builder->SnapshotHash = KswordArkCallbackEnumHashBytes(
        Builder->SnapshotHash,
        &rowIndex,
        sizeof(rowIndex));
    Builder->SnapshotHash = KswordArkCallbackEnumHashBytes(
        Builder->SnapshotHash,
        &identityHash,
        sizeof(identityHash));
    // 行已完整进入快照，推进总行数并释放待提交槽。
    Builder->SnapshotRowCount += 1UL;
    Builder->PendingEntry = NULL;
}

VOID
KswordArkCallbackEnumSnapshotFinalize(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    提交最后一行、封闭完整快照哈希，并把统一的枚举代次写入当前页面的所有
    返回行。

Arguments:

    Builder - 当前 IOCTL 请求使用的枚举构建器。

Return Value:

    无返回值。

--*/
{
    // 遍历当前页面的返回行以发布统一代次。
    ULONG entryIndex = 0UL;

    // 无构建器时没有需要最终化的快照。
    if (Builder == NULL) {
        return;
    }

    // ReserveEntry 只会在下一次预留时提交上一行，因此此处必须提交尾行。
    KswordArkCallbackEnumSnapshotCommitPending(Builder);
    // 把最终总行数并入哈希，区分具有相同前缀但长度不同的快照。
    Builder->SnapshotHash = KswordArkCallbackEnumHashBytes(
        Builder->SnapshotHash,
        &Builder->SnapshotRowCount,
        sizeof(Builder->SnapshotRowCount));
    // 零值在共享协议中保留为“哈希无效”，因此规范化为一。
    if (Builder->SnapshotHash == 0ULL) {
        Builder->SnapshotHash = 1ULL;
    }

    // 当前页面的每一行都携带相同代次，便于 R3 检测跨页混合。
    for (entryIndex = 0UL; entryIndex < Builder->ReturnedCount; ++entryIndex) {
        Builder->Entries[entryIndex].enumerationGeneration = Builder->SnapshotHash;
        Builder->Entries[entryIndex].fieldFlags |=
            KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION |
            KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH;
    }

    // 只有全部快照计算完成后才向 R3 声明哈希字段有效。
    Builder->Flags |=
        KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_HASH_VALID |
        KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_IDENTITY_HASH_VALID;
}
