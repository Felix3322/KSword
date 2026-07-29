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

#if defined(_M_AMD64)

// Windows AMD64 当前 NMI 私有节点布局；每次读取后仍需验证自句柄与 next 指针。
typedef struct _KSWORD_ARK_CALLBACK_NMI_REGISTRATION
{
    ULONG64 Next;
    ULONG64 CallbackRoutine;
    ULONG64 CallbackContext;
    ULONG64 Handle;
} KSWORD_ARK_CALLBACK_NMI_REGISTRATION;

static NTSTATUS
KswordArkCallbackExtendedLocateNmiList(
    _Out_ ULONG64* HeadStorageAddressOut,
    _Out_ ULONG64* LockAddressOut,
    _Out_ ULONG64* FirstNodeAddressOut
    )
/*++

Routine Description:

    在 KeRegisterNmiCallback 的有限代码窗口内定位 NMI 私有链表头存储和配套
    自旋锁。定位同时要求出现对同一链头的读取与回写，并验证首节点布局，从而
    避免把普通 RIP 相对全局量误识别为链表。

Arguments:

    HeadStorageAddressOut - 接收保存首节点指针的内核全局地址。
    LockAddressOut - 接收与链表相邻的锁地址，仅作为诊断元数据返回。
    FirstNodeAddressOut - 接收定位时读取到的首节点地址。

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

    // 三个结果均为必需，避免返回部分定位信息。
    if (HeadStorageAddressOut == NULL ||
        LockAddressOut == NULL ||
        FirstNodeAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 失败路径统一保持输出为零，调用方不会误用旧值。
    *HeadStorageAddressOut = 0ULL;
    *LockAddressOut = 0ULL;
    *FirstNodeAddressOut = 0ULL;
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
        ULONG64 firstNodeAddress = 0ULL;
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
        // 链头存储地址也必须能被安全读取。
        if (!KswordArkCallbackExtendedReadPointer(
                headStorageAddress,
                &firstNodeAddress)) {
            continue;
        }
        // 非空链表在发布地址前必须通过首节点布局验证。
        if (firstNodeAddress != 0ULL) {
            // 首节点仅存在于已验证的本地副本中。
            KSWORD_ARK_CALLBACK_NMI_REGISTRATION firstNode;

            // 清零后再读取，避免在异常路径使用栈残留。
            RtlZeroMemory(&firstNode, sizeof(firstNode));
            // 回调必须非零，公开句柄必须等于节点自身。
            if (!KswordArkCallbackEnumReadMemory(
                    (const VOID*)(ULONG_PTR)firstNodeAddress,
                    &firstNode,
                    sizeof(firstNode)) ||
                firstNode.CallbackRoutine == 0ULL ||
                firstNode.Handle != firstNodeAddress) {
                continue;
            }
        }

        // 所有代码形态和首节点检查都通过后一次性发布结果。
        *HeadStorageAddressOut = headStorageAddress;
        *LockAddressOut = lockAddress;
        *FirstNodeAddressOut = firstNodeAddress;
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
    _In_ ULONG64 LockAddress,
    _In_ ULONG64 FirstNodeAddress
    )
/*++

Routine Description:

    从已定位的首节点开始安全遍历 NMI 私有单链表，并把每个通过布局验证的
    注册项转换为统一回调枚举行。遇到损坏节点或超过上限时输出诊断行并停止。

Arguments:

    Builder - 当前 IOCTL 的枚举构建器。
    ModuleCache - 本次 NMI 枚举使用的模块归属缓存。
    HeadStorageAddress - 保存首节点指针的全局地址。
    LockAddress - 与私有链表配套的锁地址。
    FirstNodeAddress - 定位阶段读取并验证过的首节点地址。

Return Value:

    无返回值。

--*/
{
    // index 同时用于安全上限和用户可见的稳定序号。
    ULONG index = 0UL;
    // currentAddress 始终指向下一待验证节点。
    ULONG64 currentAddress = FirstNodeAddress;

    // 空链表不是错误，返回一行明确的未注册状态。
    if (currentAddress == 0ULL) {
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
            L"NMI 注册链已定位，但当前没有可见注册项。");
        return;
    }

    // 双重条件同时防止空终止链和损坏循环导致无限遍历。
    while (currentAddress != 0ULL && index < KSWORD_ARK_CALLBACK_NMI_WALK_LIMIT) {
        // 每个私有节点先复制到栈上，再仅使用本地副本。
        KSWORD_ARK_CALLBACK_NMI_REGISTRATION registration;
        // 名称和详情写入固定大小的协议字段。
        WCHAR nameText[KSWORD_ARK_CALLBACK_ENUM_NAME_CHARS];
        WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

        // 所有输出缓冲与节点副本在读取前清零。
        RtlZeroMemory(&registration, sizeof(registration));
        RtlZeroMemory(nameText, sizeof(nameText));
        RtlZeroMemory(detailText, sizeof(detailText));
        // 验证读取、回调地址、自句柄、非自环和 next 指针对齐。
        if (!KswordArkCallbackEnumReadMemory(
                (const VOID*)(ULONG_PTR)currentAddress,
                &registration,
                sizeof(registration)) ||
            registration.CallbackRoutine == 0ULL ||
            registration.Handle != currentAddress ||
            registration.Next == currentAddress ||
            !KswordArkCallbackEnumIsKernelModuleAddress(
                ModuleCache,
                registration.CallbackRoutine) ||
            (registration.Next != 0ULL &&
             (registration.Next & ((ULONG64)sizeof(PVOID) - 1ULL)) != 0ULL)) {
            KswordArkCallbackExtendedAddRow(
                Builder,
                ModuleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
                KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
                KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
                STATUS_DATA_ERROR,
                KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
                0UL,
                0UL,
                0ULL,
                LockAddress,
                currentAddress,
                0UL,
                L"KeRegisterNmiCallback node validation failed",
                L"NMI 私有链节点未通过布局、句柄、回调模块归属或 next 指针重验证，已停止遍历。");
            return;
        }

        // 生成不依赖模块解析结果的可读注册项名称。
        (VOID)RtlStringCbPrintfW(
            nameText,
            sizeof(nameText),
            L"KeRegisterNmiCallback[%lu]",
            (unsigned long)index);
        // 记录定位和节点元数据，方便诊断 Windows 版本布局漂移。
        (VOID)RtlStringCbPrintfW(
            detailText,
            sizeof(detailText),
            L"NMI callback；headStorage=0x%p，lock=0x%p，node=0x%p，handle=0x%p，next=0x%p。",
            (PVOID)(ULONG_PTR)HeadStorageAddress,
            (PVOID)(ULONG_PTR)LockAddress,
            (PVOID)(ULONG_PTR)currentAddress,
            (PVOID)(ULONG_PTR)registration.Handle,
            (PVOID)(ULONG_PTR)registration.Next);
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
            registration.CallbackRoutine,
            registration.CallbackContext,
            currentAddress,
            0UL,
            nameText,
            detailText);

        // 仅使用已经验证过的本地 next 值推进遍历。
        currentAddress = registration.Next;
        ++index;
    }

    // 非空尾地址表示到达安全上限，而不是正常链尾。
    if (currentAddress != 0ULL) {
        KswordArkCallbackExtendedAddRow(
            Builder,
            ModuleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI,
            KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST,
            KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED,
            STATUS_BUFFER_OVERFLOW,
            KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI,
            0UL,
            0UL,
            0ULL,
            LockAddress,
            currentAddress,
            0UL,
            L"KeRegisterNmiCallback walk limit reached",
            L"NMI 私有链超过安全遍历上限，已停止以避免损坏链导致无限循环。");
    }
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
    ULONG64 firstNodeAddress = 0ULL;

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
        &lockAddress,
        &firstNodeAddress);
    // 仅定位成功时允许解引用并遍历私有节点。
    if (NT_SUCCESS(status)) {
        KswordArkCallbackExtendedWalkNmiList(
            Builder,
            &moduleCache,
            headStorageAddress,
            lockAddress,
            firstNodeAddress);
    }
    else
#else
    // 非 AMD64 构建中显式标记占位变量，保持 /W4 /WX 无警告。
    UNREFERENCED_PARAMETER(headStorageAddress);
    UNREFERENCED_PARAMETER(lockAddress);
    UNREFERENCED_PARAMETER(firstNodeAddress);
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
