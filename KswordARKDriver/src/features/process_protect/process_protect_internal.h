#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdf.h>

#include "ark/ark_process_protect.h"
#include "ark/ark_log.h"
#include "ark/ark_push_lock.h"

#define KSWORD_ARK_PROCESS_PROTECT_TAG_STATE 'pPbK'

// 驱动内共用的非分页分配器，定义在 src/features/callback/callback_runtime.c：
// 它会在可用时走 ExAllocatePool2，否则回退到 ExAllocatePoolWithTag。
PVOID
KswordArkAllocateNonPaged(
    _In_ SIZE_T bytes,
    _In_ ULONG poolTag
    );

// 运行时状态。规则表整块受 ConfigLock 保护：判定路径只做一次 ≤32 条的线性扫描，
// 共享持锁的代价远低于再引入一套快照 + rundown 生命周期。
typedef struct _KSWORD_ARK_PROCESS_PROTECT_STATE
{
    WDFDEVICE Device;

    EX_PUSH_LOCK ConfigLock;
    ULONG GlobalFlags;
    ULONG RuleCount;
    ULONG TrustedCount;
    ULONG64 ConfigVersion;
    LARGE_INTEGER AppliedAtUtc100ns;
    KSWORD_ARK_PROCESS_PROTECT_RULE Rules[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_TRUSTED Trusted[KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED];

    // 统计计数器用原子操作维护，不参与 ConfigLock，避免热路径升级为独占持锁。
    volatile LONG64 EvaluatedCount;
    volatile LONG64 StrippedCount;
    volatile LONG64 TrustedBypassCount;
    volatile LONG64 RuleHitCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];

    // 最近一次拦截快照。写入时持 LastBlockedLock 独占，读取时共享，
    // 保证 R3 看到的是一次完整的拦截记录而不是拼接结果。
    EX_PUSH_LOCK LastBlockedLock;
    LARGE_INTEGER LastBlockedUtc100ns;
    ULONG LastBlockedInitiatorPid;
    ULONG LastBlockedTargetPid;
    ULONG LastBlockedRuleId;
    ULONG LastBlockedOriginalAccess;
    ULONG LastBlockedGrantedAccess;
    ULONG LastBlockedIsThreadObject;
    WCHAR LastBlockedInitiatorImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];
    WCHAR LastBlockedTargetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];

    // 对象回调可用性由 object_callback.c 回填。
    volatile LONG ObjectCallbackRegistered;
    volatile LONG ObjectCallbackStatus;
} KSWORD_ARK_PROCESS_PROTECT_STATE;

KSWORD_ARK_PROCESS_PROTECT_STATE*
KswordArkProcessProtectGetState(
    VOID
    );
