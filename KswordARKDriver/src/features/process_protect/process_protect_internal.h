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

// 同样定义在 callback_runtime.c：解析进程映像路径，优先 SeLocateProcessImageName，
// 失败时回退到短名。自愈巡检用它给"最近一次篡改"补上目标映像。
BOOLEAN
KswordArkResolveProcessImagePath(
    _In_opt_ PEPROCESS processObject,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars,
    _Out_opt_ BOOLEAN* pathUnavailableOut
    );

// 受保护进程台账的一项。
// 巡检不长期持有 EPROCESS 引用（那会推迟对象释放），改为每轮用 PID 重新查找，
// 再用创建时间核对身份——PID 会复用，只比 PID 会把保护错打到新进程头上。
typedef struct _KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY
{
    ULONG ProcessId;
    ULONG RuleId;
    ULONG RuleIndex;
    UCHAR ExpectedProtection;
    UCHAR Reserved[3];
    ULONG HardenFlags;
    LONGLONG CreateTimeQuadPart;
} KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY;

// 运行时状态。规则表整块受 ConfigLock 保护：判定路径只做一次 ≤32 条的线性扫描，
// 共享持锁的代价远低于再引入一套快照 + rundown 生命周期。
typedef struct _KSWORD_ARK_PROCESS_PROTECT_STATE
{
    WDFDEVICE Device;

    EX_PUSH_LOCK ConfigLock;
    ULONG GlobalFlags;
    ULONG RuleCount;
    ULONG TrustedCount;
    ULONG ScanIntervalMs;
    ULONG64 ConfigVersion;
    LARGE_INTEGER AppliedAtUtc100ns;
    KSWORD_ARK_PROCESS_PROTECT_RULE Rules[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_TRUSTED Trusted[KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED];

    // 统计计数器用原子操作维护，不参与 ConfigLock，避免热路径升级为独占持锁。
    volatile LONG64 EvaluatedCount;
    volatile LONG64 StrippedCount;
    volatile LONG64 TrustedBypassCount;
    volatile LONG64 RuleHitCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];

    // ---- 内核 PP 层 ----
    EX_PUSH_LOCK TrackedLock;
    ULONG TrackedCount;
    KSWORD_ARK_PROCESS_PROTECT_TRACKED_ENTRY Tracked[KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED];

    volatile LONG64 KernelApplyCount;
    volatile LONG64 SelfHealCount;
    volatile LONG64 KernelApplyFailureCount;
    volatile LONG64 HardenApplyCount;
    volatile LONG64 RuleKernelApplyCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    volatile LONG LastKernelApplyStatus;

    EX_PUSH_LOCK LastTamperLock;
    LARGE_INTEGER LastTamperUtc100ns;
    ULONG LastTamperProcessId;
    ULONG LastTamperObservedProtection;
    ULONG LastTamperExpectedProtection;
    ULONG LastTamperRuleId;
    WCHAR LastTamperImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];

    // 巡检线程。Stopping 置位后线程排空退出，卸载路径等待它结束再释放状态。
    PKTHREAD ScanThread;
    KEVENT ScanWakeEvent;
    volatile LONG ScanStopping;

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

VOID
KswordArkProcessProtectLogFormat(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State,
    _In_z_ PCSTR LevelText,
    _In_z_ _Printf_format_string_ PCSTR FormatText,
    ...
    );

VOID
KswordArkProcessProtectCopyFixedWideText(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ PCWSTR Source
    );

// 复用句柄回调层的目标匹配：内核 PP 层必须与削权层用同一套匹配语义，
// 否则同一条规则会出现"句柄命中但没打 PP"这种自相矛盾的状态。
BOOLEAN
KswordArkProcessProtectIdentityMatchPublic(
    _In_ ULONG TargetKind,
    _In_ ULONG ConfiguredProcessId,
    _In_opt_z_ PCWSTR ConfiguredImage,
    _In_ ULONG CandidateProcessId,
    _In_opt_z_ PCWSTR CandidateImagePath
    );

// ---- 内核 PP 层（process_protect_kernel.c） ----

NTSTATUS
KswordArkProcessProtectKernelStart(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State
    );

VOID
KswordArkProcessProtectKernelStop(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State
    );

// 配置换表后调用：作废旧台账，避免继续按已删除的规则维持保护。
VOID
KswordArkProcessProtectKernelResetTracking(
    _In_ KSWORD_ARK_PROCESS_PROTECT_STATE* State
    );

// 对一个进程执行一次"匹配规则 → 施加内核保护 → 登记台账"。
// ImagePath 允许为空；为空时只有 PID 类规则可能命中。
VOID
KswordArkProcessProtectKernelApplyToProcess(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONG ProcessId,
    _In_opt_z_ PCWSTR ImagePath
    );

// 进程退出时把它移出自愈台账，避免死 PID 占满表。
VOID
KswordArkProcessProtectKernelUntrackProcess(
    _In_ ULONG ProcessId
    );
