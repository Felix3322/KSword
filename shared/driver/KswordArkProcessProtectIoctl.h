#pragma once

#include "KswordArkProcessIoctl.h"

// ============================================================
// KswordArkProcessProtectIoctl.h
// 作用：
// - 定义"基于对象管理器句柄回调的进程保护"唯一 R3/R0 协议；
// - 保护判定挂在已注册的 ObRegisterCallbacks 前置回调上，命中后只做"削权"
//   （从 DesiredAccess 中去掉危险位），不返回失败，因此发起方拿到的是一个
//   权限受限的句柄，而不是一次 OpenProcess 失败；
// - 与 KswordArkCallbackIoctl.h 的通用回调规则并行：保护判定先于通用规则执行，
//   两者削掉的权限位取并集。
// 说明：
// - 本协议只描述"保护谁、削哪些权限、谁可豁免"，不提供任何注入或提权能力；
// - 配置为一次性全量替换，不做增量下发，避免 R3/R0 两侧规则表漂移。
// ============================================================

// v2 在 v1 的句柄回调削权之上叠加"内核 PP 层"：同一张规则表既驱动 Ob 回调，
// 也负责把目标进程打成 PP/PPL 并持续维持。规则结构体因此变长，无法靠 size 字段
// 与 v1 共存（rules[] 是内嵌定长数组，元素步长变了），所以直接抬版本号，
// R0 会拒绝 v1 请求并在日志里给出版本不匹配。
#define KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION 2UL

#define KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_PROTECT_CONFIG   0x90CUL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_PROTECT_STATE  0x90DUL

#define IOCTL_KSWORD_ARK_SET_PROCESS_PROTECT_CONFIG \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_PROTECT_CONFIG, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_PROTECT_STATE, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

// ------------------------------------------------------------
// 容量上限
// ------------------------------------------------------------
// 请求与响应都是定长 METHOD_BUFFERED 包，容量直接决定内核非分页缓冲区大小，
// 因此保持在数十 KB 量级。
#define KSWORD_ARK_PROCESS_PROTECT_MAX_RULES 32UL
#define KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED 32UL
#define KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS 260U
#define KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS 64U

// ------------------------------------------------------------
// 目标匹配方式
// ------------------------------------------------------------
// PID       ：只匹配一个具体进程，进程退出后该规则自然失效。
// IMAGE_NAME：匹配映像文件名（不含目录），忽略大小写，例如 notepad.exe。
// IMAGE_PATH：匹配映像完整路径。R0 拿到的是 NT 路径
//             （\Device\HarddiskVolume3\Windows\notepad.exe），而 R3 通常持有
//             Win32 路径（C:\Windows\notepad.exe），因此判定采用"去掉盘符后的
//             大小写无关后缀匹配"，两种写法都能命中。
#define KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_NONE 0UL
#define KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID 1UL
#define KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME 2UL
#define KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH 3UL

// ------------------------------------------------------------
// 保护位：命中规则后要从 DesiredAccess 中削掉的能力
// ------------------------------------------------------------
// 每一位同时决定进程句柄和线程句柄上要削掉哪些访问位；线程侧只有在规则打开
// PROTECT_THREADS 时才参与判定。
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ 0x00000002UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE 0x00000004UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD 0x00000008UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME 0x00000010UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION 0x00000020UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_DUP_HANDLE 0x00000040UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_ALL \
    (KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_DUP_HANDLE)

// 默认档：拦掉结束进程、写内存、远程建线程和挂起，保留只读观察能力。
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_DEFAULT \
    (KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME)

// ------------------------------------------------------------
// 内核加固位（第二层：让 Windows 内核自己执行保护）
// ------------------------------------------------------------
// 第一层是 Ob 句柄回调削权，由本驱动执行；第二层把目标进程打成 PP/PPL，交给
// 内核在所有句柄路径上强制执行，绕过本驱动回调也依然生效。
//
// CLEAR_DEBUG_PORT：把 EPROCESS.DebugPort 清零，让已附加的用户态调试器失去
//     调试对象、后续附加也拿不到端口。只写整个指针字段，不涉及位域。
//
// 说明：故意没有提供 BreakOnTermination（Critical Process）与 MitigationFlags
// 相关的加固位。那两处是 EPROCESS 里的位域，DynData 只提供字段偏移、不提供位
// 偏移，而位序在不同 Windows 版本之间会变——硬编码位号等于在某些版本上写错位。
#define KSWORD_ARK_PROCESS_PROTECT_HARDEN_NONE 0x00000000UL
#define KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_HARDEN_ALL \
    (KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT)

// ------------------------------------------------------------
// 规则标志
// ------------------------------------------------------------
// ENABLED        ：未置位的规则会被 R0 跳过，但仍占用一个槽位，便于 R3 保留草稿。
// PROTECT_THREADS：同时保护该进程内的线程句柄（THREAD_TERMINATE / SET_CONTEXT 等）。
// APPLY_ON_CREATE：进程创建回调里就把内核保护打上，解决"目标进程重启后保护丢失"。
// SELF_HEAL      ：巡检发现 Protection 字节被外部改回时自动恢复，并记一次篡改。
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_PROTECT_THREADS 0x00000002UL
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_APPLY_ON_CREATE 0x00000004UL
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL 0x00000008UL

// ------------------------------------------------------------
// 信任项标志
// ------------------------------------------------------------
#define KSWORD_ARK_PROCESS_PROTECT_TRUSTED_FLAG_ENABLED 0x00000001UL

// ------------------------------------------------------------
// 全局标志
// ------------------------------------------------------------
// ENABLED           ：总开关。关闭后 R0 保留规则表但不做任何削权。
// LOG_BLOCKED       ：每次实际削权向 R3 日志通道写一条 Warn 记录。
// TRUST_SYSTEM      ：System(4) / Idle(0) 发起的句柄操作直接放行。关闭它会让
//                     进程创建、退出清理等系统路径也被削权，风险很高，默认开启。
// TRUST_PROTECTED_PEERS：受保护进程之间互相打开句柄不削权。
// KERNEL_PROTECTION：内核 PP 层总开关。关闭后规则表保留，但不再施加也不再巡检。
// SELF_HEAL_SCAN   ：启用周期性巡检线程；不开则只在进程创建时施加一次。
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_LOG_BLOCKED 0x00000002UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM 0x00000004UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS 0x00000008UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION 0x00000010UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_SELF_HEAL_SCAN 0x00000020UL

// 巡检周期。太密会在大量受保护进程时浪费 CPU，太稀会拉长篡改窗口。
#define KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MIN_MS 1000UL
#define KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MAX_MS 300000UL
#define KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS 3000UL

// 受保护进程台账容量。达到上限后新进程不再纳入巡检，但创建时的施加照常执行。
#define KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED 256UL

// ------------------------------------------------------------
// 能力状态：R3 用它区分"没配规则"和"这台机器上根本挂不上句柄回调"
// ------------------------------------------------------------
#define KSWORD_ARK_PROCESS_PROTECT_STATUS_UNKNOWN 0UL
#define KSWORD_ARK_PROCESS_PROTECT_STATUS_ACTIVE 1UL
#define KSWORD_ARK_PROCESS_PROTECT_STATUS_CALLBACK_UNAVAILABLE 2UL

typedef struct _KSWORD_ARK_PROCESS_PROTECT_RULE
{
    unsigned long ruleId;
    unsigned long flags;
    unsigned long targetKind;
    // targetKind 为 PID 时生效；其余匹配方式下必须为 0。
    unsigned long targetProcessId;
    unsigned long protectAccessMask;
    // v2：目标 PS_PROTECTION 字节（KSWORD_PS_PROTECTION_MAKE 组装）。
    // 0 表示这条规则只做句柄回调削权，不施加内核 PP/PPL。
    unsigned long kernelProtection;
    // v2：KSWORD_ARK_PROCESS_PROTECT_HARDEN_* 组合。
    unsigned long hardenFlags;
    unsigned long reserved;
    wchar_t targetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];
    wchar_t ruleName[KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS];
} KSWORD_ARK_PROCESS_PROTECT_RULE;

typedef struct _KSWORD_ARK_PROCESS_PROTECT_TRUSTED
{
    unsigned long flags;
    unsigned long kind;
    unsigned long processId;
    unsigned long reserved;
    wchar_t image[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];
} KSWORD_ARK_PROCESS_PROTECT_TRUSTED;

typedef struct _KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long globalFlags;
    unsigned long ruleCount;
    unsigned long trustedCount;
    // v2：巡检周期毫秒。0 表示用 SCAN_INTERVAL_DEFAULT_MS。
    unsigned long scanIntervalMs;
    KSWORD_ARK_PROCESS_PROTECT_RULE rules[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_TRUSTED trusted[KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED];
} KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST;

typedef struct _KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long globalFlags;
    unsigned long ruleCount;

    unsigned long trustedCount;
    // KSWORD_ARK_PROCESS_PROTECT_STATUS_*。CALLBACK_UNAVAILABLE 时规则表仍然
    // 保留，但不会有任何一次削权发生。
    unsigned long capabilityStatus;
    // 句柄回调注册失败时的原始 NTSTATUS；注册成功为 0。
    long objectCallbackStatus;
    unsigned long reserved;

    unsigned long long configVersion;
    unsigned long long appliedAtUtc100ns;

    // 统计计数器。evaluated 统计进入保护判定的句柄创建/复制次数，
    // stripped 统计真正削掉了权限位的次数，trustedBypass 统计因信任项放行的次数。
    unsigned long long evaluatedCount;
    unsigned long long strippedCount;
    unsigned long long trustedBypassCount;

    unsigned long long lastBlockedUtc100ns;
    unsigned long lastBlockedInitiatorPid;
    unsigned long lastBlockedTargetPid;
    unsigned long lastBlockedRuleId;
    unsigned long lastBlockedOriginalAccess;
    unsigned long lastBlockedGrantedAccess;
    unsigned long lastBlockedIsThreadObject;
    wchar_t lastBlockedInitiatorImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];
    wchar_t lastBlockedTargetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];

    // ---- v2：内核 PP 层 ----
    unsigned long scanIntervalMs;
    // 当前台账里仍然有效的受保护进程数量。
    unsigned long trackedProcessCount;
    // kernelApplyCount：成功施加 PP/PPL 的次数（含创建时施加与巡检恢复）。
    // selfHealCount：巡检发现 Protection 被改回并成功恢复的次数。
    // kernelApplyFailureCount：施加失败次数，通常意味着 DynData 偏移不可用。
    // hardenApplyCount：执行加固动作（如清 DebugPort）的次数。
    unsigned long long kernelApplyCount;
    unsigned long long selfHealCount;
    unsigned long long kernelApplyFailureCount;
    unsigned long long hardenApplyCount;
    // 最近一次篡改：被改回时观察到的字节与期望字节。
    unsigned long long lastTamperUtc100ns;
    unsigned long lastTamperProcessId;
    unsigned long lastTamperObservedProtection;
    unsigned long lastTamperExpectedProtection;
    unsigned long lastTamperRuleId;
    // 最近一次施加失败的原始 NTSTATUS，0 表示还没失败过。
    long lastKernelApplyStatus;
    unsigned long reservedV2;
    wchar_t lastTamperImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];

    unsigned long long ruleHitCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    // v2：每条规则施加内核保护的次数，与 ruleHitCounts（句柄削权次数）分开统计。
    unsigned long long ruleKernelApplyCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_RULE rules[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_TRUSTED trusted[KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED];
} KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE;
