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

#define KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION 1UL

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
// 规则标志
// ------------------------------------------------------------
// ENABLED        ：未置位的规则会被 R0 跳过，但仍占用一个槽位，便于 R3 保留草稿。
// PROTECT_THREADS：同时保护该进程内的线程句柄（THREAD_TERMINATE / SET_CONTEXT 等）。
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_PROTECT_THREADS 0x00000002UL

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
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_LOG_BLOCKED 0x00000002UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM 0x00000004UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS 0x00000008UL

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
    unsigned long reserved;
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

    unsigned long long ruleHitCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_RULE rules[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_TRUSTED trusted[KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED];
} KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE;
