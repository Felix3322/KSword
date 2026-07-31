#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

#include "ark/ark_network.h"
#include "ark/ark_log.h"

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10U
#endif

#define KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY 2048UL
#define KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY 2048UL
#define KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT 4UL

typedef struct _KSWORD_ARK_NETWORK_RUNTIME
{
    EX_PUSH_LOCK Lock; // Lock：保护低频规则快照，沿用既有规则生命周期。
    KSPIN_LOCK EventLock; // EventLock：保护 DISPATCH_LEVEL 可写的固定事件 ring。
    KSPIN_LOCK TrafficLock; // TrafficLock：保护 IP packet classify 写入的逐包 ring。
    WDFDEVICE Device; // Device：控制设备和日志入口。
    PDRIVER_OBJECT DriverObject; // DriverObject：WFP callout 注册使用的驱动对象。
    PDEVICE_OBJECT DeviceObject; // DeviceObject：FwpsCalloutRegister0 使用的设备对象。
    HANDLE EngineHandle; // EngineHandle：动态 WFP engine 会话。
    UINT32 ConnectCalloutId; // ConnectCalloutId：ALE_AUTH_CONNECT_V4 runtime callout ID。
    UINT32 RecvAcceptCalloutId; // RecvAcceptCalloutId：ALE_AUTH_RECV_ACCEPT_V4 runtime callout ID。
    UINT64 ConnectFilterId; // ConnectFilterId：出站授权 filter ID。
    UINT64 RecvAcceptFilterId; // RecvAcceptFilterId：入站授权 filter ID。
    UINT32 TrafficCalloutIds[KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT]; // TrafficCalloutIds：IPv4/IPv6 入站/出站逐包 runtime callout ID。
    UINT64 TrafficFilterIds[KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT]; // TrafficFilterIds：逐包 inspection filter ID。
    NTSTATUS RegisterStatus; // RegisterStatus：runtime callout 注册结果。
    NTSTATUS EngineStatus; // EngineStatus：BFE engine/filter 安装结果。
    NTSTATUS TrafficCaptureStatus; // TrafficCaptureStatus：逐包 callout/filter 注册结果。
    ULONG RuntimeFlags; // RuntimeFlags：WFP 与规则能力位。
    ULONG RuleCount; // RuleCount：启用规则总数。
    ULONG BlockedRuleCount; // BlockedRuleCount：启用阻断规则数。
    ULONG HiddenPortRuleCount; // HiddenPortRuleCount：启用隐藏端口规则数。
    ULONG Generation; // Generation：规则快照代数。
    volatile LONG64 ClassifyCount; // ClassifyCount：ALE classify 累计调用数。
    volatile LONG64 BlockedCount; // BlockedCount：实际阻断累计数。
    ULONG EventWriteIndex; // EventWriteIndex：下一事件写入槽位。
    ULONG EventCount; // EventCount：ring 当前有效行数。
    ULONG64 NextEventSequence; // NextEventSequence：下一稳定单调序号。
    ULONG64 DroppedEventCount; // DroppedEventCount：ring 覆盖旧行的累计数。
    ULONG TrafficWriteIndex; // TrafficWriteIndex：逐包 ring 下一写入槽位。
    ULONG TrafficCount; // TrafficCount：逐包 ring 当前有效行数。
    ULONG64 NextTrafficSequence; // NextTrafficSequence：下一逐包稳定单调序号。
    ULONG64 DroppedTrafficCount; // DroppedTrafficCount：逐包 ring 覆盖旧行累计数。
    KSWORD_ARK_NETWORK_RULE Rules[KSWORD_ARK_NETWORK_MAX_RULES]; // Rules：规则快照。
    KSWORD_ARK_NETWORK_WFP_EVENT_ROW EventRing[KSWORD_ARK_NETWORK_EVENT_RING_CAPACITY]; // EventRing：固定非分页 ALE 事件 ring。
    KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW TrafficRing[KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY]; // TrafficRing：固定非分页 IPv4/IPv6 逐包 ring。
} KSWORD_ARK_NETWORK_RUNTIME;

EXTERN_C_START

KSWORD_ARK_NETWORK_RUNTIME*
KswordARKNetworkGetRuntime(
    VOID
    );

VOID
KswordARKNetworkLogFormat(
    _In_z_ PCSTR LevelText,
    _In_z_ _Printf_format_string_ PCSTR FormatText,
    ...
    );

BOOLEAN
KswordARKNetworkRuleMatchesLocked(
    _In_ const KSWORD_ARK_NETWORK_RULE* Rule,
    _In_ ULONG Direction,
    _In_ ULONG Protocol,
    _In_ USHORT LocalPort,
    _In_ USHORT RemotePort,
    _In_ ULONG ProcessId
    );

VOID
KswordARKNetworkRecordWfpAleEvent(
    _In_ ULONG Direction,
    _In_ ULONG Protocol,
    _In_ ULONG LocalAddressV4HostOrder,
    _In_ ULONG RemoteAddressV4HostOrder,
    _In_ USHORT LocalPort,
    _In_ USHORT RemotePort,
    _In_ ULONG ProcessId,
    _In_ ULONG Flags
    );

NTSTATUS
KswordARKNetworkWfpRegister(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    );

VOID
KswordARKNetworkWfpUnregister(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    );

NTSTATUS
KswordARKNetworkTrafficRegisterRuntimeCallouts(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    );

NTSTATUS
KswordARKNetworkTrafficAddEngineObjects(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    );

VOID
KswordARKNetworkTrafficDeleteEngineObjects(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    );

VOID
KswordARKNetworkTrafficUnregisterRuntimeCallouts(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    );

EXTERN_C_END
