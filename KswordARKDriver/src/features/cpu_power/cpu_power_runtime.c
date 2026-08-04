#include "cpu_power_runtime.h"

#include <intrin.h>

// ============================================================
// cpu_power_runtime.c
// 作用：
// - 只对白名单 Intel 电源管理 MSR 提供结构化读写；
// - 所有 MSR 访问都在目标逻辑处理器上执行并受 SEH 保护；
// - 不允许调用方提供 MSR 编号、掩码或任意原始写入值。
// ============================================================

// Intel 架构与 RAPL/HWP 文档定义的固定 MSR 编号。
#define KSW_CPU_POWER_MSR_PLATFORM_INFO       0x000000CEUL
#define KSW_CPU_POWER_MSR_PERF_STATUS         0x00000198UL
#define KSW_CPU_POWER_MSR_PERF_CONTROL        0x00000199UL
#define KSW_CPU_POWER_MSR_MISC_ENABLE         0x000001A0UL
#define KSW_CPU_POWER_MSR_TURBO_RATIO_LIMIT   0x000001ADUL
#define KSW_CPU_POWER_MSR_RAPL_POWER_UNIT     0x00000606UL
#define KSW_CPU_POWER_MSR_PACKAGE_POWER_LIMIT 0x00000610UL
#define KSW_CPU_POWER_MSR_PACKAGE_POWER_INFO  0x00000614UL
#define KSW_CPU_POWER_MSR_PM_ENABLE           0x00000770UL
#define KSW_CPU_POWER_MSR_HWP_CAPABILITIES    0x00000771UL
#define KSW_CPU_POWER_MSR_HWP_REQUEST         0x00000774UL

// Intel MSR 字段使用的固定掩码与位位置。
#define KSW_CPU_POWER_LIMIT_VALUE_MASK       0x0000000000007FFFULL
#define KSW_CPU_POWER_LIMIT_ENABLE_BIT       15UL
#define KSW_CPU_POWER_LIMIT_CLAMP_BIT        16UL
#define KSW_CPU_POWER_LIMIT_SECOND_SHIFT     32UL
#define KSW_CPU_POWER_LIMIT_SECOND_ENABLE    47UL
#define KSW_CPU_POWER_LIMIT_SECOND_CLAMP     48UL
#define KSW_CPU_POWER_LIMIT_LOCK_BIT         63UL
#define KSW_CPU_POWER_MISC_TURBO_DISABLE_BIT 38UL
#define KSW_CPU_POWER_PLATFORM_RATIO_BIT     28UL
#define KSW_CPU_POWER_PLATFORM_TDP_BIT       29UL
#define KSW_CPU_POWER_PERF_RATIO_SHIFT        8UL
#define KSW_CPU_POWER_PERF_RATIO_MASK         0x000000000000FF00ULL

// HWP 与 CPUID.06H 使用的架构能力位。
#define KSW_CPU_POWER_CPUID1_EIST_BIT  7UL
#define KSW_CPU_POWER_CPUID6_TURBO_BIT 1UL
#define KSW_CPU_POWER_CPUID6_HWP_BIT   7UL
#define KSW_CPU_POWER_CPUID6_EPP_BIT   10UL

// g_KswordCpuPowerLock 串行化查询和修改，防止两个 UI 请求交错覆盖同一 MSR。
static EX_PUSH_LOCK g_KswordCpuPowerLock;

// KswordARKCpuPowerReadMsr：在当前逻辑处理器读取一个编译期白名单 MSR。
static NTSTATUS
KswordARKCpuPowerReadMsr(
    _In_ ULONG MsrIndex,
    _Out_ ULONGLONG* Value
    )
{
    // 输出指针必须有效，避免异常路径写空地址。
    if (Value == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 先清零输出，失败时调用方不会看到旧栈值。
    *Value = 0ULL;
    __try {
        // __readmsr 仅接收本文件固定调用点传入的白名单编号。
        *Value = __readmsr(MsrIndex);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 虚拟化过滤或型号不支持时保留精确同步异常状态。
        return GetExceptionCode();
    }

    // 完整读取 64 位值后返回成功。
    return STATUS_SUCCESS;
}

// KswordARKCpuPowerWriteMsr：在当前逻辑处理器写入一个编译期白名单 MSR。
static NTSTATUS
KswordARKCpuPowerWriteMsr(
    _In_ ULONG MsrIndex,
    _In_ ULONGLONG Value
    )
{
    __try {
        // __writemsr 的编号和最终值均由本模块按字段生成。
        __writemsr(MsrIndex, Value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 锁定、虚拟化过滤或型号不支持时返回同步异常状态。
        return GetExceptionCode();
    }

    // 写指令无异常完成时返回成功，调用方仍必须执行回读验证。
    return STATUS_SUCCESS;
}

// KswordARKCpuPowerCopyCpuidText：把 CPUID 寄存器字节复制到固定协议文本。
static VOID
KswordARKCpuPowerCopyCpuidText(
    _Out_writes_bytes_(DestinationBytes) CHAR* Destination,
    _In_ SIZE_T DestinationBytes,
    _In_reads_bytes_(SourceBytes) const VOID* Source,
    _In_ SIZE_T SourceBytes
    )
{
    // 空缓冲区不执行任何访问。
    if (Destination == NULL || DestinationBytes == 0U) {
        return;
    }

    // 先清零完整目标，保证最后总有 NUL 终止符。
    RtlZeroMemory(Destination, DestinationBytes);
    // 仅在来源有效时复制目标容量减一以内的字节。
    if (Source != NULL && SourceBytes != 0U) {
        // copyBytes 明确限制在目标 NUL 之前。
        const SIZE_T copyBytes = min(SourceBytes, DestinationBytes - 1U);
        // 复制 CPUID 原始 ASCII 字节。
        RtlCopyMemory(Destination, Source, copyBytes);
    }
}

// KswordARKCpuPowerDecodeIdentity：解析 family/model/stepping 的扩展编码。
static VOID
KswordARKCpuPowerDecodeIdentity(
    _In_ ULONG Signature,
    _Out_ ULONG* Family,
    _Out_ ULONG* Model,
    _Out_ ULONG* Stepping
    )
{
    // 先提取基础字段，随后按 CPUID 规则扩展。
    ULONG family = (Signature >> 8U) & 0x0FUL;
    // model 保留基础四位。
    ULONG model = (Signature >> 4U) & 0x0FUL;
    // extendedFamily 只在基础 family 为 0xF 时累加。
    const ULONG extendedFamily = (Signature >> 20U) & 0xFFUL;
    // extendedModel 在 family 0x6/0xF 时拼到高位。
    const ULONG extendedModel = (Signature >> 16U) & 0x0FUL;
    // baseFamily 保留扩展前字段用于 model 判定。
    const ULONG baseFamily = family;

    // family 0xF 使用扩展字段。
    if (family == 0x0FUL) {
        family += extendedFamily;
    }
    // family 0x6 或基础 family 0xF 使用扩展 model。
    if (baseFamily == 0x06UL || baseFamily == 0x0FUL) {
        model |= extendedModel << 4U;
    }

    // 逐项发布解码结果。
    *Family = family;
    *Model = model;
    *Stepping = Signature & 0x0FUL;
}

// KswordARKCpuPowerRawPowerToMilliwatts：按 RAPL power unit 解码 15 位功耗值。
static ULONG
KswordARKCpuPowerRawPowerToMilliwatts(
    _In_ ULONGLONG RawPower,
    _In_ ULONG PowerUnitMicrowatts
    )
{
    // 0 单位表示 RAPL 单位读取失败，不能生成伪造功耗。
    if (PowerUnitMicrowatts == 0UL) {
        return 0UL;
    }

    // 使用 64 位整数并四舍五入到 mW，避免内核浮点运算。
    return (ULONG)(((RawPower & KSW_CPU_POWER_LIMIT_VALUE_MASK) *
        (ULONGLONG)PowerUnitMicrowatts + 500ULL) / 1000ULL);
}

// KswordARKCpuPowerDecodeTimeWindowMilliseconds：解码 RAPL Y/Z 时间窗口。
static ULONG
KswordARKCpuPowerDecodeTimeWindowMilliseconds(
    _In_ ULONG EncodedWindow,
    _In_ ULONG TimeUnitNanoseconds
    )
{
    // Y 位于低 5 位，Z 位于高 2 位。
    const ULONG y = EncodedWindow & 0x1FUL;
    // Z 表示 1 + Z/4 的倍率。
    const ULONG z = (EncodedWindow >> 5U) & 0x03UL;
    // 乘法在 64 位执行并先除以四，降低溢出概率。
    ULONGLONG nanoseconds = (ULONGLONG)TimeUnitNanoseconds *
        (ULONGLONG)(4UL + z);

    // 超大 Y 在左移前按 ULONG 毫秒上限饱和。
    if (y >= 31UL || nanoseconds > (MAXULONGLONG >> y)) {
        return MAXULONG;
    }
    // 应用 2^Y 后完成 Z 的四分之一倍率。
    nanoseconds = (nanoseconds << y) / 4ULL;
    // 转成毫秒并按 ULONG 上限饱和。
    if (nanoseconds / 1000000ULL > MAXULONG) {
        return MAXULONG;
    }
    // 返回整数毫秒。
    return (ULONG)(nanoseconds / 1000000ULL);
}

// KswordARKCpuPowerCaptureCpuid：填充厂商、品牌、身份与架构能力。
static VOID
KswordARKCpuPowerCaptureCpuid(
    _Inout_ KSWORD_ARK_CPU_POWER_RESPONSE* Response,
    _Out_ BOOLEAN* PerfControlSupported,
    _Out_ BOOLEAN* TurboSupported,
    _Out_ BOOLEAN* HwpSupported,
    _Out_ BOOLEAN* HwpEppSupported
    )
{
    // CPUID 寄存器缓冲区使用 MSVC intrinsic 规定的四个 int。
    int registers[4] = { 0, 0, 0, 0 };
    // vendorBytes 按 EBX/EDX/ECX 顺序拼接 12 字节厂商 ID。
    CHAR vendorBytes[12] = { 0 };
    // brandBytes 保存三个扩展叶的 48 字节品牌字符串。
    CHAR brandBytes[48] = { 0 };
    // 最大基础叶决定是否可访问叶 1 与叶 6。
    ULONG maximumBasicLeaf = 0UL;
    // 最大扩展叶决定是否存在品牌字符串。
    ULONG maximumExtendedLeaf = 0UL;

    // 初始化能力输出，避免旧值穿过无能力路径。
    *PerfControlSupported = FALSE;
    *TurboSupported = FALSE;
    *HwpSupported = FALSE;
    *HwpEppSupported = FALSE;

    // 基础叶 0 返回最大叶和厂商字符串。
    __cpuidex(registers, 0, 0);
    // 保存最大基础叶。
    maximumBasicLeaf = (ULONG)registers[0];
    // 按架构顺序复制厂商 ID。
    RtlCopyMemory(vendorBytes + 0, &registers[1], sizeof(registers[1]));
    RtlCopyMemory(vendorBytes + 4, &registers[3], sizeof(registers[3]));
    RtlCopyMemory(vendorBytes + 8, &registers[2], sizeof(registers[2]));
    // 发布固定 NUL 终止的厂商文本。
    KswordARKCpuPowerCopyCpuidText(
        Response->vendorId,
        sizeof(Response->vendorId),
        vendorBytes,
        sizeof(vendorBytes));

    // 精确识别 Intel 与 AMD，其他厂商保持 Unknown。
    if (RtlCompareMemory(vendorBytes, "GenuineIntel", sizeof(vendorBytes)) ==
        sizeof(vendorBytes)) {
        Response->vendor = KSWORD_ARK_CPU_POWER_VENDOR_INTEL;
    }
    else if (RtlCompareMemory(vendorBytes, "AuthenticAMD", sizeof(vendorBytes)) ==
        sizeof(vendorBytes)) {
        Response->vendor = KSWORD_ARK_CPU_POWER_VENDOR_AMD;
    }

    // 叶 1 提供签名与 hypervisor-present 位。
    if (maximumBasicLeaf >= 1UL) {
        // 读取处理器签名与通用特征。
        __cpuidex(registers, 1, 0);
        // 解码 family/model/stepping。
        KswordARKCpuPowerDecodeIdentity(
            (ULONG)registers[0],
            &Response->family,
            &Response->model,
            &Response->stepping);
        // ECX[7] 表示 Enhanced Intel SpeedStep，并声明 IA32_PERF_CTL 路径。
        *PerfControlSupported = ((((ULONG)registers[2]) &
            (1UL << KSW_CPU_POWER_CPUID1_EIST_BIT)) != 0UL) ? TRUE : FALSE;
        // ECX[31] 表示当前环境存在 hypervisor。
        if ((((ULONG)registers[2]) & (1UL << 31U)) != 0UL) {
            Response->responseFlags |=
                KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_HYPERVISOR_PRESENT;
        }
    }

    // 叶 6 提供 Turbo、HWP 与 HWP EPP 架构能力。
    if (maximumBasicLeaf >= 6UL) {
        // 读取 thermal/power management 特征叶。
        __cpuidex(registers, 6, 0);
        // EAX[1] 表示 Intel Turbo Boost Technology。
        *TurboSupported = ((((ULONG)registers[0]) &
            (1UL << KSW_CPU_POWER_CPUID6_TURBO_BIT)) != 0UL) ? TRUE : FALSE;
        // EAX[7] 表示 Hardware-Controlled Performance States。
        *HwpSupported = ((((ULONG)registers[0]) &
            (1UL << KSW_CPU_POWER_CPUID6_HWP_BIT)) != 0UL) ? TRUE : FALSE;
        // EAX[10] 表示 HWP Energy Performance Preference。
        *HwpEppSupported = ((((ULONG)registers[0]) &
            (1UL << KSW_CPU_POWER_CPUID6_EPP_BIT)) != 0UL) ? TRUE : FALSE;
    }

    // 扩展叶 0x80000000 返回品牌叶上限。
    __cpuidex(registers, (int)0x80000000UL, 0);
    // 保存最大扩展叶。
    maximumExtendedLeaf = (ULONG)registers[0];
    // 三个品牌叶必须全部存在才复制完整 48 字节。
    if (maximumExtendedLeaf >= 0x80000004UL) {
        // 逐叶写入固定品牌缓冲区。
        for (ULONG leafOffset = 0UL; leafOffset < 3UL; ++leafOffset) {
            // 读取当前 16 字节品牌片段。
            __cpuidex(registers, (int)(0x80000002UL + leafOffset), 0);
            // 复制四个寄存器到对应偏移。
            RtlCopyMemory(
                brandBytes + (leafOffset * sizeof(registers)),
                registers,
                sizeof(registers));
        }
        // 发布固定 NUL 终止的品牌文本。
        KswordARKCpuPowerCopyCpuidText(
            Response->brandText,
            sizeof(Response->brandText),
            brandBytes,
            sizeof(brandBytes));
    }

    // 标记 CPUID 基础身份已经可用。
    Response->fieldFlags |= KSWORD_ARK_CPU_POWER_FIELD_CPUID;
}

// KswordARKCpuPowerDecodeSnapshot：把已读取的原始 MSR 解码为稳定协议字段。
static VOID
KswordARKCpuPowerDecodeSnapshot(
    _Inout_ KSWORD_ARK_CPU_POWER_RESPONSE* Response
    )
{
    // RAPL 单位存在时解码 power/time unit。
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_RAPL_UNIT) != 0UL) {
        // powerExponent 位于 MSR[3:0]。
        const ULONG powerExponent = (ULONG)(Response->msrRaplPowerUnit & 0x0FULL);
        // timeExponent 位于 MSR[19:16]。
        const ULONG timeExponent =
            (ULONG)((Response->msrRaplPowerUnit >> 16U) & 0x0FULL);
        // powerDenominator 是 2 的单位指数次方。
        const ULONGLONG powerDenominator = 1ULL << powerExponent;
        // timeDenominator 是 2 的单位指数次方。
        const ULONGLONG timeDenominator = 1ULL << timeExponent;
        // 使用四舍五入整数单位，最小保持 1 微瓦。
        Response->powerUnitMicrowatts = (ULONG)max(
            1ULL,
            (1000000ULL + (powerDenominator / 2ULL)) / powerDenominator);
        // 时间单位同样使用整数纳秒表达。
        Response->timeUnitNanoseconds = (ULONG)max(
            1ULL,
            (1000000000ULL + (timeDenominator / 2ULL)) / timeDenominator);
    }

    // 解码当前 PL1/PL2 与 enable/clamp/lock 位。
    if ((Response->fieldFlags &
        KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_LIMIT) != 0UL) {
        // PL1 使用低 15 位。
        Response->pl1Milliwatts = KswordARKCpuPowerRawPowerToMilliwatts(
            Response->msrPackagePowerLimit,
            Response->powerUnitMicrowatts);
        // PL2 使用位 46:32。
        Response->pl2Milliwatts = KswordARKCpuPowerRawPowerToMilliwatts(
            Response->msrPackagePowerLimit >> KSW_CPU_POWER_LIMIT_SECOND_SHIFT,
            Response->powerUnitMicrowatts);
        // 分别发布 enable 与 clamp 状态。
        Response->pl1Enabled =
            (ULONG)((Response->msrPackagePowerLimit >>
                KSW_CPU_POWER_LIMIT_ENABLE_BIT) & 1ULL);
        Response->pl1ClampEnabled =
            (ULONG)((Response->msrPackagePowerLimit >>
                KSW_CPU_POWER_LIMIT_CLAMP_BIT) & 1ULL);
        Response->pl2Enabled =
            (ULONG)((Response->msrPackagePowerLimit >>
                KSW_CPU_POWER_LIMIT_SECOND_ENABLE) & 1ULL);
        Response->pl2ClampEnabled =
            (ULONG)((Response->msrPackagePowerLimit >>
                KSW_CPU_POWER_LIMIT_SECOND_CLAMP) & 1ULL);
        // 位 63 一旦锁定，只能由复位/固件重新建立状态。
        if (((Response->msrPackagePowerLimit >>
            KSW_CPU_POWER_LIMIT_LOCK_BIT) & 1ULL) != 0ULL) {
            Response->responseFlags |=
                KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_POWER_LIMIT_LOCKED;
        }
    }

    // 解码 SKU TDP、最小/最大功耗与最大时间窗口。
    if ((Response->fieldFlags &
        KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_INFO) != 0UL) {
        // 位 14:0 是 Thermal Spec Power。
        Response->packageTdpMilliwatts = KswordARKCpuPowerRawPowerToMilliwatts(
            Response->msrPackagePowerInfo,
            Response->powerUnitMicrowatts);
        // 位 30:16 是 Minimum Power。
        Response->packageMinimumPowerMilliwatts =
            KswordARKCpuPowerRawPowerToMilliwatts(
                Response->msrPackagePowerInfo >> 16U,
                Response->powerUnitMicrowatts);
        // 位 46:32 是 Maximum Power。
        Response->packageMaximumPowerMilliwatts =
            KswordARKCpuPowerRawPowerToMilliwatts(
                Response->msrPackagePowerInfo >> 32U,
                Response->powerUnitMicrowatts);
        // 位 54:48 使用同一 Y/Z 时间编码。
        Response->packageMaximumTimeWindowMilliseconds =
            KswordARKCpuPowerDecodeTimeWindowMilliseconds(
                (ULONG)((Response->msrPackagePowerInfo >> 48U) & 0x7FULL),
                Response->timeUnitNanoseconds);
        // 某些 SKU 返回 0 最大功耗，UI 必须显示“平台上限未知”。
        if (Response->packageMaximumPowerMilliwatts == 0UL) {
            Response->responseFlags |=
                KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_PLATFORM_MAX_UNKNOWN;
        }
    }

    // 解码平台倍率信息与可编程能力提示。
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_PLATFORM_INFO) != 0UL) {
        // 最大非 Turbo ratio 位于 15:8。
        Response->maximumNonTurboRatio =
            (ULONG)((Response->msrPlatformInfo >> 8U) & 0xFFULL);
        // 最大效率 ratio 位于 47:40。
        Response->maximumEfficiencyRatio =
            (ULONG)((Response->msrPlatformInfo >> 40U) & 0xFFULL);
        // 位 28 表示 Turbo Ratio Limit 可编程。
        if (((Response->msrPlatformInfo >>
            KSW_CPU_POWER_PLATFORM_RATIO_BIT) & 1ULL) != 0ULL) {
            Response->capabilityFlags |=
                KSWORD_ARK_CPU_POWER_CAP_TURBO_RATIO_PROGRAMMABLE;
        }
        // 位 29 作为平台可编程 TDP 的额外证据。
        if (((Response->msrPlatformInfo >>
            KSW_CPU_POWER_PLATFORM_TDP_BIT) & 1ULL) != 0ULL) {
            Response->capabilityFlags |=
                KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_PROGRAMMABLE;
        }
    }

    // 任何可读且未锁定的 package limit 都允许结构化 PL1/PL2 修改。
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_LIMIT) != 0UL &&
        (Response->responseFlags &
            KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_POWER_LIMIT_LOCKED) == 0UL) {
        Response->capabilityFlags |=
            KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_PROGRAMMABLE;
    }

    // IA32_MISC_ENABLE[38] 为 1 时 Turbo 被禁用。
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_MISC_ENABLE) != 0UL) {
        Response->turboEnabled =
            ((Response->msrMiscEnable >> KSW_CPU_POWER_MISC_TURBO_DISABLE_BIT) &
                1ULL) == 0ULL ? 1UL : 0UL;
        Response->capabilityFlags |= KSWORD_ARK_CPU_POWER_CAP_TURBO_CONTROL;
    }

    // IA32_PERF_CTL[15:8] 是软件请求倍频；IA32_PERF_STATUS[15:8] 是当前倍频反馈。
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_PERF_CONTROL) != 0UL) {
        Response->requestedMultiplier =
            (ULONG)((Response->msrPerfControl >>
                KSW_CPU_POWER_PERF_RATIO_SHIFT) & 0xFFULL);
    }
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_PERF_STATUS) != 0UL) {
        Response->currentMultiplier =
            (ULONG)((Response->msrPerfStatus >>
                KSW_CPU_POWER_PERF_RATIO_SHIFT) & 0xFFULL);
    }

    // IA32_PM_ENABLE[0] 表示 HWP 已由固件或操作系统启用。
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_PM_ENABLE) != 0UL &&
        (Response->msrPmEnable & 1ULL) != 0ULL) {
        Response->capabilityFlags |= KSWORD_ARK_CPU_POWER_CAP_HWP_ENABLED;
    }

    // HWP capability 的四个性能字节按架构顺序解码。
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_HWP_CAPABILITIES) != 0UL) {
        Response->hwpHighestPerformance =
            (ULONG)(Response->msrHwpCapabilities & 0xFFULL);
        Response->hwpGuaranteedPerformance =
            (ULONG)((Response->msrHwpCapabilities >> 8U) & 0xFFULL);
        Response->hwpMostEfficientPerformance =
            (ULONG)((Response->msrHwpCapabilities >> 16U) & 0xFFULL);
        Response->hwpLowestPerformance =
            (ULONG)((Response->msrHwpCapabilities >> 24U) & 0xFFULL);
    }

    // HWP request 的 min/max/desired/EPP 分别位于低四个字节。
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_HWP_REQUEST) != 0UL) {
        Response->hwpMinimumPerformance =
            (ULONG)(Response->msrHwpRequest & 0xFFULL);
        Response->hwpMaximumPerformance =
            (ULONG)((Response->msrHwpRequest >> 8U) & 0xFFULL);
        Response->hwpDesiredPerformance =
            (ULONG)((Response->msrHwpRequest >> 16U) & 0xFFULL);
        Response->hwpEnergyPerformancePreference =
            (ULONG)((Response->msrHwpRequest >> 24U) & 0xFFULL);
    }

    // Turbo Ratio Limit 的八个字节按活跃核心数量顺序展示。
    if ((Response->fieldFlags &
        KSWORD_ARK_CPU_POWER_FIELD_TURBO_RATIO_LIMIT) != 0UL) {
        // 逐字节解码并保留 0 表示该档位未实现。
        for (ULONG ratioIndex = 0UL;
            ratioIndex < KSWORD_ARK_CPU_POWER_TURBO_RATIO_COUNT;
            ++ratioIndex) {
            Response->turboRatios[ratioIndex] =
                (ULONG)((Response->msrTurboRatioLimit >>
                    (ratioIndex * 8U)) & 0xFFULL);
        }
    }
}

// KswordARKCpuPowerQuerySnapshotUnlocked：调用方持锁时执行完整只读采样。
static NTSTATUS
KswordARKCpuPowerQuerySnapshotUnlocked(
    _Out_ KSWORD_ARK_CPU_POWER_RESPONSE* Response
    )
{
    // perfControlSupported 来自 CPUID.1:ECX.EIST，作为读取 0x198/0x199 的架构门控。
    BOOLEAN perfControlSupported = FALSE;
    // capability 状态由 CPUID 叶 6 输出。
    BOOLEAN turboSupported = FALSE;
    // hwpSupported 表示架构支持，不等于 IA32_PM_ENABLE 已开启。
    BOOLEAN hwpSupported = FALSE;
    // hwpEppSupported 单独控制 EPP 字节是否可写。
    BOOLEAN hwpEppSupported = FALSE;
    // firstFailure 保存第一条 MSR 异常，响应仍返回其余可读字段。
    NTSTATUS firstFailure = STATUS_SUCCESS;
    // status 接收每次白名单 MSR 读取结果。
    NTSTATUS status = STATUS_SUCCESS;

    // 输出包必须有效。
    if (Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 清零完整响应并建立版本化固定头。
    RtlZeroMemory(Response, sizeof(*Response));
    Response->size = sizeof(*Response);
    Response->version = KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION;
    // 查询当前系统的活动处理器和组数量。
    Response->logicalProcessorCount =
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    Response->processorGroupCount = (ULONG)KeQueryActiveGroupCount();

    // 先采集 CPUID；该路径不访问型号相关 MSR。
    KswordARKCpuPowerCaptureCpuid(
        Response,
        &perfControlSupported,
        &turboSupported,
        &hwpSupported,
        &hwpEppSupported);

    // 当前模块只对白名单 Intel MSR 定义写语义。
    if (Response->vendor != KSWORD_ARK_CPU_POWER_VENDOR_INTEL) {
        Response->responseFlags |=
            KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_UNSUPPORTED_VENDOR;
        Response->lastStatus = STATUS_NOT_SUPPORTED;
        return STATUS_SUCCESS;
    }

    // 发布 CPUID 架构能力，不以单个 MSR 读取失败抹掉能力事实。
    if (turboSupported != FALSE) {
        Response->capabilityFlags |= KSWORD_ARK_CPU_POWER_CAP_TURBO;
    }
    if (hwpSupported != FALSE) {
        Response->capabilityFlags |= KSWORD_ARK_CPU_POWER_CAP_HWP;
    }
    if (hwpEppSupported != FALSE) {
        Response->capabilityFlags |= KSWORD_ARK_CPU_POWER_CAP_HWP_EPP;
    }

    // EIST 宣告 IA32_PERF_CTL/STATUS 时读取请求值与当前反馈。
    if (perfControlSupported != FALSE) {
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_PERF_CONTROL,
            &Response->msrPerfControl);
        if (NT_SUCCESS(status)) {
            Response->fieldFlags |= KSWORD_ARK_CPU_POWER_FIELD_PERF_CONTROL;
            Response->capabilityFlags |=
                KSWORD_ARK_CPU_POWER_CAP_PERF_CONTROL |
                KSWORD_ARK_CPU_POWER_CAP_PERF_CONTROL_PROGRAMMABLE;
        }
        else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }

        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_PERF_STATUS,
            &Response->msrPerfStatus);
        if (NT_SUCCESS(status)) {
            Response->fieldFlags |= KSWORD_ARK_CPU_POWER_FIELD_PERF_STATUS;
        }
        else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }

    // 读取 RAPL 单位。
    status = KswordARKCpuPowerReadMsr(
        KSW_CPU_POWER_MSR_RAPL_POWER_UNIT,
        &Response->msrRaplPowerUnit);
    if (NT_SUCCESS(status)) {
        Response->fieldFlags |= KSWORD_ARK_CPU_POWER_FIELD_RAPL_UNIT;
        Response->capabilityFlags |= KSWORD_ARK_CPU_POWER_CAP_RAPL;
    }
    else {
        firstFailure = status;
    }

    // 只有单位可读时才继续读取 package power 域。
    if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_RAPL_UNIT) != 0UL) {
        // 读取当前 PL1/PL2 与 lock 位。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_PACKAGE_POWER_LIMIT,
            &Response->msrPackagePowerLimit);
        if (NT_SUCCESS(status)) {
            Response->fieldFlags |=
                KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_LIMIT;
            Response->capabilityFlags |=
                KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_LIMIT;
        }
        else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }

        // 读取 SKU power info；该寄存器可选，失败不阻塞当前限制展示。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_PACKAGE_POWER_INFO,
            &Response->msrPackagePowerInfo);
        if (NT_SUCCESS(status)) {
            Response->fieldFlags |=
                KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_INFO;
            Response->capabilityFlags |=
                KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_INFO;
        }
        else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }

    // 平台信息提供倍率和可编程提示。
    status = KswordARKCpuPowerReadMsr(
        KSW_CPU_POWER_MSR_PLATFORM_INFO,
        &Response->msrPlatformInfo);
    if (NT_SUCCESS(status)) {
        Response->fieldFlags |= KSWORD_ARK_CPU_POWER_FIELD_PLATFORM_INFO;
    }
    else if (NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    // Turbo 开关依赖 IA32_MISC_ENABLE。
    if (turboSupported != FALSE) {
        // 读取当前 Turbo disable 位。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_MISC_ENABLE,
            &Response->msrMiscEnable);
        if (NT_SUCCESS(status)) {
            Response->fieldFlags |= KSWORD_ARK_CPU_POWER_FIELD_MISC_ENABLE;
        }
        else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }

    // HWP 架构支持时读取 enable/capability/request 三个白名单 MSR。
    if (hwpSupported != FALSE) {
        // 先读取 HWP 是否已经由平台启用。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_PM_ENABLE,
            &Response->msrPmEnable);
        if (NT_SUCCESS(status)) {
            Response->fieldFlags |= KSWORD_ARK_CPU_POWER_FIELD_PM_ENABLE;
        }
        else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }

        // 读取性能上下界能力。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_HWP_CAPABILITIES,
            &Response->msrHwpCapabilities);
        if (NT_SUCCESS(status)) {
            Response->fieldFlags |=
                KSWORD_ARK_CPU_POWER_FIELD_HWP_CAPABILITIES;
        }
        else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }

        // 仅在 PM_ENABLE[0] 已知为 1 时读取当前 HWP request。
        if ((Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_PM_ENABLE) != 0UL &&
            (Response->msrPmEnable & 1ULL) != 0ULL) {
            // 读取当前逻辑处理器的请求字节。
            status = KswordARKCpuPowerReadMsr(
                KSW_CPU_POWER_MSR_HWP_REQUEST,
                &Response->msrHwpRequest);
            if (NT_SUCCESS(status)) {
                Response->fieldFlags |=
                    KSWORD_ARK_CPU_POWER_FIELD_HWP_REQUEST;
            }
            else if (NT_SUCCESS(firstFailure)) {
                firstFailure = status;
            }
        }
    }

    // 只有平台明确声明 ratio limit 可编程时才读取 0x1AD。
    if (turboSupported != FALSE &&
        (Response->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_PLATFORM_INFO) != 0UL &&
        ((Response->msrPlatformInfo >> KSW_CPU_POWER_PLATFORM_RATIO_BIT) & 1ULL) != 0ULL) {
        // 读取最多八档 Turbo Ratio Limit。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_TURBO_RATIO_LIMIT,
            &Response->msrTurboRatioLimit);
        if (NT_SUCCESS(status)) {
            Response->fieldFlags |=
                KSWORD_ARK_CPU_POWER_FIELD_TURBO_RATIO_LIMIT;
            Response->capabilityFlags |=
                KSWORD_ARK_CPU_POWER_CAP_TURBO_RATIO_LIMIT;
        }
        else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }

    // 将所有成功读取的原始字段解码为 UI 可直接消费的整数单位。
    KswordARKCpuPowerDecodeSnapshot(Response);
    // 任一预期 MSR 失败时标记 partial，但不把成功字段伪装成全失败。
    if (!NT_SUCCESS(firstFailure)) {
        Response->responseFlags |=
            KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_PARTIAL_MSR;
        Response->lastStatus = firstFailure;
    }
    else {
        Response->lastStatus = STATUS_SUCCESS;
    }

    // 查询 IOCTL 始终以传输成功返回固定包，语义状态位于 lastStatus/flags。
    return STATUS_SUCCESS;
}

// KswordARKCpuPowerQuerySnapshot：在 push lock 下执行公开只读查询。
NTSTATUS
KswordARKCpuPowerQuerySnapshot(
    _Out_ KSWORD_ARK_CPU_POWER_RESPONSE* Response
    )
{
    // status 接收内部固定包查询结果。
    NTSTATUS status = STATUS_SUCCESS;

    // 查询同样进入临界区，防止读到一次修改的中间状态。
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_KswordCpuPowerLock);
    // 锁内执行全部当前处理器采样。
    status = KswordARKCpuPowerQuerySnapshotUnlocked(Response);
    // 对称释放共享锁与临界区。
    ExReleasePushLockShared(&g_KswordCpuPowerLock);
    KeLeaveCriticalRegion();
    // 返回传输级结果。
    return status;
}

// KswordARKCpuPowerMilliwattsToRaw：把用户态 mW 转为 RAPL 15 位单位值。
static NTSTATUS
KswordARKCpuPowerMilliwattsToRaw(
    _In_ ULONG Milliwatts,
    _In_ ULONG PowerUnitMicrowatts,
    _Out_ ULONGLONG* RawPower
    )
{
    // 输入和输出必须处于协议硬边界内。
    if (RawPower == NULL || PowerUnitMicrowatts == 0UL ||
        Milliwatts == 0UL ||
        Milliwatts > KSWORD_ARK_CPU_POWER_ABSOLUTE_MAX_MILLIWATTS) {
        return STATUS_INVALID_PARAMETER;
    }

    // scaledMicrowatts 使用 64 位，1000 W 仍远低于溢出边界。
    const ULONGLONG scaledMicrowatts = (ULONGLONG)Milliwatts * 1000ULL;
    // 按最近整数编码 RAPL 功耗字段。
    const ULONGLONG rawPower =
        (scaledMicrowatts + ((ULONGLONG)PowerUnitMicrowatts / 2ULL)) /
        (ULONGLONG)PowerUnitMicrowatts;
    // 0 或超过 15 位都不能静默截断。
    if (rawPower == 0ULL || rawPower > KSW_CPU_POWER_LIMIT_VALUE_MASK) {
        return STATUS_INTEGER_OVERFLOW;
    }

    // 发布已验证的 15 位值。
    *RawPower = rawPower;
    return STATUS_SUCCESS;
}

// KswordARKCpuPowerValidateExpectedSnapshot：防止 UI 以陈旧值覆盖固件/其他工具的新设置。
static NTSTATUS
KswordARKCpuPowerValidateExpectedSnapshot(
    _In_ const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* Request,
    _Inout_ KSWORD_ARK_CPU_POWER_RESPONSE* Snapshot
    )
{
    // 未请求 optimistic check 时直接返回。
    if ((Request->requestFlags &
        KSWORD_ARK_CPU_POWER_REQUEST_FLAG_REQUIRE_CURRENT) == 0UL) {
        return STATUS_SUCCESS;
    }

    // 只比较本次将修改的寄存器，其他操作不会制造无关冲突。
    if (((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_POWER_LIMITS) != 0UL &&
            Request->expectedPackagePowerLimit != Snapshot->msrPackagePowerLimit) ||
        ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_TURBO) != 0UL &&
            Request->expectedMiscEnable != Snapshot->msrMiscEnable) ||
        ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_HWP) != 0UL &&
            Request->expectedHwpRequest != Snapshot->msrHwpRequest) ||
        ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_TURBO_RATIO) != 0UL &&
            Request->expectedTurboRatioLimit != Snapshot->msrTurboRatioLimit) ||
        ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_PERF_CONTROL) != 0UL &&
            Request->expectedPerfControl != Snapshot->msrPerfControl)) {
        // 标记 stale，供 UI 解释为“先刷新再重试”。
        Snapshot->responseFlags |=
            KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_STALE_SNAPSHOT;
        // failureReason 让 R3 区分并发快照冲突与普通参数错误。
        Snapshot->failureReason =
            KSWORD_ARK_CPU_POWER_FAILURE_STALE_SNAPSHOT;
        Snapshot->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_REVISION_MISMATCH;
    }

    // 所有受影响寄存器仍与 UI 快照一致。
    return STATUS_SUCCESS;
}

// KswordARKCpuPowerValidateRequest：按能力、锁定位和数值范围校验结构化请求。
static NTSTATUS
KswordARKCpuPowerValidateRequest(
    _In_ const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* Request,
    _Inout_ KSWORD_ARK_CPU_POWER_RESPONSE* Snapshot
    )
{
    // 协议头、flags 与 UI 确认均为硬门控。
    if (Request == NULL || Snapshot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    // 已有响应时为协议头/flags 错误记录明确原因。
    if (
        Request->size < sizeof(*Request) ||
        Request->version != KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION ||
        Request->applyFlags == 0UL ||
        (Request->applyFlags & ~KSWORD_ARK_CPU_POWER_APPLY_ALL) != 0UL ||
        (Request->requestFlags &
            ~(KSWORD_ARK_CPU_POWER_REQUEST_FLAG_UI_CONFIRMED |
              KSWORD_ARK_CPU_POWER_REQUEST_FLAG_REQUIRE_CURRENT |
              KSWORD_ARK_CPU_POWER_REQUEST_FLAG_TURBO_RATIO_ARRAY)) != 0UL ||
        ((Request->requestFlags &
            KSWORD_ARK_CPU_POWER_REQUEST_FLAG_TURBO_RATIO_ARRAY) != 0UL &&
         (Request->applyFlags &
            KSWORD_ARK_CPU_POWER_APPLY_TURBO_RATIO) == 0UL) ||
        (Request->requestFlags &
            KSWORD_ARK_CPU_POWER_REQUEST_FLAG_UI_CONFIRMED) == 0UL) {
        Snapshot->failureReason =
            KSWORD_ARK_CPU_POWER_FAILURE_REQUEST_HEADER;
        return STATUS_INVALID_PARAMETER;
    }

    // AMD SMU 接口按 family/model 变化，本版本不把 Intel MSR 语义套到 AMD。
    if (Snapshot->vendor != KSWORD_ARK_CPU_POWER_VENDOR_INTEL) {
        Snapshot->failureReason = KSWORD_ARK_CPU_POWER_FAILURE_VENDOR;
        return STATUS_NOT_SUPPORTED;
    }

    // PL1/PL2 修改必须同时具备单位、当前限制和未锁定证据。
    if ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_POWER_LIMITS) != 0UL) {
        // 读取能力或 lock 任一不满足都拒绝写入。
        if ((Snapshot->capabilityFlags &
                KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_PROGRAMMABLE) == 0ULL ||
            (Snapshot->fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_RAPL_UNIT) == 0UL ||
            (Snapshot->fieldFlags &
                KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_LIMIT) == 0UL ||
            (Snapshot->responseFlags &
                KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_POWER_LIMIT_LOCKED) != 0UL) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_POWER_CAPABILITY;
            return STATUS_ACCESS_DENIED;
        }

        // 协议绝对上限始终有效。
        if (Request->pl1Milliwatts == 0UL ||
            Request->pl2Milliwatts == 0UL ||
            Request->pl1Milliwatts >
                KSWORD_ARK_CPU_POWER_ABSOLUTE_MAX_MILLIWATTS ||
            Request->pl2Milliwatts >
                KSWORD_ARK_CPU_POWER_ABSOLUTE_MAX_MILLIWATTS) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_POWER_ABSOLUTE_RANGE;
            return STATUS_INVALID_PARAMETER;
        }

        // SKU 提供非 0 最大功耗时禁止越过该平台边界。
        if (Snapshot->packageMaximumPowerMilliwatts != 0UL &&
            (Request->pl1Milliwatts >
                Snapshot->packageMaximumPowerMilliwatts ||
             Request->pl2Milliwatts >
                Snapshot->packageMaximumPowerMilliwatts)) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_POWER_PLATFORM_MAXIMUM;
            return STATUS_INVALID_PARAMETER;
        }

        // SKU 提供非 0 最小功耗时同样拒绝低于硬件声明范围。
        if (Snapshot->packageMinimumPowerMilliwatts != 0UL &&
            (Request->pl1Milliwatts <
                Snapshot->packageMinimumPowerMilliwatts ||
             Request->pl2Milliwatts <
                Snapshot->packageMinimumPowerMilliwatts)) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_POWER_PLATFORM_MINIMUM;
            return STATUS_INVALID_PARAMETER;
        }

        // 四个布尔字段只接受 0/1。
        if (Request->pl1Enabled > 1UL ||
            Request->pl1ClampEnabled > 1UL ||
            Request->pl2Enabled > 1UL ||
            Request->pl2ClampEnabled > 1UL) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_POWER_BOOLEAN;
            return STATUS_INVALID_PARAMETER;
        }
    }

    // Turbo 开关必须有 CPUID 与 IA32_MISC_ENABLE 双重证据。
    if ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_TURBO) != 0UL) {
        // 未实现或非布尔输入均拒绝。
        if ((Snapshot->capabilityFlags &
                KSWORD_ARK_CPU_POWER_CAP_TURBO_CONTROL) == 0ULL ||
            Request->turboEnabled > 1UL) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_TURBO_CAPABILITY;
            return STATUS_NOT_SUPPORTED;
        }
    }

    // HWP 修改要求固件/操作系统已经开启 HWP。
    if ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_HWP) != 0UL) {
        // capability、enabled、request、capability MSR 缺一不可。
        if ((Snapshot->capabilityFlags & KSWORD_ARK_CPU_POWER_CAP_HWP) == 0ULL ||
            (Snapshot->capabilityFlags &
                KSWORD_ARK_CPU_POWER_CAP_HWP_ENABLED) == 0ULL ||
            (Snapshot->fieldFlags &
                KSWORD_ARK_CPU_POWER_FIELD_HWP_CAPABILITIES) == 0UL ||
            (Snapshot->fieldFlags &
                KSWORD_ARK_CPU_POWER_FIELD_HWP_REQUEST) == 0UL) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_HWP_CAPABILITY;
            return STATUS_NOT_SUPPORTED;
        }

        // 四个 HWP 字段均为 8 位。
        if (Request->hwpMinimumPerformance > 0xFFUL ||
            Request->hwpMaximumPerformance > 0xFFUL ||
            Request->hwpDesiredPerformance > 0xFFUL ||
            Request->hwpEnergyPerformancePreference > 0xFFUL) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_HWP_PLATFORM_RANGE;
            return STATUS_INVALID_PARAMETER;
        }
        // minimum 大于 maximum 是最常见的 UI 关系错误，单独报告。
        if (Request->hwpMinimumPerformance >
            Request->hwpMaximumPerformance) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_HWP_ORDER;
            return STATUS_INVALID_PARAMETER;
        }

        // 非 0 desired 必须落在请求的 min/max 内。
        if (Request->hwpDesiredPerformance != 0UL &&
            (Request->hwpDesiredPerformance <
                Request->hwpMinimumPerformance ||
             Request->hwpDesiredPerformance >
                Request->hwpMaximumPerformance)) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_HWP_DESIRED_RANGE;
            return STATUS_INVALID_PARAMETER;
        }

        // HWP capability 提供非 0 上下界时必须服从该边界。
        if (Snapshot->hwpLowestPerformance != 0UL &&
            Request->hwpMinimumPerformance <
                Snapshot->hwpLowestPerformance) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_HWP_PLATFORM_RANGE;
            return STATUS_INVALID_PARAMETER;
        }
        if (Snapshot->hwpHighestPerformance != 0UL &&
            (Request->hwpMaximumPerformance >
                Snapshot->hwpHighestPerformance ||
             Request->hwpDesiredPerformance >
                Snapshot->hwpHighestPerformance)) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_HWP_PLATFORM_RANGE;
            return STATUS_INVALID_PARAMETER;
        }

        // 不支持 EPP 时禁止用户悄悄改变该保留字节。
        if ((Snapshot->capabilityFlags &
                KSWORD_ARK_CPU_POWER_CAP_HWP_EPP) == 0ULL &&
            Request->hwpEnergyPerformancePreference !=
                Snapshot->hwpEnergyPerformancePreference) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_HWP_EPP;
            return STATUS_NOT_SUPPORTED;
        }
    }

    // Turbo Ratio 只在平台 bit 28 与 0x1AD 都可读时开放。
    if ((Request->applyFlags &
        KSWORD_ARK_CPU_POWER_APPLY_TURBO_RATIO) != 0UL) {
        // ratio 为一个 1..255 的全档位目标；还原路径可提供逐档结构化数组。
        if ((Snapshot->capabilityFlags &
                KSWORD_ARK_CPU_POWER_CAP_TURBO_RATIO_PROGRAMMABLE) == 0ULL ||
            (Snapshot->fieldFlags &
                KSWORD_ARK_CPU_POWER_FIELD_TURBO_RATIO_LIMIT) == 0UL) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_TURBO_RATIO;
            return STATUS_NOT_SUPPORTED;
        }

        // 只验证硬件当前实现的非 0 档位，禁止把 0 或截断值写入有效档位。
        BOOLEAN hasImplementedRatio = FALSE;
        for (ULONG ratioIndex = 0UL;
            ratioIndex < KSWORD_ARK_CPU_POWER_TURBO_RATIO_COUNT;
            ++ratioIndex) {
            if (Snapshot->turboRatios[ratioIndex] == 0UL) {
                continue;
            }
            hasImplementedRatio = TRUE;
            const ULONG targetRatio =
                (Request->requestFlags &
                    KSWORD_ARK_CPU_POWER_REQUEST_FLAG_TURBO_RATIO_ARRAY) != 0UL
                ? Request->turboRatios[ratioIndex]
                : Request->turboRatio;
            if (targetRatio == 0UL || targetRatio > 0xFFUL) {
                Snapshot->failureReason =
                    KSWORD_ARK_CPU_POWER_FAILURE_TURBO_RATIO;
                return STATUS_INVALID_PARAMETER;
            }
        }
        if (hasImplementedRatio == FALSE) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_TURBO_RATIO;
            return STATUS_NOT_SUPPORTED;
        }
    }

    // 请求倍频只开放 IA32_PERF_CTL[15:8]，且必须通过 EIST 能力与可读性探测。
    if ((Request->applyFlags &
        KSWORD_ARK_CPU_POWER_APPLY_PERF_CONTROL) != 0UL) {
        if ((Snapshot->capabilityFlags &
                KSWORD_ARK_CPU_POWER_CAP_PERF_CONTROL_PROGRAMMABLE) == 0ULL ||
            (Snapshot->fieldFlags &
                KSWORD_ARK_CPU_POWER_FIELD_PERF_CONTROL) == 0UL ||
            Request->requestedMultiplier == 0UL ||
            Request->requestedMultiplier > 0xFFUL) {
            Snapshot->failureReason =
                KSWORD_ARK_CPU_POWER_FAILURE_PERF_CONTROL;
            return STATUS_NOT_SUPPORTED;
        }
    }

    // 最后执行 optimistic snapshot 比较。
    return KswordARKCpuPowerValidateExpectedSnapshot(Request, Snapshot);
}

// KswordARKCpuPowerBuildPackageLimit：保留时间窗/保留位，只替换 PL1/PL2 值和开关。
static NTSTATUS
KswordARKCpuPowerBuildPackageLimit(
    _In_ const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* Request,
    _In_ ULONG PowerUnitMicrowatts,
    _In_ ULONGLONG CurrentValue,
    _Out_ ULONGLONG* NewValue
    )
{
    // rawPl1/rawPl2 接收验证后的 15 位单位值。
    ULONGLONG rawPl1 = 0ULL;
    ULONGLONG rawPl2 = 0ULL;
    // status 保存每次编码结果。
    NTSTATUS status = STATUS_SUCCESS;
    // 低高两个 17 位区间覆盖值、enable 与 clamp。
    const ULONGLONG firstMask = 0x1FFFFULL;
    const ULONGLONG secondMask = 0x1FFFFULL <<
        KSW_CPU_POWER_LIMIT_SECOND_SHIFT;

    // 分别编码 PL1 与 PL2。
    status = KswordARKCpuPowerMilliwattsToRaw(
        Request->pl1Milliwatts,
        PowerUnitMicrowatts,
        &rawPl1);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordARKCpuPowerMilliwattsToRaw(
        Request->pl2Milliwatts,
        PowerUnitMicrowatts,
        &rawPl2);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 先清除两个可控 17 位区域，保留时间窗、lock 与保留位。
    *NewValue = CurrentValue & ~(firstMask | secondMask);
    // 写入 PL1 原始值。
    *NewValue |= rawPl1;
    // 按请求写入 PL1 enable/clamp。
    *NewValue |= ((ULONGLONG)Request->pl1Enabled) <<
        KSW_CPU_POWER_LIMIT_ENABLE_BIT;
    *NewValue |= ((ULONGLONG)Request->pl1ClampEnabled) <<
        KSW_CPU_POWER_LIMIT_CLAMP_BIT;
    // 写入 PL2 原始值与两个开关。
    *NewValue |= rawPl2 << KSW_CPU_POWER_LIMIT_SECOND_SHIFT;
    *NewValue |= ((ULONGLONG)Request->pl2Enabled) <<
        KSW_CPU_POWER_LIMIT_SECOND_ENABLE;
    *NewValue |= ((ULONGLONG)Request->pl2ClampEnabled) <<
        KSW_CPU_POWER_LIMIT_SECOND_CLAMP;
    // 不允许构造过程改变 lock 位。
    if (((*NewValue ^ CurrentValue) &
        (1ULL << KSW_CPU_POWER_LIMIT_LOCK_BIT)) != 0ULL) {
        return STATUS_DATA_ERROR;
    }

    // 返回完整新值。
    return STATUS_SUCCESS;
}

// KswordARKCpuPowerApplyCurrentProcessor：在当前已绑定逻辑处理器执行白名单修改并回读。
static NTSTATUS
KswordARKCpuPowerApplyCurrentProcessor(
    _In_ const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* Request,
    _In_ const KSWORD_ARK_CPU_POWER_RESPONSE* Snapshot
    )
{
    // currentValue/newValue/readbackValue 复用于每个串行 MSR 操作。
    ULONGLONG currentValue = 0ULL;
    ULONGLONG newValue = 0ULL;
    ULONGLONG readbackValue = 0ULL;
    // status 保存每个读取、构造和写入状态。
    NTSTATUS status = STATUS_SUCCESS;

    // RAPL package limit 修改保留两个 time window、lock 与所有保留位。
    if ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_POWER_LIMITS) != 0UL) {
        // 每个处理器重新读取，兼容多 package 系统的独立当前值。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_PACKAGE_POWER_LIMIT,
            &currentValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // 任一 package 已锁定都拒绝对该处理器写入。
        if (((currentValue >> KSW_CPU_POWER_LIMIT_LOCK_BIT) & 1ULL) != 0ULL) {
            return STATUS_ACCESS_DENIED;
        }
        // 只替换结构化可控字段。
        status = KswordARKCpuPowerBuildPackageLimit(
            Request,
            Snapshot->powerUnitMicrowatts,
            currentValue,
            &newValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // 写入完整 read-modify-write 结果。
        status = KswordARKCpuPowerWriteMsr(
            KSW_CPU_POWER_MSR_PACKAGE_POWER_LIMIT,
            newValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // 立即回读并验证两个 17 位可控区。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_PACKAGE_POWER_LIMIT,
            &readbackValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (((readbackValue ^ newValue) &
            (0x1FFFFULL | (0x1FFFFULL <<
                KSW_CPU_POWER_LIMIT_SECOND_SHIFT))) != 0ULL) {
            return STATUS_DATA_ERROR;
        }
    }

    // Turbo 开关只改变 IA32_MISC_ENABLE[38]。
    if ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_TURBO) != 0UL) {
        // 读取该逻辑处理器当前完整值。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_MISC_ENABLE,
            &currentValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // 启用 Turbo 时清除 disable 位，禁用时设置该位。
        newValue = Request->turboEnabled != 0UL
            ? currentValue & ~(1ULL << KSW_CPU_POWER_MISC_TURBO_DISABLE_BIT)
            : currentValue | (1ULL << KSW_CPU_POWER_MISC_TURBO_DISABLE_BIT);
        // 写入只变更一个架构位的完整值。
        status = KswordARKCpuPowerWriteMsr(
            KSW_CPU_POWER_MSR_MISC_ENABLE,
            newValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // 回读验证 bit 38，其他固件并发变化不误判为本次失败。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_MISC_ENABLE,
            &readbackValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (((readbackValue ^ newValue) &
            (1ULL << KSW_CPU_POWER_MISC_TURBO_DISABLE_BIT)) != 0ULL) {
            return STATUS_DATA_ERROR;
        }
    }

    // 请求倍频只替换 IA32_PERF_CTL[15:8]，保留电压及所有型号相关位。
    if ((Request->applyFlags &
        KSWORD_ARK_CPU_POWER_APPLY_PERF_CONTROL) != 0UL) {
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_PERF_CONTROL,
            &currentValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        newValue = currentValue & ~KSW_CPU_POWER_PERF_RATIO_MASK;
        newValue |= ((ULONGLONG)Request->requestedMultiplier) <<
            KSW_CPU_POWER_PERF_RATIO_SHIFT;
        status = KswordARKCpuPowerWriteMsr(
            KSW_CPU_POWER_MSR_PERF_CONTROL,
            newValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_PERF_CONTROL,
            &readbackValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (((readbackValue ^ newValue) &
            KSW_CPU_POWER_PERF_RATIO_MASK) != 0ULL) {
            return STATUS_DATA_ERROR;
        }
    }

    // HWP request 是每逻辑处理器状态，因此必须逐处理器更新。
    if ((Request->applyFlags & KSWORD_ARK_CPU_POWER_APPLY_HWP) != 0UL) {
        // 读取当前处理器请求并保留高 32 位 package/control 字段。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_HWP_REQUEST,
            &currentValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // 清除 min/max/desired 三个字节。
        newValue = currentValue & ~0x0000000000FFFFFFULL;
        // 写入三个结构化性能请求字节。
        newValue |= (ULONGLONG)Request->hwpMinimumPerformance;
        newValue |= ((ULONGLONG)Request->hwpMaximumPerformance) << 8U;
        newValue |= ((ULONGLONG)Request->hwpDesiredPerformance) << 16U;
        // 只有 CPUID 宣告 EPP 时才替换 EPP 字节。
        if ((Snapshot->capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_HWP_EPP) != 0ULL) {
            newValue &= ~0x00000000FF000000ULL;
            newValue |=
                ((ULONGLONG)Request->hwpEnergyPerformancePreference) << 24U;
        }
        // 写入当前逻辑处理器的 HWP request。
        status = KswordARKCpuPowerWriteMsr(
            KSW_CPU_POWER_MSR_HWP_REQUEST,
            newValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // 回读低 24 或 32 位验证实际接受值。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_HWP_REQUEST,
            &readbackValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // verifyMask 根据 EPP 能力选择验证范围。
        const ULONGLONG verifyMask =
            (Snapshot->capabilityFlags &
                KSWORD_ARK_CPU_POWER_CAP_HWP_EPP) != 0ULL
            ? 0x00000000FFFFFFFFULL
            : 0x0000000000FFFFFFULL;
        // 固件未接受请求时返回数据错误。
        if (((readbackValue ^ newValue) & verifyMask) != 0ULL) {
            return STATUS_DATA_ERROR;
        }
    }

    // Turbo Ratio Limit 仅替换当前 MSR 中已经实现的非 0 档位。
    if ((Request->applyFlags &
        KSWORD_ARK_CPU_POWER_APPLY_TURBO_RATIO) != 0UL) {
        // 读取当前 package 的 1..8 核档位。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_TURBO_RATIO_LIMIT,
            &currentValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // newValue 从当前值开始，避免写入未实现的 0 档位。
        newValue = currentValue;
        // changedMask 只覆盖原本非 0 的档位。
        ULONGLONG changedMask = 0ULL;
        // 遍历架构定义的八个 ratio 字节。
        for (ULONG ratioIndex = 0UL;
            ratioIndex < KSWORD_ARK_CPU_POWER_TURBO_RATIO_COUNT;
            ++ratioIndex) {
            // shift 是当前档位字节偏移。
            const ULONG shift = ratioIndex * 8U;
            // 当前字节为 0 时保持未实现状态。
            if (((currentValue >> shift) & 0xFFULL) == 0ULL) {
                continue;
            }
            // 普通操作写入同一目标；还原操作按结构化数组恢复每个档位。
            const ULONG targetRatio =
                (Request->requestFlags &
                    KSWORD_ARK_CPU_POWER_REQUEST_FLAG_TURBO_RATIO_ARRAY) != 0UL
                ? Request->turboRatios[ratioIndex]
                : Request->turboRatio;
            newValue &= ~(0xFFULL << shift);
            newValue |= ((ULONGLONG)targetRatio) << shift;
            // 记录该字节用于写后验证。
            changedMask |= 0xFFULL << shift;
        }
        // 没有实现任何档位时拒绝构造猜测值。
        if (changedMask == 0ULL) {
            return STATUS_NOT_SUPPORTED;
        }
        // 写入 package Turbo Ratio Limit。
        status = KswordARKCpuPowerWriteMsr(
            KSW_CPU_POWER_MSR_TURBO_RATIO_LIMIT,
            newValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // 回读所有受影响档位。
        status = KswordARKCpuPowerReadMsr(
            KSW_CPU_POWER_MSR_TURBO_RATIO_LIMIT,
            &readbackValue);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (((readbackValue ^ newValue) & changedMask) != 0ULL) {
            return STATUS_DATA_ERROR;
        }
    }

    // 当前逻辑处理器的所有请求字段均完成回读验证。
    return STATUS_SUCCESS;
}

// KswordARKCpuPowerApplyAllProcessors：在 PASSIVE_LEVEL 逐组绑定并更新所有活动处理器。
static NTSTATUS
KswordARKCpuPowerApplyAllProcessors(
    _In_ const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* Request,
    _In_ const KSWORD_ARK_CPU_POWER_RESPONSE* Snapshot,
    _Out_ ULONG* UpdatedProcessorCount,
    _Out_ ULONG* FailedProcessorCount
    )
{
    // groupCount 是当前活动处理器组数量。
    const USHORT groupCount = KeQueryActiveGroupCount();
    // firstFailure 保留第一条失败状态，循环仍继续覆盖其他 package/core。
    NTSTATUS firstFailure = STATUS_SUCCESS;

    // 初始化计数输出。
    *UpdatedProcessorCount = 0UL;
    *FailedProcessorCount = 0UL;

    // 遍历每个活动处理器组。
    for (USHORT groupIndex = 0U; groupIndex < groupCount; ++groupIndex) {
        // processorCount 是当前组的活动逻辑处理器数。
        const ULONG processorCount =
            KeQueryActiveProcessorCountEx(groupIndex);
        // 遍历组内所有活动处理器编号。
        for (ULONG processorIndex = 0UL;
            processorIndex < processorCount;
            ++processorIndex) {
            // targetAffinity 精确绑定当前系统线程到一个逻辑处理器。
            GROUP_AFFINITY targetAffinity;
            // previousAffinity 用于无条件恢复调用线程原亲和性。
            GROUP_AFFINITY previousAffinity;
            // status 接收当前逻辑处理器的完整修改结果。
            NTSTATUS status = STATUS_SUCCESS;

            // KAFFINITY 无法表达的编号明确计为失败。
            if (processorIndex >= sizeof(KAFFINITY) * 8UL) {
                ++(*FailedProcessorCount);
                if (NT_SUCCESS(firstFailure)) {
                    firstFailure = STATUS_NOT_SUPPORTED;
                }
                continue;
            }

            // 清零两个 affinity 结构，保留字段不会携带栈垃圾。
            RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
            RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
            // 设置目标组与单处理器掩码。
            targetAffinity.Group = groupIndex;
            targetAffinity.Mask = ((KAFFINITY)1) << processorIndex;
            // 将当前系统线程绑定到目标处理器。
            KeSetSystemGroupAffinityThread(
                &targetAffinity,
                &previousAffinity);
            // 在目标处理器执行白名单 read-modify-write 和回读。
            status = KswordARKCpuPowerApplyCurrentProcessor(
                Request,
                Snapshot);
            // 无论结果如何都恢复调用线程亲和性。
            KeRevertToUserGroupAffinityThread(&previousAffinity);

            // 分别累计成功与失败处理器。
            if (NT_SUCCESS(status)) {
                ++(*UpdatedProcessorCount);
            }
            else {
                ++(*FailedProcessorCount);
                if (NT_SUCCESS(firstFailure)) {
                    firstFailure = status;
                }
            }
        }
    }

    // 没有任何处理器被更新时返回明确失败。
    if (*UpdatedProcessorCount == 0UL && NT_SUCCESS(firstFailure)) {
        firstFailure = STATUS_NOT_FOUND;
    }
    // 返回第一条失败，全部成功时为 STATUS_SUCCESS。
    return firstFailure;
}

// KswordARKCpuPowerApply：串行化验证、跨处理器修改并发布最终回读快照。
NTSTATUS
KswordARKCpuPowerApply(
    _In_ const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST* Request,
    _Out_ KSWORD_ARK_CPU_POWER_RESPONSE* Response
    )
{
    // status 接收验证、写入和最终查询结果。
    NTSTATUS status = STATUS_SUCCESS;
    // updatedCount/failedCount 在最终回读覆盖响应前单独保存。
    ULONG updatedCount = 0UL;
    ULONG failedCount = 0UL;

    // 公开入口先验证指针，协议字段在锁内继续验证。
    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    // MSR 写入只允许在 PASSIVE_LEVEL 的系统线程上下文执行。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // 排他锁覆盖初始快照、所有处理器写入与最终回读。
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_KswordCpuPowerLock);

    // 先采样当前状态，所有能力与 expected 比较都基于同一锁内快照。
    status = KswordARKCpuPowerQuerySnapshotUnlocked(Response);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    // 执行协议头、能力、数值、锁定位和 optimistic snapshot 校验。
    status = KswordARKCpuPowerValidateRequest(Request, Response);
    if (!NT_SUCCESS(status)) {
        Response->lastStatus = status;
        goto Exit;
    }

    // 逐组更新所有活动逻辑处理器。
    status = KswordARKCpuPowerApplyAllProcessors(
        Request,
        Response,
        &updatedCount,
        &failedCount);
    if (!NT_SUCCESS(status)) {
        // 写入阶段失败与参数校验失败必须在固定响应中可区分。
        Response->failureReason =
            KSWORD_ARK_CPU_POWER_FAILURE_PROCESSOR_APPLY;
        // 部分处理器已经成功时明确标记 partial，避免 UI 宣称原子成功。
        if (updatedCount != 0UL) {
            Response->responseFlags |=
                KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_WRITE_PARTIAL;
        }
        Response->updatedProcessorCount = updatedCount;
        Response->failedProcessorCount = failedCount;
        Response->lastStatus = status;
        goto Exit;
    }

    // 全部写入成功后重新采样当前调用处理器，向 UI 返回实际回读值。
    status = KswordARKCpuPowerQuerySnapshotUnlocked(Response);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    // 恢复跨处理器计数并标记所有 worker 已完成回读验证。
    Response->updatedProcessorCount = updatedCount;
    Response->failedProcessorCount = failedCount;
    Response->responseFlags |=
        KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_WRITE_VERIFIED;
    Response->lastStatus = STATUS_SUCCESS;

Exit:
    // 对称释放排他锁与临界区。
    ExReleasePushLockExclusive(&g_KswordCpuPowerLock);
    KeLeaveCriticalRegion();
    // 返回真实语义状态；IOCTL handler 仍会设置固定响应长度。
    return status;
}
