// ============================================================
// MinidumpCodeText.cpp
// 作用：
// - 实现 MinidumpCodeText.h 声明的各类“数值 → 可读文本”释义表；
// - 表内容为静态常量数组 + 线性/哈希查找，全部线程安全（无可变状态）；
// - 常量名保持英文原文，说明文字用中文规范文本。
// ============================================================

#include "MinidumpCodeText.h"

namespace ks::minidump
{
    namespace
    {
        // CodeNamePair：一条“数值 → 常量名/说明”映射。
        struct CodeNamePair
        {
            std::uint32_t code;  // code：数值本体。
            const char* name;    // name：英文常量名（UTF-8）。
            const char* meaning; // meaning：中文说明（UTF-8），可为空指针。
        };

        // kExceptionCodes：常见 NTSTATUS 异常码表（用户态崩溃最常见的集合）。
        constexpr CodeNamePair kExceptionCodes[] = {
            { 0x80000003u, "EXCEPTION_BREAKPOINT", "断点指令（int 3）被执行，且没有调试器接管。" },
            { 0x80000004u, "EXCEPTION_SINGLE_STEP", "单步陷阱：TF 标志置位后执行了一条指令。" },
            { 0xC0000005u, "EXCEPTION_ACCESS_VIOLATION", "访问违例：读写了无权访问的虚拟地址，是最常见的崩溃原因。" },
            { 0xC0000006u, "EXCEPTION_IN_PAGE_ERROR", "换页错误：访问的页面无法从后备存储（文件/页面文件）读入。" },
            { 0xC0000008u, "STATUS_INVALID_HANDLE", "使用了无效的内核对象句柄。" },
            { 0xC000000Du, "STATUS_INVALID_PARAMETER", "向系统服务传入了无效参数。" },
            { 0xC0000017u, "STATUS_NO_MEMORY", "内存不足：无法分配所需的虚拟内存或页面文件配额。" },
            { 0xC000001Du, "EXCEPTION_ILLEGAL_INSTRUCTION", "非法指令：CPU 无法译码执行当前指令。" },
            { 0xC0000025u, "EXCEPTION_NONCONTINUABLE_EXCEPTION", "对不可继续的异常执行了继续操作。" },
            { 0xC0000026u, "EXCEPTION_INVALID_DISPOSITION", "异常处理器返回了无效的处置值。" },
            { 0xC000008Cu, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED", "数组越界（BOUND 指令检查失败）。" },
            { 0xC000008Du, "EXCEPTION_FLT_DENORMAL_OPERAND", "浮点异常：操作数为非规格化数。" },
            { 0xC000008Eu, "EXCEPTION_FLT_DIVIDE_BY_ZERO", "浮点除零。" },
            { 0xC000008Fu, "EXCEPTION_FLT_INEXACT_RESULT", "浮点结果无法精确表示。" },
            { 0xC0000090u, "EXCEPTION_FLT_INVALID_OPERATION", "无效的浮点操作。" },
            { 0xC0000091u, "EXCEPTION_FLT_OVERFLOW", "浮点上溢。" },
            { 0xC0000092u, "EXCEPTION_FLT_STACK_CHECK", "浮点栈检查失败。" },
            { 0xC0000093u, "EXCEPTION_FLT_UNDERFLOW", "浮点下溢。" },
            { 0xC0000094u, "EXCEPTION_INT_DIVIDE_BY_ZERO", "整数除零。" },
            { 0xC0000095u, "EXCEPTION_INT_OVERFLOW", "整数运算溢出（INTO 指令触发）。" },
            { 0xC0000096u, "EXCEPTION_PRIV_INSTRUCTION", "特权指令：在用户态执行了需要内核权限的指令。" },
            { 0xC00000FDu, "EXCEPTION_STACK_OVERFLOW", "线程栈溢出：通常由无限递归或超大栈上分配导致。" },
            { 0xC0000135u, "STATUS_DLL_NOT_FOUND", "找不到需要加载的 DLL。" },
            { 0xC0000138u, "STATUS_ORDINAL_NOT_FOUND", "按序号导入的函数在目标 DLL 中不存在。" },
            { 0xC0000139u, "STATUS_ENTRYPOINT_NOT_FOUND", "按名称导入的函数在目标 DLL 中不存在。" },
            { 0xC0000142u, "STATUS_DLL_INIT_FAILED", "DLL 初始化（DllMain）返回失败。" },
            { 0xC00002B4u, "STATUS_FLOAT_MULTIPLE_FAULTS", "多重浮点故障。" },
            { 0xC00002B5u, "STATUS_FLOAT_MULTIPLE_TRAPS", "多重浮点陷阱。" },
            { 0xC0000374u, "STATUS_HEAP_CORRUPTION", "堆损坏：堆管理器检测到堆结构被破坏（常见于越界写/双重释放）。" },
            { 0xC0000409u, "STATUS_STACK_BUFFER_OVERRUN", "栈缓冲区被破坏或 fail-fast：GS 安全检查、__fastfail 等主动终止。" },
            { 0xC0000417u, "STATUS_INVALID_CRUNTIME_PARAMETER", "CRT 检测到无效参数并主动终止进程。" },
            { 0xC0000420u, "STATUS_ASSERTION_FAILURE", "断言失败（NT_ASSERT）。" },
            // 以下为用户态崩溃里同样常见、但不属于经典 NTSTATUS 区段的异常码。
            { 0x40000015u, "STATUS_FATAL_APP_EXIT", "应用程序主动致命退出。" },
            { 0x4000001Eu, "STATUS_WX86_SINGLE_STEP", "WOW64 子系统中的单步陷阱。" },
            { 0x4000001Fu, "STATUS_WX86_BREAKPOINT", "WOW64 子系统中的断点：32 位进程在 64 位系统上命中 int 3。" },
            { 0x40010005u, "DBG_CONTROL_C", "调试器收到 Ctrl+C。" },
            { 0x40010006u, "DBG_PRINTEXCEPTION_C", "OutputDebugStringA 产生的调试输出异常，不是崩溃。" },
            { 0x4001000Au, "DBG_PRINTEXCEPTION_WIDE_C", "OutputDebugStringW 产生的调试输出异常，不是崩溃。" },
            { 0x406D1388u, "MS_VC_EXCEPTION", "Visual C++ 线程命名异常：调试器用来设置线程名，不是崩溃。" },
            { 0x80000001u, "STATUS_GUARD_PAGE_VIOLATION", "访问了守卫页（PAGE_GUARD）：线程栈自动扩展由内核内部处理、不会落进转储，转储里见到它基本都是自建的守卫页（写屏障、内存池、反调试）被触碰。" },
            { 0x80000002u, "STATUS_DATATYPE_MISALIGNMENT", "数据未按要求对齐。" },
            { 0xC0000018u, "STATUS_CONFLICTING_ADDRESSES", "映射地址冲突。" },
            { 0xC0000027u, "STATUS_UNWIND", "栈展开过程中的内部状态。" },
            { 0xC0000029u, "STATUS_INVALID_UNWIND_TARGET", "非法的栈展开目标：栈上的展开信息已被破坏。" },
            { 0xC000007Bu, "STATUS_INVALID_IMAGE_FORMAT", "映像格式非法：多为 32/64 位混用或文件损坏。" },
            { 0xC00000BBu, "STATUS_NOT_SUPPORTED", "请求的操作不受支持。" },
            { 0xC0000143u, "STATUS_DLL_INIT_FAILED_LOGOFF", "注销过程中 DLL 初始化失败。" },
            { 0xC0000194u, "STATUS_POSSIBLE_DEADLOCK", "检测到可能的死锁（临界区等待超时）。" },
            { 0xC000041Du, "STATUS_FATAL_USER_CALLBACK_EXCEPTION", "用户回调（窗口过程等）中抛出了致命异常。" },
            { 0xC0000602u, "STATUS_FAIL_FAST_EXCEPTION", "主动致命退出（__fastfail）：参数 1 的子码说明触发了哪条安全检查。" },
            { 0xC0000606u, "STATUS_STACK_BUFFER_OVERRUN_FAILFAST", "栈缓冲区溢出触发的致命退出。" },
            { 0xC06D007Eu, "STATUS_MOD_NOT_FOUND", "延迟加载失败：找不到模块。" },
            { 0xC06D007Fu, "STATUS_PROC_NOT_FOUND", "延迟加载失败：模块中找不到导出函数。" },
            { 0xE0434352u, "CLR_EXCEPTION", ".NET 运行时抛出的托管异常（未被托管代码接住）。" },
            { 0xE0434F4Du, "CLR_EXCEPTION_LEGACY", "旧版 .NET 运行时的托管异常。" },
            { 0xE0464C57u, "WINRT_ORIGINATE_ERROR", "WinRT 错误起源标记，不一定是崩溃点。" },
            { 0xE06D7363u, "CPP_EH_EXCEPTION", "MSVC C++ 异常（throw）：崩溃点是抛出位置，真正的缺陷通常在更上游。" },
        };

        // FastFailPair：一条 __fastfail 子码释义。
        struct FastFailPair
        {
            std::uint32_t code; // code：FAST_FAIL_* 子码。
            const char* name;   // name：常量名。
            const char* text;   // text：中文说明。
        };

        // kFastFailCodes：__fastfail 子码表（winnt.h 的 FAST_FAIL_* 常量族）。
        // 0xC0000409 / 0xC0000602 的参数 1 就是它，直接说明触发了哪条安全检查。
        constexpr FastFailPair kFastFailCodes[] = {
            { 0u, "FAST_FAIL_LEGACY_GS_VIOLATION",
              "旧式 /GS 栈保护检查失败的通用值（未细分子类型），等同于栈上缓冲区被写越界。" },
            { 1u, "FAST_FAIL_VTGUARD_CHECK_FAILURE",
              "VTGuard 虚表守卫校验失败：对象的虚表指针被改写，是释放后使用或类型混淆的典型特征。" },
            { 2u, "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE",
              "/GS 栈 cookie 与函数入口保存的值不符——货真价实的栈缓冲区溢出；查崩溃函数里的局部数组与 memcpy/strcpy 即可锁定。" },
            { 3u, "FAST_FAIL_CORRUPT_LIST_ENTRY",
              "LIST_ENTRY 双向链表自洽性检查失败：多为链表节点被越界写，或节点已释放却仍挂在链上。" },
            { 4u, "FAST_FAIL_INCORRECT_STACK",
              "当前栈指针不在预期的线程栈范围内，常见于栈被切换、栈帧被破坏或展开信息不一致。" },
            { 5u, "FAST_FAIL_INVALID_ARG",
              "内部接口收到了不可能出现的参数值，通常意味着调用方的数据结构已经损坏。" },
            { 6u, "FAST_FAIL_GS_COOKIE_INIT",
              "模块加载时 /GS 全局安全 cookie 初始化失败或被改写。" },
            { 7u, "FAST_FAIL_FATAL_APP_EXIT",
              "应用主动致命退出：abort、std::terminate、未捕获异常经 CRT 兜底以及 CRT 的非法参数处理器都汇聚到这里；它表示程序自己决定退出，不是内存破坏，要往上一层找是哪段逻辑调用的。" },
            { 8u, "FAST_FAIL_RANGE_CHECK_FAILURE",
              "编译器插入的范围检查失败，例如 switch 跳转表索引越界。" },
            { 9u, "FAST_FAIL_UNSAFE_REGISTRY_ACCESS",
              "以不安全的方式访问了注册表。" },
            { 10u, "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE",
              "控制流防护（CFG）判定间接调用目标不是合法函数入口：要么函数指针或虚表被改写，要么钩子与注入类软件改了调用目标。" },
            { 11u, "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE",
              "控制流防护写检查失败：受保护的只读数据被写入。" },
            { 12u, "FAST_FAIL_INVALID_FIBER_SWITCH",
              "非法的纤程切换：在错误的线程或错误的状态下调用了 SwitchToFiber。" },
            { 13u, "FAST_FAIL_INVALID_SET_OF_CONTEXT",
              "设置线程上下文的内容非法，常见于注入或热补丁类代码修改线程上下文。" },
            { 14u, "FAST_FAIL_INVALID_REFERENCE_COUNT",
              "引用计数出现不可能的值（通常是减到 0 之后再减），指向提前释放或重复 Release。" },
            { 18u, "FAST_FAIL_INVALID_JUMP_BUFFER",
              "longjmp 的 jmp_buf 内容非法或已被破坏，含 setjmp 帧返回之后再 longjmp 的情况。" },
            { 19u, "FAST_FAIL_MRDATA_MODIFIED",
              "只读可变数据段（.mrdata）在受保护期间被修改，常见于试图改写导入表或回调表的行为。" },
            { 20u, "FAST_FAIL_CERTIFICATION_FAILURE",
              "证书或签名校验失败。" },
            { 21u, "FAST_FAIL_INVALID_EXCEPTION_CHAIN",
              "SEH 异常处理链不自洽，是 x86 上栈溢出改写 SEH 链的经典特征。" },
            { 22u, "FAST_FAIL_CRYPTO_LIBRARY",
              "加密库自检或内部一致性检查失败。" },
            { 23u, "FAST_FAIL_INVALID_CALL_IN_DLL_CALLOUT",
              "在加载器锁持有期间（DllMain 等回调里）调用了被禁止的接口，属于死锁高危行为。" },
            { 24u, "FAST_FAIL_INVALID_IMAGE_BASE",
              "映像基址非法。" },
            { 25u, "FAST_FAIL_DLOAD_PROTECTION_FAILURE",
              "延迟加载保护机制失败。" },
            { 26u, "FAST_FAIL_UNSAFE_EXTENSION_CALL",
              "调用了被判定为不安全的扩展或插件入口。" },
            { 27u, "FAST_FAIL_DEPRECATED_SERVICE_INVOKED",
              "调用了已废弃的系统服务。" },
            { 28u, "FAST_FAIL_INVALID_BUFFER_ACCESS",
              "缓冲区访问越界，由带边界信息的内部接口检出。" },
            { 29u, "FAST_FAIL_INVALID_BALANCED_TREE",
              "平衡树结构不自洽，多为节点内存被破坏。" },
            { 30u, "FAST_FAIL_INVALID_NEXT_THREAD",
              "调度器取到了非法的下一个线程对象。" },
            { 31u, "FAST_FAIL_GUARD_ICALL_CHECK_SUPPRESSED",
              "控制流防护的间接调用命中了被抑制的导出目标；头文件标注为遥测且不致命，只上报不终止进程，一般不是崩溃根因。" },
            { 32u, "FAST_FAIL_APCS_DISABLED",
              "在 APC 被禁用的状态下执行了需要 APC 的操作。" },
            { 33u, "FAST_FAIL_INVALID_IDLE_STATE",
              "非法的空闲状态转换。" },
            { 34u, "FAST_FAIL_MRDATA_PROTECTION_FAILURE",
              "为 .mrdata 重新加只读保护失败。" },
            { 35u, "FAST_FAIL_UNEXPECTED_HEAP_EXCEPTION",
              "堆内部抛出了预期之外的异常，绝大多数情况下仍然是堆元数据被破坏。" },
            { 36u, "FAST_FAIL_INVALID_LOCK_STATE",
              "锁状态非法：未持有就释放、重复释放，或锁对象内存被覆盖。" },
            { 37u, "FAST_FAIL_GUARD_JUMPTABLE",
              "控制流防护的跳转表校验失败。" },
            { 38u, "FAST_FAIL_INVALID_LONGJUMP_TARGET",
              "longjmp 目标不在编译期登记的合法目标表内（CFG 对 longjmp 的加固）。" },
            { 39u, "FAST_FAIL_INVALID_DISPATCH_CONTEXT",
              "异常分发上下文非法，通常伴随栈或展开数据损坏。" },
            { 40u, "FAST_FAIL_INVALID_THREAD",
              "线程对象非法。" },
            { 41u, "FAST_FAIL_INVALID_SYSCALL_NUMBER",
              "系统调用号非法，常见于绕过 ntdll 的直接系统调用在新版本上号变了，或 ntdll 被挂钩篡改；头文件标注为遥测且不致命。" },
            { 42u, "FAST_FAIL_INVALID_FILE_OPERATION",
              "非法的文件操作；头文件标注为遥测且不致命。" },
            { 43u, "FAST_FAIL_LPAC_ACCESS_DENIED",
              "低权限应用容器下访问被拒；头文件标注为遥测且不致命。" },
            { 44u, "FAST_FAIL_GUARD_SS_FAILURE",
              "影子栈（Intel CET）校验失败：返回地址与影子栈中的副本不一致，即返回地址被改写，也可能是不兼容的钩子篡改了栈。" },
            { 45u, "FAST_FAIL_LOADER_CONTINUITY_FAILURE",
              "加载器完整性校验失败，加载了不符合策略的映像；头文件标注为遥测且不致命。" },
            { 46u, "FAST_FAIL_GUARD_EXPORT_SUPPRESSION_FAILURE",
              "导出抑制校验失败。" },
            { 47u, "FAST_FAIL_INVALID_CONTROL_STACK",
              "控制栈（影子栈）内容非法。" },
            { 48u, "FAST_FAIL_SET_CONTEXT_DENIED",
              "设置线程上下文的请求被安全策略拒绝。" },
            { 49u, "FAST_FAIL_INVALID_IAT",
              "导入地址表被改写，最常见于 IAT 钩子与新式加固机制冲突。" },
            { 50u, "FAST_FAIL_HEAP_METADATA_CORRUPTION",
              "堆元数据损坏，由段堆或 NT 堆的加固检查检出，与 0xC0000374 同源。" },
            { 51u, "FAST_FAIL_PAYLOAD_RESTRICTION_VIOLATION",
              "违反了漏洞利用防护的载荷限制策略，例如禁止加载远程映像或非微软签名的二进制；多由系统与企业策略触发，而非程序缺陷。" },
            { 52u, "FAST_FAIL_LOW_LABEL_ACCESS_DENIED",
              "访问低完整性标签的对象被拒；头文件标注为遥测且不致命。" },
            { 53u, "FAST_FAIL_ENCLAVE_CALL_FAILURE",
              "飞地（Enclave）调用失败。" },
            { 54u, "FAST_FAIL_UNHANDLED_LSS_EXCEPTON",
              "LSS 相关的未处理异常；官方头文件里的拼写本身就少一个字母，做名称比对时不要改。" },
            { 55u, "FAST_FAIL_ADMINLESS_ACCESS_DENIED",
              "Adminless 模式下的访问被拒；头文件标注为遥测且不致命。" },
            { 56u, "FAST_FAIL_UNEXPECTED_CALL",
              "出现了不应发生的调用，走到了理论上不可达的分支。" },
            { 57u, "FAST_FAIL_CONTROL_INVALID_RETURN_ADDRESS",
              "返回地址校验失败，与影子栈及返回地址保护相关。" },
            { 58u, "FAST_FAIL_UNEXPECTED_HOST_BEHAVIOR",
              "虚拟化宿主行为异常：客户机检测到宿主返回了不合理的结果。" },
            { 59u, "FAST_FAIL_FLAGS_CORRUPTION",
              "内部标志位被破坏。" },
            { 60u, "FAST_FAIL_VEH_CORRUPTION",
              "向量化异常处理器链被破坏，常见于注入类软件挂了 VEH 之后被卸载或内存被回收。" },
            { 61u, "FAST_FAIL_ETW_CORRUPTION",
              "ETW 相关结构被破坏，常见于试图修改 ETW 以躲避监控的代码。" },
            { 62u, "FAST_FAIL_RIO_ABORT",
              "注册式 I/O 被中止。" },
            { 63u, "FAST_FAIL_INVALID_PFN",
              "页帧号非法，属于内核侧检查。" },
            { 64u, "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE_XFG",
              "扩展控制流防护（XFG）间接调用检查失败：调用目标的函数签名哈希与调用点不符；比 CFG 更严格，误报多来自不兼容的钩子与老式 detour。" },
            { 65u, "FAST_FAIL_CAST_GUARD",
              "CastGuard 检出非法的 C++ 向下转型：static_cast 到了实际并非该类型的对象。" },
            { 66u, "FAST_FAIL_HOST_VISIBILITY_CHANGE",
              "虚拟化或隔离场景下内存对宿主的可见性发生了非预期变化。" },
            { 67u, "FAST_FAIL_KERNEL_CET_SHADOW_STACK_ASSIST",
              "内核 CET 影子栈辅助路径失败，属于内核侧检查。" },
            { 68u, "FAST_FAIL_PATCH_CALLBACK_FAILED",
              "热补丁回调执行失败。" },
            { 69u, "FAST_FAIL_NTDLL_PATCH_FAILED",
              "对 ntdll 的补丁应用失败。" },
            { 70u, "FAST_FAIL_INVALID_FLS_DATA",
              "纤程本地存储数据非法或被破坏。" },
            { 71u, "FAST_FAIL_ASAN_ERROR",
              "AddressSanitizer 检出错误后走 fastfail 终止；真正的越界与释放后使用细节在 ASan 自己的报告里，不在异常参数中。" },
            { 72u, "FAST_FAIL_CLR_EXCEPTION_AOT",
              "NativeAOT 形态的 .NET 运行时抛出异常后走 fastfail 终止。" },
            { 73u, "FAST_FAIL_POINTER_AUTH_INVALID_RETURN_ADDRESS",
              "ARM64 指针认证校验返回地址失败：返回地址被改写或签名不匹配。" },
            { 74u, "FAST_FAIL_INVALID_THREAD_STATE",
              "线程状态非法。" },
            { 75u, "FAST_FAIL_CORRUPT_WOW64_STATE",
              "WOW64 线程状态被破坏（64 位系统上的 32 位进程）。" },
            { 76u, "FAST_FAIL_INVALID_EXTENDED_STATE",
              "扩展处理器状态（XSAVE 区域）非法。" },
            { 77u, "FAST_FAIL_KERNEL_POINTER_EXPECTED",
              "期望内核指针却拿到了非内核指针，属于内核侧检查。" },
            { 4294967295u, "FAST_FAIL_INVALID_FAST_FAIL_CODE",
              "占位值：调用方传入的 __fastfail 代码本身不合法。" },
        };


        // FindPair 作用：在映射表内线性查找数值；表都很小，线性查找足够快。
        // 传入表指针 pairs、表长 count 与目标 code；返回命中的表项或 nullptr。
        const CodeNamePair* FindPair(
            const CodeNamePair* const pairs,
            const std::size_t count,
            const std::uint32_t code)
        {
            for (std::size_t index = 0; index < count; ++index)
            {
                if (pairs[index].code == code)
                {
                    return &pairs[index];
                }
            }
            return nullptr;
        }
    }

    QString ExceptionCodeName(const std::uint32_t code)
    {
        // pair：命中的异常码表项；未命中时返回空串交由调用方兜底。
        const CodeNamePair* const pair = FindPair(
            kExceptionCodes,
            sizeof(kExceptionCodes) / sizeof(kExceptionCodes[0]),
            code);
        return pair != nullptr ? QString::fromUtf8(pair->name) : QString();
    }

    QString ExceptionCodeMeaning(const std::uint32_t code)
    {
        // pair：命中的异常码表项；meaning 为空指针时同样返回空串。
        const CodeNamePair* const pair = FindPair(
            kExceptionCodes,
            sizeof(kExceptionCodes) / sizeof(kExceptionCodes[0]),
            code);
        if (pair == nullptr || pair->meaning == nullptr)
        {
            return QString();
        }
        return QString::fromUtf8(pair->meaning);
    }

    QString AccessViolationDetailText(
        const std::uint64_t operationType,
        const std::uint64_t faultAddress)
    {
        // operationText：参数 0 的标准语义（0 读 / 1 写 / 8 执行）。
        QString operationText;
        switch (operationType)
        {
        case 0: operationText = QStringLiteral("读取"); break;
        case 1: operationText = QStringLiteral("写入"); break;
        case 8: operationText = QStringLiteral("执行（DEP）"); break;
        default:
            operationText = QStringLiteral("操作类型 %1").arg(operationType);
            break;
        }
        return QStringLiteral("%1 地址 0x%2 失败")
            .arg(operationText)
            .arg(QString::number(faultAddress, 16).toUpper());
    }

    QString FastFailCodeText(const std::uint64_t code)
    {
        for (const FastFailPair& pair : kFastFailCodes)
        {
            if (pair.code == code)
            {
                return QStringLiteral("%1 —— %2")
                    .arg(QString::fromLatin1(pair.name), QString::fromUtf8(pair.text));
            }
        }
        return QString();
    }

    QString CppExceptionMagicText(const std::uint64_t magic)
    {
        // 魔数取自 MSVC 的 ehdata_values.h。实际转储里 ExceptionInformation[0]
        // 几乎恒为 EH_MAGIC_NUMBER1；另外两个值只是 PER_IS_MSVC_EH 宏为兼容而接受的，
        // 它们标记的是 FuncInfo 里哪些可选字段有效，与 ThrowInfo 布局无关
        //（ThrowInfo 任何版本都是固定 4 个字段）。
        switch (magic)
        {
        case 0x19930520ull:
            return QStringLiteral("EH_MAGIC_NUMBER1：MSVC C++ 抛出对象的标准异常记录");
        case 0x19930521ull:
            return QStringLiteral("EH_MAGIC_NUMBER2：编译期声明了异常规格列表（FuncInfo::pESTypeList 有效）");
        case 0x19930522ull:
            return QStringLiteral("EH_MAGIC_NUMBER3：编译期记录了异常处理模式（FuncInfo::EHFlags 有效，区分 /EHs 与 /EHa）");
        default:
            return QString();
        }
    }

    bool IsCppException(const std::uint32_t code)
    {
        // EH_EXCEPTION_NUMBER = 'msc' | 0xE0000000：MSVC 承载 C++ throw 的固定异常码。
        return code == 0xE06D7363u;
    }

    bool IsManagedException(const std::uint32_t code)
    {
        // 现代 CLR 观测到 0xE0434352，更早的 .NET Framework 观测到 0xE0434F4D；
        // 具体分界随运行时版本而变，两者都按托管异常处理。
        return code == 0xE0434352u || code == 0xE0434F4Du;
    }



    QString ProcessorArchitectureText(const std::uint16_t architecture)
    {
        // 编号来自 PROCESSOR_ARCHITECTURE_* 常量族。
        switch (architecture)
        {
        case 0: return QStringLiteral("x86");
        case 5: return QStringLiteral("ARM");
        case 6: return QStringLiteral("IA64");
        case 9: return QStringLiteral("x64 (AMD64)");
        case 12: return QStringLiteral("ARM64");
        default:
            return QStringLiteral("架构编号 %1").arg(architecture);
        }
    }

    QString StreamTypeName(const std::uint32_t streamType)
    {
        // 编号与 minidumpapiset.h 的 MINIDUMP_STREAM_TYPE 一一对应。
        switch (streamType)
        {
        case 0: return QStringLiteral("UnusedStream");
        case 1: return QStringLiteral("ReservedStream0");
        case 2: return QStringLiteral("ReservedStream1");
        case 3: return QStringLiteral("ThreadListStream");
        case 4: return QStringLiteral("ModuleListStream");
        case 5: return QStringLiteral("MemoryListStream");
        case 6: return QStringLiteral("ExceptionStream");
        case 7: return QStringLiteral("SystemInfoStream");
        case 8: return QStringLiteral("ThreadExListStream");
        case 9: return QStringLiteral("Memory64ListStream");
        case 10: return QStringLiteral("CommentStreamA");
        case 11: return QStringLiteral("CommentStreamW");
        case 12: return QStringLiteral("HandleDataStream");
        case 13: return QStringLiteral("FunctionTableStream");
        case 14: return QStringLiteral("UnloadedModuleListStream");
        case 15: return QStringLiteral("MiscInfoStream");
        case 16: return QStringLiteral("MemoryInfoListStream");
        case 17: return QStringLiteral("ThreadInfoListStream");
        case 18: return QStringLiteral("HandleOperationListStream");
        case 19: return QStringLiteral("TokenStream");
        case 20: return QStringLiteral("JavaScriptDataStream");
        case 21: return QStringLiteral("SystemMemoryInfoStream");
        case 22: return QStringLiteral("ProcessVmCountersStream");
        case 23: return QStringLiteral("IptTraceStream");
        case 24: return QStringLiteral("ThreadNamesStream");
        case 0x8000: return QStringLiteral("ceStreamNull");
        default:
            return QString();
        }
    }

    QString StreamTypeNote(const std::uint32_t streamType)
    {
        // 每个流一句中文用途说明，帮助不熟悉格式的用户理解目录页。
        switch (streamType)
        {
        case 3: return QStringLiteral("线程列表：每个线程的 ID、TEB、栈范围与上下文位置");
        case 4: return QStringLiteral("模块列表：加载模块的基址、大小、版本与 PDB 信息");
        case 5: return QStringLiteral("内存列表：转储中包含的内存范围（小型转储）");
        case 6: return QStringLiteral("异常信息：崩溃线程 ID、异常码、地址与参数");
        case 7: return QStringLiteral("系统信息：CPU 架构、逻辑处理器数与操作系统版本");
        case 8: return QStringLiteral("扩展线程列表：带背景通道信息的线程数组");
        case 9: return QStringLiteral("64 位内存列表：完整内存转储的数据范围目录");
        case 10: return QStringLiteral("ANSI 注释：写转储时附加的说明文字");
        case 11: return QStringLiteral("Unicode 注释：写转储时附加的说明文字");
        case 12: return QStringLiteral("句柄数据：崩溃时打开的内核对象句柄");
        case 13: return QStringLiteral("函数表：动态函数表（RtlAddFunctionTable）信息");
        case 14: return QStringLiteral("已卸载模块列表：进程生命周期内卸载过的模块");
        case 15: return QStringLiteral("杂项信息：进程 ID、启动时间、CPU 时间与频率");
        case 16: return QStringLiteral("内存信息列表：所有虚拟内存区域的状态/保护/类型");
        case 17: return QStringLiteral("线程信息列表：线程起始地址、CPU 时间与调度信息");
        case 18: return QStringLiteral("句柄操作列表：句柄跟踪（htrace）记录");
        case 19: return QStringLiteral("令牌信息：进程/线程令牌数据");
        case 21: return QStringLiteral("系统内存信息：系统级内存性能计数");
        case 22: return QStringLiteral("进程 VM 计数：进程虚拟内存统计");
        case 23: return QStringLiteral("Intel PT 跟踪数据");
        case 24: return QStringLiteral("线程名列表：线程 ID 与线程描述名");
        default:
            return QString();
        }
    }

    QString MemoryStateText(const std::uint32_t state)
    {
        // 状态值来自 VirtualQuery 的 MEM_* 常量。
        switch (state)
        {
        case 0x1000: return QStringLiteral("MEM_COMMIT");
        case 0x2000: return QStringLiteral("MEM_RESERVE");
        case 0x10000: return QStringLiteral("MEM_FREE");
        default:
            return QStringLiteral("0x%1").arg(QString::number(state, 16).toUpper());
        }
    }

    QString MemoryProtectText(const std::uint32_t protect)
    {
        if (protect == 0)
        {
            return QString();
        }
        // baseText：低 8 位的基础保护属性。
        QString baseText;
        switch (protect & 0xFFu)
        {
        case 0x01: baseText = QStringLiteral("PAGE_NOACCESS"); break;
        case 0x02: baseText = QStringLiteral("PAGE_READONLY"); break;
        case 0x04: baseText = QStringLiteral("PAGE_READWRITE"); break;
        case 0x08: baseText = QStringLiteral("PAGE_WRITECOPY"); break;
        case 0x10: baseText = QStringLiteral("PAGE_EXECUTE"); break;
        case 0x20: baseText = QStringLiteral("PAGE_EXECUTE_READ"); break;
        case 0x40: baseText = QStringLiteral("PAGE_EXECUTE_READWRITE"); break;
        case 0x80: baseText = QStringLiteral("PAGE_EXECUTE_WRITECOPY"); break;
        default:
            baseText = QStringLiteral("0x%1").arg(QString::number(protect & 0xFFu, 16).toUpper());
            break;
        }
        // 修饰位逐个追加，保持与 SDK 常量名一致。
        if ((protect & 0x100u) != 0) { baseText += QStringLiteral(" | PAGE_GUARD"); }
        if ((protect & 0x200u) != 0) { baseText += QStringLiteral(" | PAGE_NOCACHE"); }
        if ((protect & 0x400u) != 0) { baseText += QStringLiteral(" | PAGE_WRITECOMBINE"); }
        return baseText;
    }

    QString MemoryTypeText(const std::uint32_t type)
    {
        // 类型值来自 VirtualQuery 的 MEM_IMAGE/MAPPED/PRIVATE。
        switch (type)
        {
        case 0: return QString();
        case 0x1000000: return QStringLiteral("MEM_IMAGE");
        case 0x40000: return QStringLiteral("MEM_MAPPED");
        case 0x20000: return QStringLiteral("MEM_PRIVATE");
        default:
            return QStringLiteral("0x%1").arg(QString::number(type, 16).toUpper());
        }
    }
}
