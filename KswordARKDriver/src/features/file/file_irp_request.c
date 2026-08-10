/*++

Module Name:

    file_irp_request.c

Abstract:

    自建 IRP 并直接投递到文件系统设备栈的指定层。与 file_directory_query.c 的
    Zw* 路径互为对照：Zw* 请求从栈顶进入，必然经过 FltMgr 与全部 legacy filter；
    本模块允许把同一个语义请求投递到 IoGetBaseFileSystemDeviceObject 或
    VPB->DeviceObject，从而让 R3 用差集判断"哪些条目只有绕过过滤层才可见"。

    本模块不接受 R3 传入的裸内核指针：所有目标 DEVICE_OBJECT 都由本模块自己从
    路径解析出的 FILE_OBJECT 推导，用户态只能选择"用哪一层"，不能选择"哪个地址"。

Environment:

    Kernel-mode Driver Framework，全部入口要求 PASSIVE_LEVEL。

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"
#include "ark/ark_file_irp.h"

#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000UL
#endif

#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000UL
#endif

#ifndef IRP_MJ_MAXIMUM_FUNCTION
#define IRP_MJ_MAXIMUM_FUNCTION 0x1b
#endif

#define KSWORD_ARK_FILE_IRP_POOL_TAG 'iFsK'

// 单次 QUERY_DIRECTORY 的原生缓冲；与 file_directory_query.c 保持一致，
// 让两条路径在"一次能取回多少条目"这一点上没有观测差异。
#define KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES (64UL * 1024UL)

/*
 * ObCreateObject 未被 WDK 公开声明，但由 ntoskrnl.exe 导出。手工构造 FILE_OBJECT
 * 是"让 IRP_MJ_CREATE 本身也绕过过滤层"的唯一途径：IoCreateFile 系列一定从栈顶
 * 进入，无法把 CREATE 投递到基础文件系统设备。只在 targetLayer 明确要求绕过时
 * 才会走到这里。
 */
NTKERNELAPI
NTSTATUS
NTAPI
ObCreateObject(
    _In_ KPROCESSOR_MODE ProbeMode,
    _In_ POBJECT_TYPE ObjectType,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ KPROCESSOR_MODE OwnershipMode,
    _Inout_opt_ PVOID ParseContext,
    _In_ ULONG ObjectBodySize,
    _In_ ULONG PagedPoolCharge,
    _In_ ULONG NonPagedPoolCharge,
    _Out_ PVOID* Object
    );

// KSWORD_ARK_FILE_IRP_SYNC：一次同步 IRP 的完成同步块。
// 完成例程返回 STATUS_MORE_PROCESSING_REQUIRED，因此 I/O 管理器不会再写
// UserIosb，最终状态必须由完成例程自己抄进这里。
typedef struct _KSWORD_ARK_FILE_IRP_SYNC
{
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
} KSWORD_ARK_FILE_IRP_SYNC, *PKSWORD_ARK_FILE_IRP_SYNC;

// KSWORD_ARK_FILE_IRP_TARGET：一次请求解析出的完整设备栈视图。
// 三个候选层同时保留，响应里一并回给 R3，UI 才能解释"为什么这一层不可用"。
typedef struct _KSWORD_ARK_FILE_IRP_TARGET
{
    PFILE_OBJECT FileObject;        // 目标文件对象。
    PDEVICE_OBJECT TargetDevice;    // 本次 IRP 实际投递的设备。
    PDEVICE_OBJECT RelatedDevice;   // IoGetRelatedDeviceObject 结果。
    PDEVICE_OBJECT BaseFsDevice;    // IoGetBaseFileSystemDeviceObject 结果。
    PDEVICE_OBJECT VpbDevice;       // VPB->DeviceObject。
    PDEVICE_OBJECT FileDevice;      // FileObject->DeviceObject。
    PDEVICE_OBJECT CreateDevice;    // 手工路径下真正接收 IRP_MJ_CREATE 的设备。
    HANDLE FileHandle;              // 托管打开路径持有的内核句柄。
    PWCHAR ManualNameBuffer;        // 手工 FILE_OBJECT 的名字缓冲。
    BOOLEAN Manual;                 // TRUE 表示 FILE_OBJECT 由本模块构造。
    BOOLEAN VpbReferenced;          // CREATE 成功后是否加过 VPB 引用。
    ULONG ResolvedLayer;            // 实际生效的栈层。
    NTSTATUS CreateStatus;          // CREATE 阶段结果。
} KSWORD_ARK_FILE_IRP_TARGET, *PKSWORD_ARK_FILE_IRP_TARGET;

static PVOID
KswordArkFileIrpAllocate(
    _In_ SIZE_T BufferBytes
    )
/*++

Routine Description:

    分配一块非分页缓冲用于 IRP 数据段。IRP 可能被下层驱动异步持有，缓冲不能
    来自调用栈，也不能来自会被响应覆盖的 METHOD_BUFFERED 系统缓冲。

Arguments:

    BufferBytes - 请求字节数；0 直接返回 NULL。

Return Value:

    成功返回地址，失败返回 NULL。

--*/
{
    PVOID buffer = NULL;

    if (BufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    buffer = ExAllocatePoolWithTag(
        NonPagedPoolNx,
        BufferBytes,
        KSWORD_ARK_FILE_IRP_POOL_TAG);
#pragma warning(pop)

    if (buffer != NULL) {
        RtlZeroMemory(buffer, BufferBytes);
    }
    return buffer;
}

static VOID
KswordArkFileIrpFree(
    _In_opt_ PVOID Buffer
    )
/*++

Routine Description:

    释放 KswordArkFileIrpAllocate 返回的缓冲；NULL 输入允许直接返回。

Arguments:

    Buffer - 待释放地址。

Return Value:

    无。

--*/
{
    if (Buffer != NULL) {
        ExFreePoolWithTag(Buffer, KSWORD_ARK_FILE_IRP_POOL_TAG);
    }
}

static VOID
KswordArkFileIrpReleaseManualName(
    _Inout_ PKSWORD_ARK_FILE_IRP_TARGET Target,
    _In_opt_ PFILE_OBJECT FileObject
    )
/*++

Routine Description:

    把手工 CREATE 用的名字缓冲从 FILE_OBJECT 上摘下来并释放。

    这块缓冲挂到 FILE_OBJECT->FileName.Buffer 上之后就有了第二个潜在释放者：
    引用归零时 nt!IopDeleteFile 会检查 FileName.Length，非零就用 tag 0 把
    FileName.Buffer 释放掉（nt!IopDeleteFile+0x195）。本模块若也按自己的 tag 释放
    同一个指针，就是一次确定性的重复释放 —— 每次 open/close 循环都会发生。

    这种错误不一定当场崩：池块头被写坏后，可能要等后续某次无关的池操作做一致性校验
    才爆 0x13A KERNEL_MODE_HEAP_CORRUPTION，栈上指向的是发现者而不是肇事者
    （实测里发现者是 ndis/NETIO，而损坏块的归属标记是本模块的 KsFi）。开启驱动验证器
    特殊池时，已释放块所在页已被取消映射，第二次释放读池头当场触发
    0x50 PAGE_FAULT_IN_NONPAGED_AREA。

    因此"摘"和"放"必须成对做，且必须在 ObDereferenceObject 之前：先清空 FileName
    让 IopDeleteFile 无事可做，再由本模块按自己的 tag 释放。另有一种情况是文件系统
    在重解析（reparse / 挂载点 / 符号链接 / DFS）时换掉了 FileName.Buffer，
    此时 Target->ManualNameBuffer 已是野指针，一律不碰。

Arguments:

    Target - 目标视图；返回时 ManualNameBuffer 一律置空。
    FileObject - 关联文件对象；为 NULL 表示尚未交给文件系统。

Return Value:

    无。

--*/
{
    PWCHAR attached = (FileObject != NULL) ? FileObject->FileName.Buffer : NULL;

    if (FileObject != NULL) {
        //
        // 先把缓冲从 FILE_OBJECT 上摘下来。IopDeleteFile 判的是 FileName.Length：
        // 非零就会用 tag 0 再释放一次 FileName.Buffer（nt!IopDeleteFile+0x195）。
        // 摘的动作和释放动作必须成对，缺一半就是重复释放或泄漏。
        //
        FileObject->FileName.Buffer = NULL;
        FileObject->FileName.Length = 0U;
        FileObject->FileName.MaximumLength = 0U;
    }

    if (FileObject == NULL || attached == Target->ManualNameBuffer) {
        //
        // 缓冲仍是本模块那块（两者同为 NULL 也走这里，释放是空操作）。
        // 注意"指针没变"不等于"文件系统没动过"：nt!IoReplaceFileObjectName 在新名字
        // 不超过 MaximumLength 时是原地 memset+memcpy（+0x2e 分支），指针原样保留。
        // 上面那 32 个 WCHAR 的余量恰恰把重解析主动导向了这条原地改写分支。
        // 但无论内容怎么变，这块的所有权仍在本模块，按本模块的 tag 释放是对的。
        //
        KswordArkFileIrpFree(Target->ManualNameBuffer);
    }
    else if (attached != NULL) {
        //
        // 指针被换过。nt!IoReplaceFileObjectName 的重新分配分支（+0x7f）用
        // ExAllocatePool2(POOL_FLAG_PAGED, …, 'IoNm') 拿新块，并在 +0xa3 用
        // ExFreePoolWithTag(旧块, 0) 把本模块那块直接释放掉了 —— tag 传 0 不做校验，
        // 所以本模块的池块确实可以被一个无关组件放掉。因此 Target->ManualNameBuffer
        // 此刻是野指针，一个字节都不能再碰。
        //
        // 换上来的这块按 I/O 管理器的约定归"丢弃 FILE_OBJECT 的一方"释放，且一律用
        // tag 0（IopDeleteFile+0x195 与 IopParseDevice+0x16f0 都是这么做的）。既然
        // 收尾权已经收归本模块，这块也得由本模块照同样的规矩放掉，否则就是泄漏。
        //
        ExFreePoolWithTag(attached, 0);
    }

    Target->ManualNameBuffer = NULL;
}

static VOID
KswordArkFileIrpDisposeManualFileObject(
    _Inout_ PKSWORD_ARK_FILE_IRP_TARGET Target,
    _In_ PFILE_OBJECT FileObject
    )
/*++

Routine Description:

    丢弃手工构造的 FILE_OBJECT，且不让 I/O 管理器把收尾再做一遍。

    引用归零会触发 nt!IopDeleteFile，它按"普通 FILE_OBJECT"的约定收尾，一口气做四件事：
    经 IopCloseFile 发 IRP_MJ_CLEANUP、自己发 IRP_MJ_CLOSE、减一次 VPB 引用、
    用 tag 0 释放 FileName.Buffer。判据是 Flags 里的 FO_HANDLE_CREATED /
    FO_FILE_OPEN_CANCELLED，而手工构造的对象从来没进过句柄表，这两位恒为 0，
    所以四件事全都会执行。

    这四件事本模块自己全做过，而且是按 CREATE 的实际接收设备（Target->CreateDevice）
    做的 —— I/O 管理器只会发给 IoGetRelatedDeviceObject 返回的栈顶设备，那正是本模块
    要绕开的层。所以收尾权必须留在本模块，重复的那一份要掐掉。

    掐法是 IopDeleteFile 的第一道判据：FileObject->DeviceObject 为 NULL 时它只调
    IopDeleteFileObjectExtension 就返回。Vpb 与 FileName 一并清掉，这样即使将来
    判据挪了位置，减 VPB 引用和释放名字缓冲这两条也各自还有一道独立的闸。

    这不是绕过内核的取巧手段：nt!IopParseDevice 丢弃自己那个 FILE_OBJECT 时，
    做的就是"释放名字缓冲 → FileName.Length 清零 → DeviceObject 置空 → 解引用"。

Arguments:

    Target - 目标视图；返回时 ManualNameBuffer 置空。
    FileObject - 待丢弃的手工文件对象。

Return Value:

    无。

--*/
{
    KswordArkFileIrpReleaseManualName(Target, FileObject);
    FileObject->DeviceObject = NULL;
    FileObject->Vpb = NULL;
    ObDereferenceObject(FileObject);
}

static VOID
KswordArkFileIrpCloseVolumeAnchor(
    _In_opt_ PFILE_OBJECT VolumeFileObject,
    _In_opt_ HANDLE VolumeHandle
    )
/*++

Routine Description:

    释放"卷锚点"——手工 CREATE 期间用来打开卷的那个句柄与文件对象。

    手工路径从卷文件对象身上借出三个裸指针：挂载的文件系统设备、真实卷设备、
    以及卷的 VPB。这三者的存活完全靠卷文件对象这一个引用担保：VPB 与其上挂载的
    FS 设备由 VPB->ReferenceCount 保活，而卷上最后一个 FILE_OBJECT 消失后，
    强制卸载 / 弹出介质 / BitLocker 锁卷都可以让 VPB 被回收、FS 设备被 IoDeleteDevice。
    IoGetBaseFileSystemDeviceObject 和 Vpb->DeviceObject 返回的都是借用指针，
    文档不保证源 FILE_OBJECT 释放之后仍然有效。

    因此锚点必须一直持有到手工 CREATE 成功、本模块补上自己的设备与 VPB 引用为止，
    在此之前的任何一条退出路径上才释放。提前放掉就是拿着已释放的设备对象发 IRP。

Arguments:

    VolumeFileObject - 卷文件对象；允许为 NULL。
    VolumeHandle - 卷句柄；允许为 NULL。

Return Value:

    无。

--*/
{
    if (VolumeFileObject != NULL) {
        ObDereferenceObject(VolumeFileObject);
    }
    if (VolumeHandle != NULL) {
        ZwClose(VolumeHandle);
    }
}

static NTSTATUS
KswordArkFileIrpCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_opt_ PVOID Context
    )
/*++

Routine Description:

    统一完成例程。抄走最终 IO_STATUS_BLOCK 后返回
    STATUS_MORE_PROCESSING_REQUIRED，让 IRP 停在本层，由发起方负责释放 MDL 和
    IRP 本身。中文说明：参考实现里"先 IoFreeIrp 再读 Irp->UserEvent"是释放后
    使用，本模块把释放责任完全收回发起方，完成例程只做状态搬运。

Arguments:

    DeviceObject - 完成时所处的设备对象，本模块不使用。
    Irp - 已完成的请求。
    Context - 指向调用方栈上的 KSWORD_ARK_FILE_IRP_SYNC。

Return Value:

    始终返回 STATUS_MORE_PROCESSING_REQUIRED。

--*/
{
    PKSWORD_ARK_FILE_IRP_SYNC sync = (PKSWORD_ARK_FILE_IRP_SYNC)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (sync != NULL) {
        sync->IoStatus = Irp->IoStatus;
        KeSetEvent(&sync->Event, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
KswordArkFileIrpCallAndWait(
    _In_ PDEVICE_OBJECT TargetDevice,
    _In_ PIRP Irp,
    _Inout_ PKSWORD_ARK_FILE_IRP_SYNC Sync,
    _In_ ULONG TimeoutMs,
    _In_ BOOLEAN PowerIrp,
    _Out_ PBOOLEAN CancelledOut
    )
/*++

Routine Description:

    投递一个已经填好的 IRP 并同步等待完成。超时后先取消再无限等待排空：Sync
    位于调用栈上，只要下层还可能触碰它就绝不能返回。

Arguments:

    TargetDevice - 投递目标。
    Irp - 已设置完成例程的请求。
    Sync - 完成同步块，必须在本函数返回前保持有效。
    TimeoutMs - 正常等待上限。
    PowerIrp - TRUE 时使用 PoCallDriver 语义。
    CancelledOut - TRUE 表示本次请求因超时被取消。

Return Value:

    目标驱动写入的最终 NTSTATUS。

--*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    NTSTATUS waitStatus = STATUS_SUCCESS;
    LARGE_INTEGER timeout;

    *CancelledOut = FALSE;

    if (PowerIrp) {
        status = PoCallDriver(TargetDevice, Irp);
    }
    else {
        status = IoCallDriver(TargetDevice, Irp);
    }

    if (status == STATUS_PENDING) {
        timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000LL);
        waitStatus = KeWaitForSingleObject(
            &Sync->Event,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
        if (waitStatus == STATUS_TIMEOUT) {
            *CancelledOut = TRUE;
            (VOID)IoCancelIrp(Irp);
            // 排空是强制的：完成例程仍会写 Sync，提前返回会破坏调用栈。
            (VOID)KeWaitForSingleObject(
                &Sync->Event,
                Executive,
                KernelMode,
                FALSE,
                NULL);
        }
    }

    return Sync->IoStatus.Status;
}

static VOID
KswordArkFileIrpCopyObjectName(
    _In_opt_ PVOID Object,
    _Out_writes_(MaxChars) PWCHAR NameBuffer,
    _In_ ULONG MaxChars,
    _Out_ PULONG NameLengthCharsOut
    )
/*++

Routine Description:

    读取对象名并写入固定宽字符字段。失败时只留空串，不影响 IRP 结果本身。

Arguments:

    Object - 驱动对象或设备对象。
    NameBuffer - 目标固定缓冲。
    MaxChars - 缓冲容量（含结尾 NUL）。
    NameLengthCharsOut - 实际写入字符数。

Return Value:

    无。

--*/
{
    POBJECT_NAME_INFORMATION nameInformation = NULL;
    ULONG returnedLength = 0UL;
    ULONG copyChars = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    *NameLengthCharsOut = 0UL;
    if (MaxChars == 0U) {
        return;
    }
    NameBuffer[0] = L'\0';
    if (Object == NULL) {
        return;
    }

    nameInformation = (POBJECT_NAME_INFORMATION)KswordArkFileIrpAllocate(
        sizeof(OBJECT_NAME_INFORMATION) + (512U * sizeof(WCHAR)));
    if (nameInformation == NULL) {
        return;
    }

    status = ObQueryNameString(
        Object,
        nameInformation,
        sizeof(OBJECT_NAME_INFORMATION) + (512U * sizeof(WCHAR)),
        &returnedLength);
    if (NT_SUCCESS(status) &&
        nameInformation->Name.Buffer != NULL &&
        nameInformation->Name.Length != 0U) {
        copyChars = (ULONG)(nameInformation->Name.Length / sizeof(WCHAR));
        if (copyChars >= MaxChars) {
            copyChars = MaxChars - 1U;
        }
        RtlCopyMemory(
            NameBuffer,
            nameInformation->Name.Buffer,
            copyChars * sizeof(WCHAR));
        NameBuffer[copyChars] = L'\0';
        *NameLengthCharsOut = copyChars;
    }

    KswordArkFileIrpFree(nameInformation);
}

static BOOLEAN
KswordArkFileIrpSplitVolumePath(
    _In_reads_(PathChars) PCWSTR Path,
    _In_ USHORT PathChars,
    _Out_writes_(VolumeBufferChars) PWCHAR VolumeBuffer,
    _In_ USHORT VolumeBufferChars,
    _Out_ PUSHORT VolumeCharsOut,
    _Out_ PCWSTR* RelativeNameOut,
    _Out_ PUSHORT RelativeCharsOut
    )
/*++

Routine Description:

    把 NT 路径拆成"卷根"和"卷内相对名"。手工构造 FILE_OBJECT 时必须这样拆：
    IRP_MJ_CREATE 交给文件系统设备时，FileObject->FileName 只能是卷内相对名，
    带卷前缀会被文件系统当作非法名字拒绝。

Arguments:

    Path/PathChars - 完整 NT 路径，例如 \??\C:\Windows 或
        \Device\HarddiskVolume3\Windows。
    VolumeBuffer/VolumeBufferChars - 接收卷根路径（含结尾 NUL）。
    VolumeCharsOut - 卷根字符数。
    RelativeNameOut - 指回 Path 内部的相对名起点（以反斜杠开头）。
    RelativeCharsOut - 相对名字符数；卷根自身返回 0。

Return Value:

    TRUE 表示识别成功，FALSE 表示不是支持的卷路径格式。

--*/
{
    USHORT index = 0U;
    USHORT volumeChars = 0U;

    *VolumeCharsOut = 0U;
    *RelativeNameOut = NULL;
    *RelativeCharsOut = 0U;
    if (Path == NULL || PathChars < 4U || VolumeBufferChars < 8U) {
        return FALSE;
    }

    if (PathChars >= 6U &&
        Path[0] == L'\\' &&
        Path[1] == L'?' &&
        Path[2] == L'?' &&
        Path[3] == L'\\' &&
        Path[5] == L':') {
        // \??\C: 形式：卷根固定为前 6 个字符。
        volumeChars = 6U;
    }
    else if (PathChars > 8U &&
        (Path[0] == L'\\') &&
        (Path[1] == L'D' || Path[1] == L'd')) {
        // \Device\XXX 形式：卷根到第四个反斜杠之前（\Device\HarddiskVolumeN）。
        USHORT separatorCount = 0U;
        for (index = 0U; index < PathChars; ++index) {
            if (Path[index] != L'\\') {
                continue;
            }
            ++separatorCount;
            if (separatorCount == 3U) {
                break;
            }
        }
        if (separatorCount < 2U) {
            return FALSE;
        }
        volumeChars = (separatorCount == 3U) ? index : PathChars;
    }
    else {
        return FALSE;
    }

    if (volumeChars == 0U || volumeChars >= VolumeBufferChars) {
        return FALSE;
    }

    RtlCopyMemory(VolumeBuffer, Path, volumeChars * sizeof(WCHAR));
    VolumeBuffer[volumeChars] = L'\0';
    *VolumeCharsOut = volumeChars;

    if (PathChars > volumeChars && Path[volumeChars] == L'\\') {
        *RelativeNameOut = Path + volumeChars;
        *RelativeCharsOut = (USHORT)(PathChars - volumeChars);
    }
    return TRUE;
}

static VOID
KswordArkFileIrpCaptureLayers(
    _In_ PFILE_OBJECT FileObject,
    _Inout_ PKSWORD_ARK_FILE_IRP_TARGET Target
    )
/*++

Routine Description:

    记录一个文件对象上全部可选目标层。三层同时保留，UI 才能展示"栈顶与基础
    文件系统设备是否为同一个对象"——两者相同即说明这条路径上没有挂过滤层。

Arguments:

    FileObject - 已打开的文件对象。
    Target - 接收各层地址。

Return Value:

    无。

--*/
{
    Target->RelatedDevice = IoGetRelatedDeviceObject(FileObject);
    Target->BaseFsDevice = IoGetBaseFileSystemDeviceObject(FileObject);
    Target->FileDevice = FileObject->DeviceObject;
    Target->VpbDevice = NULL;
    if (FileObject->Vpb != NULL) {
        Target->VpbDevice = FileObject->Vpb->DeviceObject;
    }
    else if (FileObject->DeviceObject != NULL &&
        FileObject->DeviceObject->Vpb != NULL) {
        Target->VpbDevice = FileObject->DeviceObject->Vpb->DeviceObject;
    }
}

static PDEVICE_OBJECT
KswordArkFileIrpSelectLayer(
    _In_ const KSWORD_ARK_FILE_IRP_TARGET* Target,
    _In_ ULONG RequestedLayer,
    _Out_ PULONG ResolvedLayerOut
    )
/*++

Routine Description:

    按请求选择投递层。请求层不可用时回退到栈顶而不是失败，同时回报实际生效的
    层，避免 R3 把"回退结果"误当成"绕过成功的结果"。

Arguments:

    Target - 已捕获三层地址的目标视图。
    RequestedLayer - R3 请求的层。
    ResolvedLayerOut - 实际生效的层。

Return Value:

    选定的设备对象；全部不可用时返回 NULL。

--*/
{
    PDEVICE_OBJECT selected = NULL;

    *ResolvedLayerOut = RequestedLayer;
    switch (RequestedLayer) {
    case KSWORD_ARK_FILE_IRP_LAYER_BASE_FS:
        selected = Target->BaseFsDevice;
        break;
    case KSWORD_ARK_FILE_IRP_LAYER_VPB_FS:
        selected = Target->VpbDevice;
        break;
    case KSWORD_ARK_FILE_IRP_LAYER_DEVICE:
        selected = Target->FileDevice;
        break;
    case KSWORD_ARK_FILE_IRP_LAYER_RELATED:
    default:
        selected = Target->RelatedDevice;
        *ResolvedLayerOut = KSWORD_ARK_FILE_IRP_LAYER_RELATED;
        break;
    }

    if (selected == NULL) {
        selected = Target->RelatedDevice;
        *ResolvedLayerOut = KSWORD_ARK_FILE_IRP_LAYER_RELATED;
    }
    return selected;
}

static NTSTATUS
KswordArkFileIrpOpenManaged(
    _In_reads_(PathChars) PCWSTR Path,
    _In_ USHORT PathChars,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_ ULONG FileAttributes,
    _Inout_ PKSWORD_ARK_FILE_IRP_TARGET Target
    )
/*++

Routine Description:

    用 I/O 管理器的正常打开路径取得 FILE_OBJECT。这条路径会经过全部过滤层，
    作为"栈顶基线"使用；后续 major 仍然可以被投递到更深的层。

Arguments:

    Path/PathChars - NT 路径。
    DesiredAccess/ShareAccess/CreateDisposition/CreateOptions/FileAttributes -
        CREATE 参数。
    Target - 接收句柄、文件对象与各层地址。

Return Value:

    ZwCreateFile 与 ObReferenceObjectByHandle 的 NTSTATUS。

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)Path;
    targetPath.Length = (USHORT)(PathChars * sizeof(WCHAR));
    targetPath.MaximumLength = (USHORT)(targetPath.Length + sizeof(WCHAR));

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        &Target->FileHandle,
        DesiredAccess,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        NULL,
        0U);
    if (!NT_SUCCESS(status)) {
        Target->FileHandle = NULL;
        return status;
    }

    status = ObReferenceObjectByHandle(
        Target->FileHandle,
        0U,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&Target->FileObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(Target->FileHandle);
        Target->FileHandle = NULL;
        Target->FileObject = NULL;
        return status;
    }

    Target->Manual = FALSE;
    KswordArkFileIrpCaptureLayers(Target->FileObject, Target);
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordArkFileIrpOpenManual(
    _In_reads_(PathChars) PCWSTR Path,
    _In_ USHORT PathChars,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_ ULONG FileAttributes,
    _In_ ULONG RequestedLayer,
    _In_ ULONG TimeoutMs,
    _Inout_ PKSWORD_ARK_FILE_IRP_TARGET Target
    )
/*++

Routine Description:

    自行构造 FILE_OBJECT 并把 IRP_MJ_CREATE 直接投递到文件系统设备。这样连
    "打开"这一步都不经过过滤层，可以发现只在 CREATE 阶段被拦截隐藏的路径。

    卷根仍然用正常打开取得，因为需要它的 VPB 才能知道当前挂载的文件系统设备与
    真实卷设备；随后的目标文件 CREATE 完全由本函数构造。

Arguments:

    Path/PathChars - 完整 NT 路径。
    DesiredAccess/ShareAccess/CreateDisposition/CreateOptions/FileAttributes -
        CREATE 参数。
    RequestedLayer - 请求投递的层。
    TimeoutMs - CREATE 的等待上限。
    Target - 接收构造出的文件对象与各层地址。

Return Value:

    路径解析、对象构造或 CREATE 阶段的 NTSTATUS。

--*/
{
    WCHAR volumeBuffer[64] = { 0 };
    USHORT volumeChars = 0U;
    PCWSTR relativeName = NULL;
    USHORT relativeChars = 0U;
    UNICODE_STRING volumePath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE volumeHandle = NULL;
    PFILE_OBJECT volumeFileObject = NULL;
    PDEVICE_OBJECT fileSystemDevice = NULL;
    PDEVICE_OBJECT realDevice = NULL;
    PFILE_OBJECT manualFileObject = NULL;
    PIRP irp = NULL;
    PIO_STACK_LOCATION stackLocation = NULL;
    KSWORD_ARK_FILE_IRP_SYNC sync;
    ACCESS_STATE accessState;
    PVOID auxAccessData = NULL;
    IO_SECURITY_CONTEXT securityContext;
    BOOLEAN subjectContextCaptured = FALSE;
    BOOLEAN cancelled = FALSE;
    ULONG nameBufferBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!KswordArkFileIrpSplitVolumePath(
            Path,
            PathChars,
            volumeBuffer,
            (USHORT)RTL_NUMBER_OF(volumeBuffer),
            &volumeChars,
            &relativeName,
            &relativeChars)) {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    RtlInitUnicodeString(&volumePath, volumeBuffer);
    InitializeObjectAttributes(
        &objectAttributes,
        &volumePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwOpenFile(
        &volumeHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObReferenceObjectByHandle(
        volumeHandle,
        0U,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&volumeFileObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(volumeHandle);
        return status;
    }

    // 解析卷上当前挂载的文件系统设备与真实卷设备。
    if (RequestedLayer == KSWORD_ARK_FILE_IRP_LAYER_BASE_FS) {
        fileSystemDevice = IoGetBaseFileSystemDeviceObject(volumeFileObject);
    }
    if (fileSystemDevice == NULL && volumeFileObject->Vpb != NULL) {
        fileSystemDevice = volumeFileObject->Vpb->DeviceObject;
        realDevice = volumeFileObject->Vpb->RealDevice;
    }
    if (realDevice == NULL) {
        realDevice = volumeFileObject->DeviceObject;
    }
    if (fileSystemDevice == NULL) {
        fileSystemDevice = IoGetRelatedDeviceObject(volumeFileObject);
    }

    //
    // 卷锚点一直持有到 CREATE 成功为止：上面这几个设备指针和下面要读的 realDevice->Vpb
    // 都是从卷文件对象身上借来的，锚点一放，它们随时可能失效。
    //
    if (fileSystemDevice == NULL || realDevice == NULL) {
        KswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return STATUS_INVALID_DEVICE_STATE;
    }

    // 构造裸 FILE_OBJECT。ObCreateObject 返回引用计数为 1 且未插入句柄表的对象，
    // 收尾时用 ObDereferenceObject 释放。
    InitializeObjectAttributes(
        &objectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    status = ObCreateObject(
        KernelMode,
        *IoFileObjectType,
        &objectAttributes,
        KernelMode,
        NULL,
        (ULONG)sizeof(FILE_OBJECT),
        0U,
        0U,
        (PVOID*)&manualFileObject);
    if (!NT_SUCCESS(status)) {
        KswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return status;
    }

    RtlZeroMemory(manualFileObject, sizeof(FILE_OBJECT));
    manualFileObject->Type = IO_TYPE_FILE;
    manualFileObject->Size = sizeof(FILE_OBJECT);
    manualFileObject->DeviceObject = realDevice;
    manualFileObject->Vpb = realDevice->Vpb;
    manualFileObject->Flags = FO_SYNCHRONOUS_IO;
    KeInitializeEvent(&manualFileObject->Lock, SynchronizationEvent, FALSE);
    KeInitializeEvent(&manualFileObject->Event, NotificationEvent, FALSE);

    // 名字缓冲留出余量：文件系统在重解析场景下可能改写 FileName。
    nameBufferBytes = (ULONG)((relativeChars + 32U) * sizeof(WCHAR));
    Target->ManualNameBuffer = (PWCHAR)KswordArkFileIrpAllocate(nameBufferBytes);
    if (Target->ManualNameBuffer == NULL) {
        KswordArkFileIrpDisposeManualFileObject(Target, manualFileObject);
        KswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    manualFileObject->FileName.Buffer = Target->ManualNameBuffer;
    manualFileObject->FileName.MaximumLength = (USHORT)nameBufferBytes;
    if (relativeName != NULL && relativeChars != 0U) {
        RtlCopyMemory(
            manualFileObject->FileName.Buffer,
            relativeName,
            relativeChars * sizeof(WCHAR));
        manualFileObject->FileName.Length = (USHORT)(relativeChars * sizeof(WCHAR));
    }
    else {
        manualFileObject->FileName.Buffer[0] = L'\\';
        manualFileObject->FileName.Length = sizeof(WCHAR);
    }

    /*
     * 构造 CREATE 的安全上下文。这里不使用 SeCreateAccessState：当前 WDK 已不再
     * 公开该函数，也不再公开 AUX_ACCESS_DATA 的布局，按猜测的结构体大小传栈变量
     * 会在布局变化时直接踩栈。改为手工填 ACCESS_STATE——文件系统读取的是
     * RemainingDesiredAccess / PreviouslyGrantedAccess / SubjectSecurityContext，
     * 这三者都能用文档化 API 正确构造。
     *
     * AuxData 用一块整页零缓冲：部分文件系统会解引用它，给 NULL 会崩，而它的
     * 真实布局未公开，只能保证"足够大且全零"。
     */
    auxAccessData = KswordArkFileIrpAllocate(PAGE_SIZE);
    if (auxAccessData == NULL) {
        KswordArkFileIrpDisposeManualFileObject(Target, manualFileObject);
        KswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&accessState, sizeof(accessState));
    SeCaptureSubjectContext(&accessState.SubjectSecurityContext);
    subjectContextCaptured = TRUE;
    // 访问检查已由本驱动的 IOCTL 闸门完成，这里声明为"全部已授予、无剩余待检"。
    accessState.OriginalDesiredAccess = DesiredAccess;
    accessState.PreviouslyGrantedAccess = DesiredAccess;
    accessState.RemainingDesiredAccess = 0UL;
    accessState.SecurityEvaluated = TRUE;
    accessState.SecurityDescriptor = NULL;
    accessState.AuxData = auxAccessData;

    RtlZeroMemory(&securityContext, sizeof(securityContext));
    securityContext.SecurityQos = NULL;
    securityContext.AccessState = &accessState;
    securityContext.DesiredAccess = DesiredAccess;
    securityContext.FullCreateOptions = 0UL;

    irp = IoAllocateIrp(fileSystemDevice->StackSize, FALSE);
    if (irp == NULL) {
        if (subjectContextCaptured) {
            SeReleaseSubjectContext(&accessState.SubjectSecurityContext);
        }
        KswordArkFileIrpFree(auxAccessData);
        KswordArkFileIrpDisposeManualFileObject(Target, manualFileObject);
        KswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&sync, sizeof(sync));
    KeInitializeEvent(&sync.Event, NotificationEvent, FALSE);
    sync.IoStatus.Status = STATUS_UNSUCCESSFUL;

    irp->MdlAddress = NULL;
    irp->AssociatedIrp.SystemBuffer = NULL;
    irp->UserBuffer = NULL;
    irp->Flags = IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = &sync.IoStatus;
    irp->UserEvent = NULL;
    irp->PendingReturned = FALSE;
    irp->Cancel = FALSE;
    irp->CancelRoutine = NULL;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.AuxiliaryBuffer = NULL;
    irp->Tail.Overlay.OriginalFileObject = manualFileObject;

    stackLocation = IoGetNextIrpStackLocation(irp);
    stackLocation->MajorFunction = IRP_MJ_CREATE;
    stackLocation->MinorFunction = 0U;
    stackLocation->DeviceObject = fileSystemDevice;
    stackLocation->FileObject = manualFileObject;
    stackLocation->Parameters.Create.SecurityContext = &securityContext;
    // CreateDisposition 占据 Options 的高 8 位，这是 IRP_MJ_CREATE 的固定编码。
    stackLocation->Parameters.Create.Options =
        ((CreateDisposition & 0xFFUL) << 24) | (CreateOptions & 0x00FFFFFFUL);
    stackLocation->Parameters.Create.FileAttributes = (USHORT)FileAttributes;
    stackLocation->Parameters.Create.ShareAccess = (USHORT)ShareAccess;
    stackLocation->Parameters.Create.EaLength = 0UL;

    IoSetCompletionRoutine(
        irp,
        KswordArkFileIrpCompletion,
        &sync,
        TRUE,
        TRUE,
        TRUE);

    status = KswordArkFileIrpCallAndWait(
        fileSystemDevice,
        irp,
        &sync,
        TimeoutMs,
        FALSE,
        &cancelled);

    IoFreeIrp(irp);
    if (subjectContextCaptured) {
        SeReleaseSubjectContext(&accessState.SubjectSecurityContext);
    }
    KswordArkFileIrpFree(auxAccessData);

    if (!NT_SUCCESS(status)) {
        //
        // CREATE 失败也必须走缴械入口：文件系统既然没打开成功，就不该再收到一份
        // CLEANUP/CLOSE，而 IopDeleteFile 并不看 CREATE 的结果，只看 FILE_OBJECT
        // 的形状。此外文件系统可能在失败前已经重解析过并换掉了 FileName.Buffer。
        //
        KswordArkFileIrpDisposeManualFileObject(Target, manualFileObject);
        KswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);
        return status;
    }

    // CREATE 成功后文件系统已把该 FILE_OBJECT 记入自己的结构，需要补上
    // 设备与 VPB 引用，收尾阶段的 CLEANUP/CLOSE 才配对。
    InterlockedIncrement(&manualFileObject->DeviceObject->ReferenceCount);
    if (manualFileObject->Vpb != NULL) {
        KIRQL vpbIrql = 0;

        //
        // VPB->ReferenceCount 必须在 VPB 自旋锁下改。内核那一侧
        // （nt!IopDecrementVpbRefCount）做的是普通的 dec [Vpb+0x1C]，不是原子指令，
        // 靠队列自旋锁保证互斥；而 IoAcquireVpbSpinLock 内部就是
        // KeAcquireQueuedSpinLock(9)，与它是同一把锁（两侧反汇编已核对）。
        // 用 Interlocked 与之并发等于一边加锁一边不加锁，更新会丢 —— 这个计数一旦
        // 丢失，卷就可能在本模块仍持有文件对象时被卸载。
        //
        IoAcquireVpbSpinLock(&vpbIrql);
        manualFileObject->Vpb->ReferenceCount += 1;
        IoReleaseVpbSpinLock(vpbIrql);
        Target->VpbReferenced = TRUE;
    }

    //
    // 到这里本模块已经对设备与 VPB 各自持有一份自己的引用，借来的指针不再依赖
    // 卷锚点担保，可以放掉锚点了。
    //
    KswordArkFileIrpCloseVolumeAnchor(volumeFileObject, volumeHandle);

    Target->FileObject = manualFileObject;
    Target->Manual = TRUE;
    // 记住 CREATE 的实际接收者：CLEANUP/CLOSE 必须回到同一个设备。发到别的层
    // 会让文件系统收到一个它从未见过的 FILE_OBJECT 的收尾请求。
    Target->CreateDevice = fileSystemDevice;
    KswordArkFileIrpCaptureLayers(manualFileObject, Target);
    // 手工路径已经知道 CREATE 实际投递到了哪个设备，直接记为可选层之一。
    if (Target->BaseFsDevice == NULL) {
        Target->BaseFsDevice = fileSystemDevice;
    }
    if (Target->VpbDevice == NULL) {
        Target->VpbDevice = fileSystemDevice;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordArkFileIrpSendSimple(
    _In_ PDEVICE_OBJECT TargetDevice,
    _In_ PFILE_OBJECT FileObject,
    _In_ UCHAR MajorFunction,
    _In_ ULONG IrpFlags,
    _In_ ULONG TimeoutMs
    )
/*++

Routine Description:

    发送一个不带数据缓冲的 IRP（CLEANUP/CLOSE/FLUSH_BUFFERS/SHUTDOWN）。

Arguments:

    TargetDevice - 投递目标。
    FileObject - 关联文件对象。
    MajorFunction - IRP_MJ_* 值。
    IrpFlags - IRP->Flags 初值。
    TimeoutMs - 等待上限。

Return Value:

    目标驱动返回的 NTSTATUS。

--*/
{
    PIRP irp = NULL;
    PIO_STACK_LOCATION stackLocation = NULL;
    KSWORD_ARK_FILE_IRP_SYNC sync;
    BOOLEAN cancelled = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (TargetDevice == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    irp = IoAllocateIrp(TargetDevice->StackSize, FALSE);
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&sync, sizeof(sync));
    KeInitializeEvent(&sync.Event, NotificationEvent, FALSE);
    sync.IoStatus.Status = STATUS_UNSUCCESSFUL;

    irp->MdlAddress = NULL;
    irp->AssociatedIrp.SystemBuffer = NULL;
    irp->UserBuffer = NULL;
    irp->Flags = IrpFlags;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = &sync.IoStatus;
    irp->UserEvent = NULL;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = FileObject;

    stackLocation = IoGetNextIrpStackLocation(irp);
    stackLocation->MajorFunction = MajorFunction;
    stackLocation->MinorFunction = 0U;
    stackLocation->DeviceObject = TargetDevice;
    stackLocation->FileObject = FileObject;

    IoSetCompletionRoutine(
        irp,
        KswordArkFileIrpCompletion,
        &sync,
        TRUE,
        TRUE,
        TRUE);

    status = KswordArkFileIrpCallAndWait(
        TargetDevice,
        irp,
        &sync,
        TimeoutMs,
        FALSE,
        &cancelled);
    IoFreeIrp(irp);
    return status;
}

static VOID
KswordArkFileIrpCloseTarget(
    _Inout_ PKSWORD_ARK_FILE_IRP_TARGET Target,
    _In_ ULONG TimeoutMs,
    _Out_ PNTSTATUS CleanupStatusOut,
    _Out_ PNTSTATUS CloseStatusOut,
    _Out_ PULONG StageFlagsOut
    )
/*++

Routine Description:

    收尾一个已打开目标。托管句柄交回 I/O 管理器；手工对象必须自己按
    CLEANUP → CLOSE 顺序补齐，否则文件系统会永久持有该流的引用。

Arguments:

    Target - 待收尾的目标视图。
    TimeoutMs - 每个收尾 IRP 的等待上限。
    CleanupStatusOut/CloseStatusOut - 手工路径下的两阶段结果。
    StageFlagsOut - 追加已执行的阶段标志。

Return Value:

    无。

--*/
{
    PDEVICE_OBJECT closeDevice = NULL;

    *CleanupStatusOut = STATUS_SUCCESS;
    *CloseStatusOut = STATUS_SUCCESS;

    if (Target->Manual && Target->FileObject != NULL) {
        /*
         * 收尾必须回到 CREATE 的接收者。手工路径可以把 CREATE 投递到基础文件系统
         * 设备，而 IoGetRelatedDeviceObject 返回的是栈顶：一旦用栈顶收尾，文件系统
         * 就会收到一个自己从未见过的 FILE_OBJECT 的 CLEANUP/CLOSE。
         */
        closeDevice = Target->CreateDevice;
        if (closeDevice == NULL) {
            closeDevice = (Target->RelatedDevice != NULL)
                ? Target->RelatedDevice
                : Target->TargetDevice;
        }
        if (closeDevice != NULL) {
            *CleanupStatusOut = KswordArkFileIrpSendSimple(
                closeDevice,
                Target->FileObject,
                IRP_MJ_CLEANUP,
                IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API,
                TimeoutMs);
            *StageFlagsOut |= KSWORD_ARK_FILE_IRP_STAGE_CLEANUP;

            if (Target->VpbReferenced && Target->FileObject->Vpb != NULL) {
                KIRQL vpbIrql = 0;

                // 与 CREATE 成功后那次自增配对，同样必须在 VPB 自旋锁下做。
                IoAcquireVpbSpinLock(&vpbIrql);
                Target->FileObject->Vpb->ReferenceCount -= 1;
                IoReleaseVpbSpinLock(vpbIrql);
                Target->VpbReferenced = FALSE;
            }

            *CloseStatusOut = KswordArkFileIrpSendSimple(
                closeDevice,
                Target->FileObject,
                IRP_MJ_CLOSE,
                IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API,
                TimeoutMs);
            *StageFlagsOut |= KSWORD_ARK_FILE_IRP_STAGE_CLOSE;
        }
        if (Target->FileObject->DeviceObject != NULL) {
            InterlockedDecrement(&Target->FileObject->DeviceObject->ReferenceCount);
        }
        //
        // 上面这一整段（CLEANUP、VPB 减引用、CLOSE、设备减引用）正是 IopDeleteFile
        // 在引用归零时会自己再做一遍的事。丢弃入口会先把 FILE_OBJECT 缴械再解引用，
        // 顺序不能颠倒：缴械要读 DeviceObject/Vpb，而减引用也要读，都得排在解引用之前。
        //
        KswordArkFileIrpDisposeManualFileObject(Target, Target->FileObject);
        Target->FileObject = NULL;
        return;
    }

    if (Target->FileObject != NULL) {
        ObDereferenceObject(Target->FileObject);
        Target->FileObject = NULL;
    }
    if (Target->FileHandle != NULL) {
        *CloseStatusOut = ZwClose(Target->FileHandle);
        Target->FileHandle = NULL;
        *StageFlagsOut |= KSWORD_ARK_FILE_IRP_STAGE_CLOSE;
    }
}

static NTSTATUS
KswordArkFileIrpOpenTarget(
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* Request,
    _In_ ULONG TimeoutMs,
    _Inout_ PKSWORD_ARK_FILE_IRP_TARGET Target
    )
/*++

Routine Description:

    按请求的栈层选择打开方式：栈顶层用托管打开，其余层用手工 CREATE 直发。
    这样"选择哪一层"这一个 UI 选项就同时决定了 CREATE 是否绕过过滤层。

Arguments:

    Request - 已完成边界校验的请求快照。
    TimeoutMs - CREATE 等待上限。
    Target - 接收打开结果。

Return Value:

    CREATE 阶段的 NTSTATUS。

--*/
{
    ULONG createOptions = Request->createOptions;
    ULONG createDisposition = Request->createDisposition;
    ACCESS_MASK desiredAccess = (ACCESS_MASK)Request->desiredAccess;
    ULONG shareAccess = Request->shareAccess;

    if (desiredAccess == 0UL) {
        desiredAccess = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    }
    if (shareAccess == 0UL) {
        shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    }
    if (createDisposition == 0UL) {
        createDisposition = FILE_OPEN;
    }
    if ((Request->flags & KSWORD_ARK_FILE_IRP_FLAG_OPEN_REPARSE_POINT) != 0UL) {
        createOptions |= FILE_OPEN_REPARSE_POINT;
    }
    if ((Request->flags & KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT) != 0UL) {
        createOptions |= FILE_DIRECTORY_FILE;
    }
    createOptions |= FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT;

    if (Request->targetLayer == KSWORD_ARK_FILE_IRP_LAYER_RELATED) {
        return KswordArkFileIrpOpenManaged(
            Request->path,
            Request->pathLengthChars,
            desiredAccess,
            shareAccess,
            createDisposition,
            createOptions,
            Request->fileAttributes != 0UL
                ? Request->fileAttributes
                : FILE_ATTRIBUTE_NORMAL,
            Target);
    }

    return KswordArkFileIrpOpenManual(
        Request->path,
        Request->pathLengthChars,
        desiredAccess,
        shareAccess,
        createDisposition,
        createOptions,
        Request->fileAttributes != 0UL
            ? Request->fileAttributes
            : FILE_ATTRIBUTE_NORMAL,
        Request->targetLayer,
        TimeoutMs,
        Target);
}

// KSWORD_ARK_FILE_IRP_BUFFER_MODE：目标 major 使用哪种数据传递约定。
typedef enum _KSWORD_ARK_FILE_IRP_BUFFER_MODE
{
    KswordArkFileIrpBufferNone = 0,      // 无数据段。
    KswordArkFileIrpBufferSystem,        // AssociatedIrp.SystemBuffer。
    KswordArkFileIrpBufferUser,          // UserBuffer（必要时附 MDL）。
    KswordArkFileIrpBufferDeviceFlags,   // 按目标设备 DO_BUFFERED_IO/DO_DIRECT_IO。
    KswordArkFileIrpBufferControlCode    // 按控制码的 METHOD_* 决定。
} KSWORD_ARK_FILE_IRP_BUFFER_MODE;

static KSWORD_ARK_FILE_IRP_BUFFER_MODE
KswordArkFileIrpBufferModeForMajor(
    _In_ ULONG MajorFunction
    )
/*++

Routine Description:

    返回一个 major 的数据传递约定。这些约定来自 IRP 主功能码的固定定义，不随
    具体文件系统变化；只有 READ/WRITE 与两类控制码需要看运行期信息。

Arguments:

    MajorFunction - IRP_MJ_* 值。

Return Value:

    对应的缓冲模式。

--*/
{
    switch (MajorFunction) {
    case IRP_MJ_READ:
    case IRP_MJ_WRITE:
        return KswordArkFileIrpBufferDeviceFlags;

    case IRP_MJ_QUERY_INFORMATION:
    case IRP_MJ_SET_INFORMATION:
    case IRP_MJ_QUERY_EA:
    case IRP_MJ_SET_EA:
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
    case IRP_MJ_SET_VOLUME_INFORMATION:
    case IRP_MJ_QUERY_QUOTA:
    case IRP_MJ_SET_QUOTA:
        return KswordArkFileIrpBufferSystem;

    case IRP_MJ_DIRECTORY_CONTROL:
    case IRP_MJ_QUERY_SECURITY:
    case IRP_MJ_SET_SECURITY:
        return KswordArkFileIrpBufferUser;

    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        return KswordArkFileIrpBufferControlCode;

    default:
        return KswordArkFileIrpBufferNone;
    }
}

static BOOLEAN
KswordArkFileIrpMajorIsWriteLike(
    _In_ ULONG MajorFunction
    )
/*++

Routine Description:

    判断一个 major 是否可能改变磁盘或设备状态。写语义必须要求 UI 确认令牌，
    避免"看一眼目录"和"改写文件"共用同一个无门槛入口。

Arguments:

    MajorFunction - IRP_MJ_* 值。

Return Value:

    TRUE 表示写语义。

--*/
{
    switch (MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_WRITE:
    case IRP_MJ_SET_INFORMATION:
    case IRP_MJ_SET_EA:
    case IRP_MJ_SET_VOLUME_INFORMATION:
    case IRP_MJ_SET_SECURITY:
    case IRP_MJ_SET_QUOTA:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    case IRP_MJ_LOCK_CONTROL:
    case IRP_MJ_CREATE_NAMED_PIPE:
    case IRP_MJ_CREATE_MAILSLOT:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN
KswordArkFileIrpRequestHasWriteSemantics(
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* Request
    )
/*++

Routine Description:

    在 major 判定之外审计 CREATE 阶段的 disposition/options。查询类 major 也要先
    打开目标；如果调用方把该打开改成 FILE_CREATE/OPEN_IF/OVERWRITE 或
    FILE_DELETE_ON_CLOSE，它同样会改变文件系统，必须要求确认令牌。

--*/
{
    if (KswordArkFileIrpMajorIsWriteLike(Request->majorFunction)) {
        return TRUE;
    }
    if (Request->createDisposition >= FILE_CREATE &&
        Request->createDisposition <= FILE_OVERWRITE_IF) {
        return TRUE;
    }
    return ((Request->createOptions & FILE_DELETE_ON_CLOSE) != 0UL) ? TRUE : FALSE;
}

static BOOLEAN
KswordArkFileIrpMajorIsDangerous(
    _In_ ULONG MajorFunction
    )
/*++

Routine Description:

    判断一个 major 是否属于"对文件系统栈发送本身就不符合设计意图"的类别。
    这些请求由 PnP/电源管理器按严格状态机下发，手工构造极易让目标驱动进入
    非法状态，因此额外要求 ALLOW_DANGEROUS 标志。

Arguments:

    MajorFunction - IRP_MJ_* 值。

Return Value:

    TRUE 表示需要额外确认。

--*/
{
    switch (MajorFunction) {
    case IRP_MJ_POWER:
    case IRP_MJ_PNP:
    case IRP_MJ_SYSTEM_CONTROL:
    case IRP_MJ_SHUTDOWN:
    case IRP_MJ_DEVICE_CHANGE:
        return TRUE;
    default:
        return FALSE;
    }
}

static VOID
KswordArkFileIrpFillStackLocation(
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* Request,
    _In_ PIO_STACK_LOCATION StackLocation,
    _In_opt_ PVOID DataBuffer,
    _In_ ULONG DataBytes,
    _In_opt_ PUNICODE_STRING Pattern,
    _In_ PLARGE_INTEGER LockLength
    )
/*++

Routine Description:

    按 major 填写 IO_STACK_LOCATION 的参数联合体。每个分支只写该 major 定义的
    字段，未定义字段保持为零，避免把上一层的残留值当作有效参数传下去。

Arguments:

    Request - 请求快照。
    StackLocation - 目标驱动将要读取的栈位置。
    DataBuffer/DataBytes - 已准备好的数据缓冲。
    Pattern - DIRECTORY_CONTROL 的文件名通配符。
    LockLength - LOCK_CONTROL 的长度值。IRP 只保存指针，因此这块存储必须由
        调用方持有到请求完成，不能是本函数的局部变量。

Return Value:

    无。

--*/
{
    LARGE_INTEGER byteOffset;

    byteOffset.QuadPart = (LONGLONG)Request->byteOffset;

    switch (Request->majorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CREATE_NAMED_PIPE:
    case IRP_MJ_CREATE_MAILSLOT:
        // CREATE 已在打开阶段完成，这里只可能是 R3 要求"只做 CREATE"，
        // 参数不需要重复填写。
        break;

    case IRP_MJ_READ:
        StackLocation->Parameters.Read.Length = DataBytes;
        StackLocation->Parameters.Read.ByteOffset = byteOffset;
        StackLocation->Parameters.Read.Key = Request->lockKey;
        break;

    case IRP_MJ_WRITE:
        StackLocation->Parameters.Write.Length = DataBytes;
        StackLocation->Parameters.Write.ByteOffset = byteOffset;
        StackLocation->Parameters.Write.Key = Request->lockKey;
        break;

    case IRP_MJ_QUERY_INFORMATION:
        StackLocation->Parameters.QueryFile.Length = DataBytes;
        StackLocation->Parameters.QueryFile.FileInformationClass =
            (FILE_INFORMATION_CLASS)Request->informationClass;
        break;

    case IRP_MJ_SET_INFORMATION:
        StackLocation->Parameters.SetFile.Length = DataBytes;
        StackLocation->Parameters.SetFile.FileInformationClass =
            (FILE_INFORMATION_CLASS)Request->informationClass;
        break;

    case IRP_MJ_QUERY_EA:
        StackLocation->Parameters.QueryEa.Length = DataBytes;
        break;

    case IRP_MJ_SET_EA:
        StackLocation->Parameters.SetEa.Length = DataBytes;
        break;

    case IRP_MJ_QUERY_VOLUME_INFORMATION:
        StackLocation->Parameters.QueryVolume.Length = DataBytes;
        StackLocation->Parameters.QueryVolume.FsInformationClass =
            (FS_INFORMATION_CLASS)Request->informationClass;
        break;

    case IRP_MJ_SET_VOLUME_INFORMATION:
        StackLocation->Parameters.SetVolume.Length = DataBytes;
        StackLocation->Parameters.SetVolume.FsInformationClass =
            (FS_INFORMATION_CLASS)Request->informationClass;
        break;

    case IRP_MJ_DIRECTORY_CONTROL:
        if (Request->minorFunction == IRP_MN_QUERY_DIRECTORY) {
            StackLocation->Parameters.QueryDirectory.Length = DataBytes;
            StackLocation->Parameters.QueryDirectory.FileName = Pattern;
            StackLocation->Parameters.QueryDirectory.FileInformationClass =
                (FILE_INFORMATION_CLASS)Request->informationClass;
        }
        else {
            StackLocation->Parameters.NotifyDirectory.Length = DataBytes;
            StackLocation->Parameters.NotifyDirectory.CompletionFilter =
                Request->informationClass;
        }
        break;

    // 下面三个控制码分支必须和其它分支一样、只用 DataBytes 推导长度。
    // Request->inputBytes / outputBytes 是 R3 自述值，而实际交给目标驱动的缓冲
    // 只有 DataBytes 字节（= max(实际输入长度, 与响应容量取小后的输出长度)）。
    // 一旦自述值大于 DataBytes，目标驱动就会按自述长度往这块池内存里写，
    // 直接越过分配边界 —— 正是 0x13A KERNEL_MODE_HEAP_CORRUPTION 的成因。
    // 取小不改变正常路径：正常情况下两者本就相等。
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        StackLocation->Parameters.FileSystemControl.FsControlCode =
            Request->controlCode;
        StackLocation->Parameters.FileSystemControl.InputBufferLength =
            (Request->inputBytes < DataBytes) ? Request->inputBytes : DataBytes;
        StackLocation->Parameters.FileSystemControl.OutputBufferLength =
            (Request->outputBytes < DataBytes) ? Request->outputBytes : DataBytes;
        break;

    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        StackLocation->Parameters.DeviceIoControl.IoControlCode =
            Request->controlCode;
        StackLocation->Parameters.DeviceIoControl.InputBufferLength =
            (Request->inputBytes < DataBytes) ? Request->inputBytes : DataBytes;
        StackLocation->Parameters.DeviceIoControl.OutputBufferLength =
            (Request->outputBytes < DataBytes) ? Request->outputBytes : DataBytes;
        break;

    case IRP_MJ_LOCK_CONTROL:
        StackLocation->Parameters.LockControl.Key = Request->lockKey;
        StackLocation->Parameters.LockControl.ByteOffset = byteOffset;
        StackLocation->Parameters.LockControl.Length = LockLength;
        break;

    case IRP_MJ_QUERY_SECURITY:
        StackLocation->Parameters.QuerySecurity.SecurityInformation =
            Request->securityInformation;
        StackLocation->Parameters.QuerySecurity.Length = DataBytes;
        break;

    case IRP_MJ_SET_SECURITY:
        StackLocation->Parameters.SetSecurity.SecurityInformation =
            Request->securityInformation;
        StackLocation->Parameters.SetSecurity.SecurityDescriptor = DataBuffer;
        break;

    case IRP_MJ_QUERY_QUOTA:
        StackLocation->Parameters.QueryQuota.Length = DataBytes;
        break;

    case IRP_MJ_SET_QUOTA:
        StackLocation->Parameters.SetQuota.Length = DataBytes;
        break;

    case IRP_MJ_POWER:
        // 电源请求的参数联合体由 minor 决定。这里只按系统电源状态填写，
        // informationClass 复用为目标 SYSTEM_POWER_STATE；其余字段保持为零，
        // 让目标驱动按未支持处理而不是读到脏值。
        StackLocation->Parameters.Power.SystemContext = 0UL;
        StackLocation->Parameters.Power.Type = SystemPowerState;
        StackLocation->Parameters.Power.State.SystemState =
            (SYSTEM_POWER_STATE)Request->informationClass;
        break;

    default:
        // SHUTDOWN/CLEANUP/CLOSE/FLUSH/PNP/SYSTEM_CONTROL/DEVICE_CHANGE 不需要
        // 通用参数；PNP 的具体 minor 参数由目标驱动按 minor 自行解释。
        break;
    }
}

static NTSTATUS
KswordArkFileIrpExecuteOperation(
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* Request,
    _In_ PKSWORD_ARK_FILE_IRP_TARGET Target,
    _In_reads_bytes_opt_(InputBytes) const void* InputData,
    _In_ ULONG InputBytes,
    _In_ ULONG TimeoutMs,
    _Out_writes_bytes_to_(OutputCapacity, *OutputBytesOut) PVOID OutputBuffer,
    _In_ ULONG OutputCapacity,
    _Out_ PULONG OutputBytesOut,
    _Out_ PULONGLONG InformationOut,
    _Out_ PBOOLEAN CancelledOut
    )
/*++

Routine Description:

    构造并投递目标 major 的 IRP，然后把结果数据拷回响应缓冲。

Arguments:

    Request - 请求快照。
    Target - 已打开的目标视图。
    InputData/InputBytes - R3 提供的内联输入数据。
    TimeoutMs - 等待上限。
    OutputBuffer/OutputCapacity - 响应中可写的数据区。
    OutputBytesOut - 实际写回字节数。
    InformationOut - IoStatus.Information。
    CancelledOut - TRUE 表示超时取消。

Return Value:

    目标 major 的 NTSTATUS。

--*/
{
    PIRP irp = NULL;
    PIO_STACK_LOCATION stackLocation = NULL;
    KSWORD_ARK_FILE_IRP_SYNC sync;
    KSWORD_ARK_FILE_IRP_BUFFER_MODE bufferMode = KswordArkFileIrpBufferNone;
    PVOID dataBuffer = NULL;
    PMDL dataMdl = NULL;
    ULONG dataBytes = 0UL;
    ULONG requestedOutputBytes = 0UL;
    ULONG transferMethod = 0UL;
    UNICODE_STRING pattern;
    PUNICODE_STRING patternPointer = NULL;
    LARGE_INTEGER lockLength;
    BOOLEAN powerIrp = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    *OutputBytesOut = 0UL;
    *InformationOut = 0ULL;
    *CancelledOut = FALSE;

    if (Target->TargetDevice == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    lockLength.QuadPart = (LONGLONG)Request->lockLength;

    // 数据段容量取"输入长度"和"可写回的输出长度"的较大者：METHOD_BUFFERED 语义下
    // 两者共用一块缓冲，分开分配反而会让目标驱动读到不一致的视图。请求的输出长度
    // 先与响应实际可容纳的字节数取小，避免驱动写满一块 R3 根本收不走的缓冲。
    requestedOutputBytes = (Request->outputBytes < OutputCapacity)
        ? Request->outputBytes
        : OutputCapacity;
    dataBytes = (InputBytes > requestedOutputBytes)
        ? InputBytes
        : requestedOutputBytes;

    bufferMode = KswordArkFileIrpBufferModeForMajor(Request->majorFunction);
    if (bufferMode != KswordArkFileIrpBufferNone && dataBytes != 0UL) {
        dataBuffer = KswordArkFileIrpAllocate(dataBytes);
        if (dataBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (InputData != NULL && InputBytes != 0UL) {
            RtlCopyMemory(dataBuffer, InputData, InputBytes);
        }
    }

    irp = IoAllocateIrp(Target->TargetDevice->StackSize, FALSE);
    if (irp == NULL) {
        KswordArkFileIrpFree(dataBuffer);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&sync, sizeof(sync));
    KeInitializeEvent(&sync.Event, NotificationEvent, FALSE);
    sync.IoStatus.Status = STATUS_UNSUCCESSFUL;

    irp->MdlAddress = NULL;
    irp->AssociatedIrp.SystemBuffer = NULL;
    irp->UserBuffer = NULL;
    irp->Flags = IRP_SYNCHRONOUS_API;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = &sync.IoStatus;
    irp->UserEvent = NULL;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = Target->FileObject;
    // PnP 请求约定初值为未支持，中间层才能正确判断"是否有人处理过"。
    irp->IoStatus.Status = (Request->majorFunction == IRP_MJ_PNP)
        ? STATUS_NOT_SUPPORTED
        : STATUS_SUCCESS;
    irp->IoStatus.Information = 0ULL;

    stackLocation = IoGetNextIrpStackLocation(irp);
    stackLocation->MajorFunction = (UCHAR)Request->majorFunction;
    stackLocation->MinorFunction = (UCHAR)Request->minorFunction;
    stackLocation->DeviceObject = Target->TargetDevice;
    stackLocation->FileObject = Target->FileObject;
    stackLocation->Flags = 0U;
    if ((Request->flags & KSWORD_ARK_FILE_IRP_FLAG_RESTART_SCAN) != 0UL) {
        stackLocation->Flags |= SL_RESTART_SCAN;
    }
    if ((Request->flags & KSWORD_ARK_FILE_IRP_FLAG_RETURN_SINGLE_ENTRY) != 0UL) {
        stackLocation->Flags |= SL_RETURN_SINGLE_ENTRY;
    }

    // 绑定数据缓冲。
    switch (bufferMode) {
    case KswordArkFileIrpBufferSystem:
        // 只置 IRP_BUFFERED_IO，不置 IRP_DEALLOCATE_BUFFER：缓冲由本模块分配，
        // 释放责任也必须留在本模块，交给 I/O 管理器会造成双重释放。
        irp->AssociatedIrp.SystemBuffer = dataBuffer;
        irp->Flags |= IRP_BUFFERED_IO;
        break;

    case KswordArkFileIrpBufferUser:
        irp->UserBuffer = dataBuffer;
        if (dataBuffer != NULL &&
            (Target->TargetDevice->Flags & DO_DIRECT_IO) != 0UL) {
            dataMdl = IoAllocateMdl(dataBuffer, dataBytes, FALSE, FALSE, NULL);
            if (dataMdl == NULL) {
                IoFreeIrp(irp);
                KswordArkFileIrpFree(dataBuffer);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            MmBuildMdlForNonPagedPool(dataMdl);
            irp->MdlAddress = dataMdl;
        }
        break;

    case KswordArkFileIrpBufferDeviceFlags:
        if (dataBuffer != NULL) {
            if ((Target->TargetDevice->Flags & DO_BUFFERED_IO) != 0UL) {
                irp->AssociatedIrp.SystemBuffer = dataBuffer;
                irp->UserBuffer = dataBuffer;
            }
            else if ((Target->TargetDevice->Flags & DO_DIRECT_IO) != 0UL) {
                dataMdl = IoAllocateMdl(dataBuffer, dataBytes, FALSE, FALSE, NULL);
                if (dataMdl == NULL) {
                    IoFreeIrp(irp);
                    KswordArkFileIrpFree(dataBuffer);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                MmBuildMdlForNonPagedPool(dataMdl);
                irp->MdlAddress = dataMdl;
            }
            else {
                irp->UserBuffer = dataBuffer;
            }
        }
        irp->Flags |= (Request->majorFunction == IRP_MJ_READ)
            ? IRP_READ_OPERATION
            : IRP_WRITE_OPERATION;
        irp->Flags |= IRP_NOCACHE;
        break;

    case KswordArkFileIrpBufferControlCode:
        transferMethod = Request->controlCode & 3UL;
        if (dataBuffer != NULL) {
            if (transferMethod == METHOD_BUFFERED) {
                irp->AssociatedIrp.SystemBuffer = dataBuffer;
                irp->UserBuffer = dataBuffer;
            }
            else if (transferMethod == METHOD_IN_DIRECT ||
                     transferMethod == METHOD_OUT_DIRECT) {
                irp->AssociatedIrp.SystemBuffer = dataBuffer;
                dataMdl = IoAllocateMdl(dataBuffer, dataBytes, FALSE, FALSE, NULL);
                if (dataMdl == NULL) {
                    IoFreeIrp(irp);
                    KswordArkFileIrpFree(dataBuffer);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                MmBuildMdlForNonPagedPool(dataMdl);
                irp->MdlAddress = dataMdl;
            }
            else {
                stackLocation->Parameters.DeviceIoControl.Type3InputBuffer =
                    dataBuffer;
                irp->UserBuffer = dataBuffer;
            }
        }
        break;

    case KswordArkFileIrpBufferNone:
    default:
        break;
    }

    if (Request->majorFunction == IRP_MJ_DIRECTORY_CONTROL &&
        Request->patternLengthChars != 0U) {
        RtlZeroMemory(&pattern, sizeof(pattern));
        pattern.Buffer = (PWCH)Request->pattern;
        pattern.Length = (USHORT)(Request->patternLengthChars * sizeof(WCHAR));
        pattern.MaximumLength = (USHORT)(pattern.Length + sizeof(WCHAR));
        patternPointer = &pattern;
    }

    KswordArkFileIrpFillStackLocation(
        Request,
        stackLocation,
        dataBuffer,
        dataBytes,
        patternPointer,
        &lockLength);

    IoSetCompletionRoutine(
        irp,
        KswordArkFileIrpCompletion,
        &sync,
        TRUE,
        TRUE,
        TRUE);

    powerIrp = (Request->majorFunction == IRP_MJ_POWER) ? TRUE : FALSE;
    status = KswordArkFileIrpCallAndWait(
        Target->TargetDevice,
        irp,
        &sync,
        TimeoutMs,
        powerIrp,
        CancelledOut);

    if (powerIrp) {
        // 电源请求约定：无论结果如何都必须放行队列中的下一个电源 IRP。
        PoStartNextPowerIrp(irp);
    }

    *InformationOut = (ULONGLONG)sync.IoStatus.Information;

    // 回填输出数据。Information 是目标驱动的自述值，不能直接当作可信长度：
    // 落在 (0, dataBytes] 内才采信，否则退回"R3 请求的输出窗口"，让调用方仍能
    // 看到缓冲原样内容并自行判断。最后一律与实际容量取小。
    if (dataBuffer != NULL && OutputBuffer != NULL && OutputCapacity != 0UL) {
        ULONG copyBytes = (ULONG)sync.IoStatus.Information;
        if (copyBytes == 0UL || copyBytes > dataBytes) {
            copyBytes = requestedOutputBytes;
        }
        if (copyBytes > dataBytes) {
            copyBytes = dataBytes;
        }
        if (copyBytes > OutputCapacity) {
            copyBytes = OutputCapacity;
        }
        if (copyBytes != 0UL) {
            RtlCopyMemory(OutputBuffer, dataBuffer, copyBytes);
        }
        *OutputBytesOut = copyBytes;
    }

    if (dataMdl != NULL) {
        irp->MdlAddress = NULL;
        IoFreeMdl(dataMdl);
    }
    IoFreeIrp(irp);
    KswordArkFileIrpFree(dataBuffer);
    return status;
}

NTSTATUS
KswordARKDriverSubmitFileIrp(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* Request,
    _In_reads_bytes_opt_(InputBytes) const void* InputData,
    _In_ ULONG InputBytes,
    _Out_ size_t* BytesWrittenOut
    )
{
    KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE* response = NULL;
    KSWORD_ARK_FILE_IRP_TARGET target;
    ULONG outputCapacity = 0UL;
    ULONG outputBytes = 0UL;
    ULONG stageFlags = 0UL;
    ULONG timeoutMs = 0UL;
    ULONGLONG information = 0ULL;
    BOOLEAN cancelled = FALSE;
    NTSTATUS cleanupStatus = STATUS_SUCCESS;
    NTSTATUS closeStatus = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    outputCapacity = (ULONG)(
        OutputBufferLength - KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE);

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION;
    response->size = KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE;
    response->status = KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST;
    response->majorFunction = Request->majorFunction;
    response->minorFunction = Request->minorFunction;
    response->targetLayer = Request->targetLayer;
    response->createStatus = STATUS_UNSUCCESSFUL;
    response->operationStatus = STATUS_UNSUCCESSFUL;
    response->cleanupStatus = STATUS_UNSUCCESSFUL;
    response->closeStatus = STATUS_UNSUCCESSFUL;
    *BytesWrittenOut = KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->status = KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST;
        response->operationStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_SUCCESS;
    }
    if (Request->majorFunction > IRP_MJ_MAXIMUM_FUNCTION ||
        Request->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX) {
        response->operationStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    // 写语义与危险 major 的双重闸门：先看令牌，再看专用标志。
    if (KswordArkFileIrpRequestHasWriteSemantics(Request) ||
        KswordArkFileIrpMajorIsDangerous(Request->majorFunction)) {
        if ((Request->flags & KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED) == 0UL ||
            Request->confirmationToken != KSWORD_ARK_FILE_IRP_CONFIRMATION_TOKEN) {
            response->status = KSWORD_ARK_FILE_IRP_STATUS_CONFIRMATION_REQUIRED;
            response->operationStatus = STATUS_ACCESS_DENIED;
            return STATUS_SUCCESS;
        }
    }
    if (KswordArkFileIrpMajorIsDangerous(Request->majorFunction) &&
        (Request->flags & KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS) == 0UL) {
        response->status = KSWORD_ARK_FILE_IRP_STATUS_MAJOR_NOT_ALLOWED;
        response->operationStatus = STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    }

    timeoutMs = Request->timeoutMs;
    if (timeoutMs == 0UL || timeoutMs > KSWORD_ARK_FILE_IRP_MAX_TIMEOUT_MS) {
        timeoutMs = KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS;
    }

    RtlZeroMemory(&target, sizeof(target));
    status = KswordArkFileIrpOpenTarget(Request, timeoutMs, &target);
    response->createStatus = status;
    stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_CREATE;
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_FILE_IRP_STATUS_OPEN_FAILED;
        response->stageFlags = stageFlags;
        return STATUS_SUCCESS;
    }

    target.TargetDevice = KswordArkFileIrpSelectLayer(
        &target,
        Request->targetLayer,
        &target.ResolvedLayer);
    response->targetLayer = target.ResolvedLayer;
    response->fileObjectAddress = (ULONGLONG)(ULONG_PTR)target.FileObject;
    response->relatedDeviceAddress = (ULONGLONG)(ULONG_PTR)target.RelatedDevice;
    response->baseFsDeviceAddress = (ULONGLONG)(ULONG_PTR)target.BaseFsDevice;
    response->vpbDeviceAddress = (ULONGLONG)(ULONG_PTR)target.VpbDevice;
    response->targetDeviceAddress = (ULONGLONG)(ULONG_PTR)target.TargetDevice;

    if (target.TargetDevice != NULL) {
        response->targetStackSize = (ULONG)target.TargetDevice->StackSize;
        response->targetDeviceFlags = target.TargetDevice->Flags;
        response->targetDriverAddress =
            (ULONGLONG)(ULONG_PTR)target.TargetDevice->DriverObject;
        if (target.TargetDevice->DriverObject != NULL &&
            Request->majorFunction <= IRP_MJ_MAXIMUM_FUNCTION) {
            response->dispatchAddress = (ULONGLONG)(ULONG_PTR)
                target.TargetDevice->DriverObject->MajorFunction[
                    Request->majorFunction];
        }
        KswordArkFileIrpCopyObjectName(
            target.TargetDevice->DriverObject,
            response->driverName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS,
            &response->driverNameLengthChars);
        KswordArkFileIrpCopyObjectName(
            target.TargetDevice,
            response->deviceName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS,
            &response->deviceNameLengthChars);
    }

    // CREATE_ONLY 只验证打开阶段，不再向下发送任何请求。
    if ((Request->flags & KSWORD_ARK_FILE_IRP_FLAG_CREATE_ONLY) != 0UL ||
        Request->majorFunction == IRP_MJ_CREATE) {
        response->status = KSWORD_ARK_FILE_IRP_STATUS_OK;
        response->operationStatus = status;
    }
    else {
        NTSTATUS operationStatus = KswordArkFileIrpExecuteOperation(
            Request,
            &target,
            InputData,
            InputBytes,
            timeoutMs,
            response->outputData,
            outputCapacity,
            &outputBytes,
            &information,
            &cancelled);
        stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_OPERATION;
        response->operationStatus = operationStatus;
        response->information = information;
        response->outputBytes = outputBytes;
        if (cancelled) {
            stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_CANCELLED;
            response->status = KSWORD_ARK_FILE_IRP_STATUS_TIMEOUT;
        }
        else if (information > (ULONGLONG)outputBytes) {
            stageFlags |= KSWORD_ARK_FILE_IRP_STAGE_OUTPUT_TRUNCATED;
            response->status = KSWORD_ARK_FILE_IRP_STATUS_OK;
        }
        else {
            response->status = KSWORD_ARK_FILE_IRP_STATUS_OK;
        }
    }

    // 收尾无条件执行。SKIP_CLEANUP_CLOSE 只表达"调用方打算自己配对 CLEANUP/CLOSE"，
    // 但一次 IOCTL 结束后 R3 已经无法再引用这个内核文件对象，跳过收尾等于永久泄漏
    // 一个文件对象和一份卷引用，因此该标志不改变此处的释放行为。
    KswordArkFileIrpCloseTarget(
        &target,
        timeoutMs,
        &cleanupStatus,
        &closeStatus,
        &stageFlags);
    response->cleanupStatus = cleanupStatus;
    response->closeStatus = closeStatus;

    response->stageFlags = stageFlags;
    response->size =
        KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE + response->outputBytes;
    *BytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordArkFileIrpConsumeDirectoryBuffer(
    _In_reads_bytes_(NativeBytes) const UCHAR* NativeBuffer,
    _In_ ULONG NativeBytes,
    _In_ ULONG StartIndex,
    _In_ ULONG MaximumRows,
    _Inout_ PULONG VisibleIndex,
    _Inout_ KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE* Response,
    _Out_ PBOOLEAN PageCompleteOut
    )
/*++

Routine Description:

    把一段 FILE_ID_BOTH_DIR_INFORMATION 链转换为固定协议行。逐字段边界校验与
    file_directory_query.c 保持一致，两条路径的行内容才能直接做差集比较。

Arguments:

    NativeBuffer/NativeBytes - 目标驱动写回的原生缓冲。
    StartIndex - 当前页首个可见条目索引。
    MaximumRows - 本页最大行数。
    VisibleIndex - 跨缓冲累计的可见索引。
    Response - 接收行的响应。
    PageCompleteOut - TRUE 表示本页已满。

Return Value:

    STATUS_SUCCESS 或 STATUS_DATA_ERROR。

--*/
{
    ULONG nativeOffset = 0UL;
    const ULONG nativeHeaderBytes =
        FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);

    *PageCompleteOut = FALSE;

    while (nativeOffset < NativeBytes) {
        const FILE_ID_BOTH_DIR_INFORMATION* nativeEntry = NULL;
        KSWORD_ARK_DIRECTORY_ENTRY* outputEntry = NULL;
        ULONG remainingBytes = NativeBytes - nativeOffset;
        ULONG nameChars = 0UL;
        ULONG copyNameChars = 0UL;
        ULONG minimumEntryBytes = 0UL;
        BOOLEAN dotEntry = FALSE;

        if (remainingBytes < nativeHeaderBytes) {
            return STATUS_DATA_ERROR;
        }

        nativeEntry = (const FILE_ID_BOTH_DIR_INFORMATION*)(
            NativeBuffer + nativeOffset);
        if ((nativeEntry->FileNameLength % sizeof(WCHAR)) != 0U) {
            return STATUS_DATA_ERROR;
        }
        if (nativeEntry->FileNameLength > remainingBytes - nativeHeaderBytes) {
            return STATUS_DATA_ERROR;
        }

        minimumEntryBytes = nativeHeaderBytes + nativeEntry->FileNameLength;
        if (nativeEntry->NextEntryOffset != 0UL &&
            (nativeEntry->NextEntryOffset < minimumEntryBytes ||
                nativeEntry->NextEntryOffset > remainingBytes)) {
            return STATUS_DATA_ERROR;
        }

        dotEntry = (nativeEntry->FileNameLength == sizeof(WCHAR) &&
                nativeEntry->FileName[0] == L'.') ||
            (nativeEntry->FileNameLength == (2U * sizeof(WCHAR)) &&
                nativeEntry->FileName[0] == L'.' &&
                nativeEntry->FileName[1] == L'.');

        if (!dotEntry) {
            if (*VisibleIndex < StartIndex) {
                *VisibleIndex += 1UL;
            }
            else if (Response->rowCount >= MaximumRows) {
                Response->responseFlags |=
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE;
                *PageCompleteOut = TRUE;
                return STATUS_SUCCESS;
            }
            else {
                outputEntry = &Response->rows[Response->rowCount];
                RtlZeroMemory(outputEntry, sizeof(*outputEntry));
                outputEntry->fileAttributes = nativeEntry->FileAttributes;
                outputEntry->fileId = (ULONGLONG)nativeEntry->FileId.QuadPart;
                outputEntry->allocationSize = nativeEntry->AllocationSize.QuadPart;
                outputEntry->endOfFile = nativeEntry->EndOfFile.QuadPart;
                outputEntry->creationTime = nativeEntry->CreationTime.QuadPart;
                outputEntry->lastAccessTime = nativeEntry->LastAccessTime.QuadPart;
                outputEntry->lastWriteTime = nativeEntry->LastWriteTime.QuadPart;
                outputEntry->changeTime = nativeEntry->ChangeTime.QuadPart;

                if ((nativeEntry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL) {
                    outputEntry->flags |=
                        KSWORD_ARK_DIRECTORY_ENTRY_FLAG_DIRECTORY;
                }
                if ((nativeEntry->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0UL) {
                    outputEntry->flags |=
                        KSWORD_ARK_DIRECTORY_ENTRY_FLAG_REPARSE_POINT;
                }

                nameChars = (ULONG)(nativeEntry->FileNameLength / sizeof(WCHAR));
                copyNameChars = nameChars;
                if (copyNameChars >= KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS) {
                    copyNameChars = KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS - 1UL;
                    outputEntry->flags |=
                        KSWORD_ARK_DIRECTORY_ENTRY_FLAG_NAME_TRUNCATED;
                }
                if (copyNameChars != 0UL) {
                    RtlCopyMemory(
                        outputEntry->name,
                        nativeEntry->FileName,
                        copyNameChars * sizeof(WCHAR));
                }
                outputEntry->name[copyNameChars] = L'\0';
                outputEntry->nameLengthChars = copyNameChars;
                Response->rowCount += 1UL;
                *VisibleIndex += 1UL;
            }
        }

        if (nativeEntry->NextEntryOffset == 0UL) {
            break;
        }
        nativeOffset += nativeEntry->NextEntryOffset;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
KswordArkFileIrpQueryDirectoryOnce(
    _In_ PKSWORD_ARK_FILE_IRP_TARGET Target,
    _Out_writes_bytes_(BufferBytes) PVOID Buffer,
    _In_ ULONG BufferBytes,
    _In_ BOOLEAN RestartScan,
    _In_ ULONG TimeoutMs,
    _Out_ PULONG ReturnedBytesOut
    )
/*++

Routine Description:

    向目标层发送一次 IRP_MJ_DIRECTORY_CONTROL/IRP_MN_QUERY_DIRECTORY。

Arguments:

    Target - 已打开的目录目标。
    Buffer/BufferBytes - 非分页接收缓冲。
    RestartScan - TRUE 表示从头开始。
    TimeoutMs - 等待上限。
    ReturnedBytesOut - 目标驱动写回的有效字节数。

Return Value:

    目标驱动返回的 NTSTATUS。

--*/
{
    PIRP irp = NULL;
    PIO_STACK_LOCATION stackLocation = NULL;
    KSWORD_ARK_FILE_IRP_SYNC sync;
    BOOLEAN cancelled = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    *ReturnedBytesOut = 0UL;
    if (Target->TargetDevice == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    irp = IoAllocateIrp(Target->TargetDevice->StackSize, FALSE);
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&sync, sizeof(sync));
    KeInitializeEvent(&sync.Event, NotificationEvent, FALSE);
    sync.IoStatus.Status = STATUS_UNSUCCESSFUL;

    /*
     * 目录查询只挂 UserBuffer，不建 MDL。文件系统取缓冲用的是
     * FsRtlGetUserBuffer：有 MdlAddress 就走 MDL 映射，否则用 UserBuffer，
     * 两条路都成立。但少一层 MDL 就少一处出错面（映射失败、标志不全），
     * 而这里的缓冲本来就是非分页池里的连续内存，直接给虚拟地址最直接。
     */
    irp->MdlAddress = NULL;
    irp->AssociatedIrp.SystemBuffer = NULL;
    irp->UserBuffer = Buffer;
    irp->Flags = IRP_SYNCHRONOUS_API;
    irp->RequestorMode = KernelMode;
    irp->UserIosb = &sync.IoStatus;
    irp->UserEvent = NULL;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = Target->FileObject;

    stackLocation = IoGetNextIrpStackLocation(irp);
    stackLocation->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
    stackLocation->MinorFunction = IRP_MN_QUERY_DIRECTORY;
    stackLocation->DeviceObject = Target->TargetDevice;
    stackLocation->FileObject = Target->FileObject;
    stackLocation->Flags = RestartScan ? SL_RESTART_SCAN : 0U;
    stackLocation->Parameters.QueryDirectory.Length = BufferBytes;
    stackLocation->Parameters.QueryDirectory.FileName = NULL;
    stackLocation->Parameters.QueryDirectory.FileInformationClass =
        FileIdBothDirectoryInformation;

    IoSetCompletionRoutine(
        irp,
        KswordArkFileIrpCompletion,
        &sync,
        TRUE,
        TRUE,
        TRUE);

    status = KswordArkFileIrpCallAndWait(
        Target->TargetDevice,
        irp,
        &sync,
        TimeoutMs,
        FALSE,
        &cancelled);

    if (NT_SUCCESS(status)) {
        *ReturnedBytesOut = (ULONG)sync.IoStatus.Information;
    }

    IoFreeIrp(irp);
    return status;
}

NTSTATUS
KswordARKDriverEnumerateDirectoryByIrp(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
{
    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE* response = NULL;
    KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST openRequest;
    KSWORD_ARK_FILE_IRP_TARGET target;
    PVOID nativeBuffer = NULL;
    ULONG maximumRowsByBuffer = 0UL;
    ULONG maximumRows = 0UL;
    ULONG visibleIndex = 0UL;
    ULONG returnedBytes = 0UL;
    ULONG stageFlags = 0UL;
    BOOLEAN restartScan = TRUE;
    BOOLEAN pageComplete = FALSE;
    NTSTATUS cleanupStatus = STATUS_SUCCESS;
    NTSTATUS closeStatus = STATUS_SUCCESS;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength <
        KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maximumRowsByBuffer = (ULONG)(
        (OutputBufferLength -
            KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
    maximumRows = Request->maxEntries;
    if (maximumRows > maximumRowsByBuffer) {
        maximumRows = maximumRowsByBuffer;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION;
    response->size = KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE;
    response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE;
    response->rowSize = (ULONG)sizeof(KSWORD_ARK_DIRECTORY_ENTRY);
    response->startIndex = Request->startIndex;
    response->nextIndex = Request->startIndex;
    response->targetLayer = Request->targetLayer;
    response->openStatus = STATUS_UNSUCCESSFUL;
    response->lastStatus = STATUS_UNSUCCESSFUL;
    *BytesWrittenOut = KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        maximumRows == 0UL ||
        Request->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_INVALID_REQUEST;
        response->lastStatus = (KeGetCurrentIrql() != PASSIVE_LEVEL)
            ? STATUS_INVALID_DEVICE_STATE
            : STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    /*
     * 目录枚举固定用托管路径打开，而不是按请求层手工构造 FILE_OBJECT。
     *
     * 原因：手工 CREATE 得到的 FILE_OBJECT 虽然能让 NTFS 返回 STATUS_SUCCESS，
     * 但它缺少 I/O 管理器在正常路径上建立的完整关联（RelatedFileObject、
     * 由 IopParseDevice 填充的字段等）。NTFS 随后在 IRP_MJ_DIRECTORY_CONTROL 里
     * 用 NtfsDecodeFileObject 判定打开类型，判不出 UserDirectoryOpen 就直接回
     * STATUS_INVALID_PARAMETER(0xC000000D)——实测 C:\ 上必现。
     *
     * 因此这里退一步：打开走 I/O 管理器，保证文件对象状态完整；
     * 真正需要绕过过滤层的 IRP_MJ_DIRECTORY_CONTROL 仍然按 targetLayer 直发。
     * 这正好覆盖隐藏文件最常用的拦截点——在目录查询完成时改写
     * FILE_*_DIRECTORY_INFORMATION 链表；代价是 CREATE 阶段的拦截绕不过去，
     * 该边界必须如实告诉调用方，不能声称"连打开都绕过了"。
     */
    RtlZeroMemory(&openRequest, sizeof(openRequest));
    openRequest.targetLayer = KSWORD_ARK_FILE_IRP_LAYER_RELATED;
    openRequest.desiredAccess = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    openRequest.shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    openRequest.createDisposition = FILE_OPEN;
    openRequest.fileAttributes = FILE_ATTRIBUTE_NORMAL;
    openRequest.flags = KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT;
    openRequest.pathLengthChars = Request->pathLengthChars;
    RtlCopyMemory(
        openRequest.path,
        Request->path,
        (SIZE_T)Request->pathLengthChars * sizeof(WCHAR));

    RtlZeroMemory(&target, sizeof(target));
    status = KswordArkFileIrpOpenTarget(
        &openRequest,
        KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS,
        &target);
    response->openStatus = status;
    response->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_OPEN_FAILED;
        return STATUS_SUCCESS;
    }

    target.TargetDevice = KswordArkFileIrpSelectLayer(
        &target,
        Request->targetLayer,
        &target.ResolvedLayer);
    response->targetLayer = target.ResolvedLayer;
    response->targetDeviceAddress = (ULONGLONG)(ULONG_PTR)target.TargetDevice;
    if (target.TargetDevice != NULL) {
        response->targetDriverAddress =
            (ULONGLONG)(ULONG_PTR)target.TargetDevice->DriverObject;
        KswordArkFileIrpCopyObjectName(
            target.TargetDevice->DriverObject,
            response->driverName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS,
            &response->driverNameLengthChars);
    }

    nativeBuffer = KswordArkFileIrpAllocate(
        KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES);
    if (nativeBuffer == NULL) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        KswordArkFileIrpCloseTarget(
            &target,
            KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS,
            &cleanupStatus,
            &closeStatus,
            &stageFlags);
        return STATUS_SUCCESS;
    }

    for (;;) {
        RtlZeroMemory(nativeBuffer, KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES);
        returnedBytes = 0UL;
        status = KswordArkFileIrpQueryDirectoryOnce(
            &target,
            nativeBuffer,
            KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES,
            restartScan,
            KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS,
            &returnedBytes);
        restartScan = FALSE;

        if (status == STATUS_NO_MORE_FILES) {
            response->lastStatus = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
            response->lastStatus = status;
            response->queryStatus = (response->rowCount == 0UL)
                ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
            break;
        }
        if (returnedBytes == 0UL ||
            returnedBytes > KSWORD_ARK_FILE_IRP_DIRECTORY_BUFFER_BYTES) {
            response->lastStatus = STATUS_DATA_ERROR;
            response->queryStatus = (response->rowCount == 0UL)
                ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
            break;
        }

        status = KswordArkFileIrpConsumeDirectoryBuffer(
            (const UCHAR*)nativeBuffer,
            returnedBytes,
            Request->startIndex,
            maximumRows,
            &visibleIndex,
            response,
            &pageComplete);
        if (!NT_SUCCESS(status)) {
            response->lastStatus = status;
            response->queryStatus = (response->rowCount == 0UL)
                ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
            break;
        }
        if (pageComplete) {
            response->lastStatus = STATUS_SUCCESS;
            break;
        }
    }

    if (response->queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK;
    }
    response->nextIndex = Request->startIndex + response->rowCount;
    response->size =
        KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
        (response->rowCount * (ULONG)sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
    *BytesWrittenOut = response->size;

    KswordArkFileIrpFree(nativeBuffer);
    KswordArkFileIrpCloseTarget(
        &target,
        KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS,
        &cleanupStatus,
        &closeStatus,
        &stageFlags);
    return STATUS_SUCCESS;
}
