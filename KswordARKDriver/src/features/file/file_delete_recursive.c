/*++

Module Name:

    file_delete_recursive.c

Abstract:

    R0 目录树递归删除。中文说明：R3 侧展开目录依赖 FILE_LIST_DIRECTORY，
    目录 DACL 拒绝列举时就拿不到子项，随后删除父目录必然因“目录非空”失败；
    内核 Zw* 以 KernelMode 前置模式打开对象时不做访问检查，所以递归展开必须
    留在 R0。本模块用显式栈迭代实现后序删除，避免内核栈递归深度失控，并对
    深度、条目总数设硬上限，保证单次 IOCTL 的阻塞时间可预期。

    单个节点的删除动作仍复用 KswordARKDriverDeletePath，保持只读属性归一化、
    FileDispositionInformationEx 回退和映像区段刷新等既有语义。

Environment:

    Kernel-mode Driver Framework，调用线程必须位于 PASSIVE_LEVEL。

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"

#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000UL
#endif

#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000UL
#endif

#define KSWORD_ARK_DELETE_TREE_POOL_TAG 'tDsK'

// 每帧一块固定枚举缓冲：8 KiB 足够容纳一批目录项，且深度上限内总占用可控。
#define KSWORD_ARK_DELETE_TREE_BATCH_BYTES (8UL * 1024UL)

// KSWORD_ARK_DELETE_TREE_FRAME：一层目录的遍历状态。
// 保留批次偏移是为了在进入子目录后能回到同一批次的下一项继续处理，
// 避免每次返回父层都重新枚举导致 O(n^2)。
typedef struct _KSWORD_ARK_DELETE_TREE_FRAME
{
    HANDLE DirectoryHandle;
    ULONG PathLengthChars;
    ULONG BatchOffset;
    ULONG BatchBytes;
    BOOLEAN BatchValid;
    BOOLEAN RestartScan;
    PUCHAR BatchBuffer;
} KSWORD_ARK_DELETE_TREE_FRAME, *PKSWORD_ARK_DELETE_TREE_FRAME;

// KSWORD_ARK_DELETE_TREE_CONTEXT：一次递归删除的全部可变状态。
// PathBuffer 是唯一的路径工作区，压栈时追加子项名、弹栈时截断回父目录长度。
typedef struct _KSWORD_ARK_DELETE_TREE_CONTEXT
{
    PWCHAR PathBuffer;
    ULONG PathCapacityChars;
    PKSWORD_ARK_DELETE_TREE_FRAME Frames;
    ULONG FrameCapacity;
    ULONG FrameCount;
    PUCHAR BatchPool;
    KSWORD_ARK_DELETE_PATH_RESPONSE* Response;
    ULONG DeleteFlags;
    BOOLEAN ContinueOnError;
    BOOLEAN Aborted;
} KSWORD_ARK_DELETE_TREE_CONTEXT, *PKSWORD_ARK_DELETE_TREE_CONTEXT;

static PVOID
KswordARKDeleteTreeAllocate(
    _In_ SIZE_T BufferBytes
    )
/*++

Routine Description:

    为递归删除分配一块清零的非分页缓冲。

Arguments:

    BufferBytes - 请求字节数。

Return Value:

    成功返回缓冲地址，失败返回 NULL。

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
        KSWORD_ARK_DELETE_TREE_POOL_TAG);
#pragma warning(pop)

    if (buffer != NULL) {
        RtlZeroMemory(buffer, BufferBytes);
    }
    return buffer;
}

static VOID
KswordARKDeleteTreeFree(
    _In_opt_ PVOID Buffer
    )
/*++

Routine Description:

    释放 KswordARKDeleteTreeAllocate 分配的缓冲；NULL 输入直接返回。

Arguments:

    Buffer - 待释放地址。

Return Value:

    无。

--*/
{
    if (Buffer != NULL) {
        ExFreePoolWithTag(Buffer, KSWORD_ARK_DELETE_TREE_POOL_TAG);
    }
}

static VOID
KswordARKDeleteTreeReleaseContext(
    _Inout_ PKSWORD_ARK_DELETE_TREE_CONTEXT Context
    )
/*++

Routine Description:

    关闭仍在栈上的目录句柄并释放全部工作缓冲。中断退出路径也必须走这里，
    否则内核句柄会随驱动一直泄漏。

Arguments:

    Context - 递归上下文。

Return Value:

    无。

--*/
{
    ULONG frameIndex;

    if (Context == NULL) {
        return;
    }

    if (Context->Frames != NULL) {
        for (frameIndex = 0U; frameIndex < Context->FrameCount; frameIndex += 1U) {
            if (Context->Frames[frameIndex].DirectoryHandle != NULL) {
                ZwClose(Context->Frames[frameIndex].DirectoryHandle);
                Context->Frames[frameIndex].DirectoryHandle = NULL;
            }
        }
    }
    Context->FrameCount = 0U;

    KswordARKDeleteTreeFree(Context->Frames);
    Context->Frames = NULL;
    KswordARKDeleteTreeFree(Context->BatchPool);
    Context->BatchPool = NULL;
    KswordARKDeleteTreeFree(Context->PathBuffer);
    Context->PathBuffer = NULL;
}

static NTSTATUS
KswordARKDeleteTreePrepareContext(
    _Inout_ PKSWORD_ARK_DELETE_TREE_CONTEXT Context,
    _In_ KSWORD_ARK_DELETE_PATH_RESPONSE* Response,
    _In_ ULONG DeleteFlags,
    _In_ BOOLEAN ContinueOnError
    )
/*++

Routine Description:

    分配路径工作区、帧数组和枚举缓冲池。

Arguments:

    Context - 待初始化的递归上下文。
    Response - 统计回执，由调用方持有。
    DeleteFlags - 要传给单节点删除器的 BACKEND_* 标志。
    ContinueOnError - TRUE 表示单点失败后继续处理同级其余项。

Return Value:

    STATUS_SUCCESS 或 STATUS_INSUFFICIENT_RESOURCES。

--*/
{
    const ULONG frameCapacity = (ULONG)KSWORD_ARK_DELETE_PATH_MAX_DEPTH;
    const SIZE_T pathBytes =
        ((SIZE_T)KSWORD_ARK_DELETE_PATH_TREE_MAX_CHARS + 1U) * sizeof(WCHAR);
    const SIZE_T frameBytes = (SIZE_T)frameCapacity * sizeof(KSWORD_ARK_DELETE_TREE_FRAME);
    const SIZE_T batchBytes = (SIZE_T)frameCapacity * KSWORD_ARK_DELETE_TREE_BATCH_BYTES;
    ULONG frameIndex;

    RtlZeroMemory(Context, sizeof(*Context));
    Context->Response = Response;
    Context->DeleteFlags = DeleteFlags;
    Context->ContinueOnError = ContinueOnError;

    Context->PathBuffer = (PWCHAR)KswordARKDeleteTreeAllocate(pathBytes);
    Context->Frames = (PKSWORD_ARK_DELETE_TREE_FRAME)KswordARKDeleteTreeAllocate(frameBytes);
    Context->BatchPool = (PUCHAR)KswordARKDeleteTreeAllocate(batchBytes);
    if (Context->PathBuffer == NULL ||
        Context->Frames == NULL ||
        Context->BatchPool == NULL) {
        KswordARKDeleteTreeReleaseContext(Context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Context->PathCapacityChars = (ULONG)KSWORD_ARK_DELETE_PATH_TREE_MAX_CHARS;
    Context->FrameCapacity = frameCapacity;
    for (frameIndex = 0U; frameIndex < frameCapacity; frameIndex += 1U) {
        Context->Frames[frameIndex].BatchBuffer =
            Context->BatchPool + ((SIZE_T)frameIndex * KSWORD_ARK_DELETE_TREE_BATCH_BYTES);
    }
    return STATUS_SUCCESS;
}

static VOID
KswordARKDeleteTreeRecordFailure(
    _Inout_ PKSWORD_ARK_DELETE_TREE_CONTEXT Context,
    _In_ ULONG PathLengthChars,
    _In_ NTSTATUS FailureStatus
    )
/*++

Routine Description:

    记录一次删除/枚举失败。中文说明：只保留第一条失败路径，避免响应包无限
    增长；R3 拿到 failedCount 与首个失败路径就能定位问题并决定是否重试。

Arguments:

    Context - 递归上下文。
    PathLengthChars - 当前 PathBuffer 中的有效字符数。
    FailureStatus - 失败 NTSTATUS。

Return Value:

    无。

--*/
{
    ULONG copyChars;

    if (Context == NULL || Context->Response == NULL) {
        return;
    }

    Context->Response->failedCount += 1U;
    Context->Response->lastStatus = FailureStatus;

    if (Context->Response->failedPathLengthChars == 0U && PathLengthChars > 0U) {
        copyChars = PathLengthChars;
        if (copyChars >= KSWORD_ARK_DELETE_PATH_MAX_CHARS) {
            copyChars = KSWORD_ARK_DELETE_PATH_MAX_CHARS - 1U;
        }
        RtlCopyMemory(
            Context->Response->failedPath,
            Context->PathBuffer,
            (SIZE_T)copyChars * sizeof(WCHAR));
        Context->Response->failedPath[copyChars] = L'\0';
        Context->Response->failedPathLengthChars = (unsigned short)copyChars;
    }

    if (!Context->ContinueOnError) {
        Context->Aborted = TRUE;
    }
}

static BOOLEAN
KswordARKDeleteTreeDeleteNode(
    _Inout_ PKSWORD_ARK_DELETE_TREE_CONTEXT Context,
    _In_ ULONG PathLengthChars,
    _In_ BOOLEAN IsDirectory
    )
/*++

Routine Description:

    删除 PathBuffer 当前表示的单个节点，并累加统计。

Arguments:

    Context - 递归上下文。
    PathLengthChars - PathBuffer 有效字符数（不含结尾 NUL）。
    IsDirectory - TRUE 表示以目录语义打开。

Return Value:

    TRUE 表示删除成功。

--*/
{
    NTSTATUS status;

    if (Context == NULL || Context->Response == NULL) {
        return FALSE;
    }

    if (PathLengthChars == 0U || PathLengthChars > MAXUSHORT) {
        KswordARKDeleteTreeRecordFailure(Context, PathLengthChars, STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    Context->PathBuffer[PathLengthChars] = L'\0';
    status = KswordARKDriverDeletePathWithFlags(
        Context->PathBuffer,
        (USHORT)PathLengthChars,
        IsDirectory,
        Context->DeleteFlags);
    if (!NT_SUCCESS(status)) {
        KswordARKDeleteTreeRecordFailure(Context, PathLengthChars, status);
        return FALSE;
    }

    if (IsDirectory) {
        Context->Response->deletedDirectoryCount += 1U;
    }
    else {
        Context->Response->deletedFileCount += 1U;
    }
    return TRUE;
}

static NTSTATUS
KswordARKDeleteTreeQueryAttributes(
    _In_ PCWSTR PathText,
    _In_ ULONG PathLengthChars,
    _Out_ PULONG FileAttributesOut
    )
/*++

Routine Description:

    以 FILE_OPEN_REPARSE_POINT 语义读取节点属性，用于判断“目录 / 重解析点”。
    中文说明：不能用会跟随重解析点的查询，否则符号链接会被当成真实目录进入，
    导致递归删除穿透到链接目标。

Arguments:

    PathText - NT 路径，必须以 NUL 结尾。
    PathLengthChars - 字符数，不含结尾 NUL。
    FileAttributesOut - 接收 FILE_ATTRIBUTE_*。

Return Value:

    ZwCreateFile / ZwQueryInformationFile 的 NTSTATUS。

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    FILE_BASIC_INFORMATION basicInformation;
    HANDLE fileHandle = NULL;
    NTSTATUS status;

    if (PathText == NULL || PathLengthChars == 0U ||
        PathLengthChars > MAXUSHORT || FileAttributesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *FileAttributesOut = 0UL;

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)PathText;
    targetPath.Length = (USHORT)(PathLengthChars * sizeof(WCHAR));
    targetPath.MaximumLength = (USHORT)(targetPath.Length + sizeof(WCHAR));

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        &fileHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_OPEN_FOR_BACKUP_INTENT |
            FILE_OPEN_REPARSE_POINT,
        NULL,
        0U);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&basicInformation, sizeof(basicInformation));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &basicInformation,
        (ULONG)sizeof(basicInformation),
        FileBasicInformation);
    ZwClose(fileHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *FileAttributesOut = basicInformation.FileAttributes;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDeleteTreeOpenDirectory(
    _In_ PCWSTR PathText,
    _In_ ULONG PathLengthChars,
    _Out_ PHANDLE DirectoryHandleOut
    )
/*++

Routine Description:

    打开一层目录用于枚举；全共享打开，避免遍历本身制造额外占用冲突。

Arguments:

    PathText - NT 目录路径，必须以 NUL 结尾。
    PathLengthChars - 字符数，不含结尾 NUL。
    DirectoryHandleOut - 接收目录句柄，成功后由调用方 ZwClose。

Return Value:

    ZwCreateFile 的 NTSTATUS。

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    if (PathText == NULL || PathLengthChars == 0U ||
        PathLengthChars > MAXUSHORT || DirectoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DirectoryHandleOut = NULL;

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)PathText;
    targetPath.Length = (USHORT)(PathLengthChars * sizeof(WCHAR));
    targetPath.MaximumLength = (USHORT)(targetPath.Length + sizeof(WCHAR));

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    return ZwCreateFile(
        DirectoryHandleOut,
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_OPEN_FOR_BACKUP_INTENT,
        NULL,
        0U);
}

static BOOLEAN
KswordARKDeleteTreeIsDotEntry(
    _In_ const FILE_BOTH_DIR_INFORMATION* Entry
    )
/*++

Routine Description:

    判断目录项是否为 "." 或 ".."。

Arguments:

    Entry - 已完成长度校验的目录项。

Return Value:

    TRUE 表示点目录项。

--*/
{
    if (Entry == NULL) {
        return FALSE;
    }

    if (Entry->FileNameLength == sizeof(WCHAR) && Entry->FileName[0] == L'.') {
        return TRUE;
    }

    return Entry->FileNameLength == (2U * sizeof(WCHAR)) &&
        Entry->FileName[0] == L'.' &&
        Entry->FileName[1] == L'.';
}

static BOOLEAN
KswordARKDeleteTreeAppendChildName(
    _Inout_ PKSWORD_ARK_DELETE_TREE_CONTEXT Context,
    _In_ ULONG ParentLengthChars,
    _In_reads_bytes_(NameLengthBytes) PCWCH NameText,
    _In_ ULONG NameLengthBytes,
    _Out_ PULONG ChildLengthCharsOut
    )
/*++

Routine Description:

    在 PathBuffer 上把子项名拼到父目录后面。

Arguments:

    Context - 递归上下文。
    ParentLengthChars - 父目录路径字符数。
    NameText - 目录项名（非 NUL 结尾）。
    NameLengthBytes - 目录项名字节数。
    ChildLengthCharsOut - 接收拼接后的字符数。

Return Value:

    TRUE 表示拼接成功；FALSE 表示名字为空或超出路径上限。

--*/
{
    ULONG nameChars;
    ULONG childChars;

    if (Context == NULL || NameText == NULL || ChildLengthCharsOut == NULL) {
        return FALSE;
    }
    *ChildLengthCharsOut = 0U;

    nameChars = NameLengthBytes / (ULONG)sizeof(WCHAR);
    if (nameChars == 0U) {
        return FALSE;
    }

    childChars = ParentLengthChars + 1U + nameChars;
    if (childChars >= Context->PathCapacityChars) {
        return FALSE;
    }

    Context->PathBuffer[ParentLengthChars] = L'\\';
    RtlCopyMemory(
        &Context->PathBuffer[ParentLengthChars + 1U],
        NameText,
        (SIZE_T)nameChars * sizeof(WCHAR));
    Context->PathBuffer[childChars] = L'\0';
    *ChildLengthCharsOut = childChars;
    return TRUE;
}

static BOOLEAN
KswordARKDeleteTreePushDirectory(
    _Inout_ PKSWORD_ARK_DELETE_TREE_CONTEXT Context,
    _In_ ULONG PathLengthChars
    )
/*++

Routine Description:

    打开 PathBuffer 指向的目录并压栈。压栈失败时由调用方按叶子节点兜底删除。

Arguments:

    Context - 递归上下文。
    PathLengthChars - 目录路径字符数。

Return Value:

    TRUE 表示已压栈，FALSE 表示深度超限或目录打不开。

--*/
{
    PKSWORD_ARK_DELETE_TREE_FRAME frame;
    HANDLE directoryHandle = NULL;
    NTSTATUS status;

    if (Context == NULL || Context->Response == NULL) {
        return FALSE;
    }

    if (Context->FrameCount >= Context->FrameCapacity) {
        Context->Response->responseFlags |=
            KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_DEPTH_LIMITED;
        return FALSE;
    }

    Context->PathBuffer[PathLengthChars] = L'\0';
    status = KswordARKDeleteTreeOpenDirectory(
        Context->PathBuffer,
        PathLengthChars,
        &directoryHandle);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    frame = &Context->Frames[Context->FrameCount];
    frame->DirectoryHandle = directoryHandle;
    frame->PathLengthChars = PathLengthChars;
    frame->BatchOffset = 0U;
    frame->BatchBytes = 0U;
    frame->BatchValid = FALSE;
    frame->RestartScan = TRUE;
    Context->FrameCount += 1U;

    if (Context->FrameCount > Context->Response->maxDepthReached) {
        Context->Response->maxDepthReached = Context->FrameCount;
    }
    return TRUE;
}

static VOID
KswordARKDeleteTreePopDirectory(
    _Inout_ PKSWORD_ARK_DELETE_TREE_CONTEXT Context
    )
/*++

Routine Description:

    关闭栈顶目录句柄，删除该目录本身，并把 PathBuffer 截断回父目录。
    中文说明：句柄必须先关闭再删除，否则自身持有的引用会让目录删除挂起。

Arguments:

    Context - 递归上下文。

Return Value:

    无。

--*/
{
    PKSWORD_ARK_DELETE_TREE_FRAME frame;
    ULONG directoryLengthChars;

    if (Context == NULL || Context->FrameCount == 0U) {
        return;
    }

    Context->FrameCount -= 1U;
    frame = &Context->Frames[Context->FrameCount];
    directoryLengthChars = frame->PathLengthChars;

    if (frame->DirectoryHandle != NULL) {
        ZwClose(frame->DirectoryHandle);
        frame->DirectoryHandle = NULL;
    }
    frame->BatchValid = FALSE;
    frame->BatchBytes = 0U;
    frame->BatchOffset = 0U;

    (VOID)KswordARKDeleteTreeDeleteNode(Context, directoryLengthChars, TRUE);

    if (Context->FrameCount > 0U) {
        Context->PathBuffer[Context->Frames[Context->FrameCount - 1U].PathLengthChars] = L'\0';
    }
}

static BOOLEAN
KswordARKDeleteTreeFetchBatch(
    _Inout_ PKSWORD_ARK_DELETE_TREE_CONTEXT Context,
    _Inout_ PKSWORD_ARK_DELETE_TREE_FRAME Frame
    )
/*++

Routine Description:

    为栈顶目录取下一批目录项。

Arguments:

    Context - 递归上下文。
    Frame - 栈顶帧。

Return Value:

    TRUE 表示已取到一批可处理的目录项；FALSE 表示本层遍历结束
    （枚举完毕或枚举失败，两种情况都由调用方弹栈并删除目录本身）。

--*/
{
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwQueryDirectoryFile(
        Frame->DirectoryHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        Frame->BatchBuffer,
        KSWORD_ARK_DELETE_TREE_BATCH_BYTES,
        FileBothDirectoryInformation,
        FALSE,
        NULL,
        Frame->RestartScan);
    Frame->RestartScan = FALSE;

    if (status == STATUS_NO_MORE_FILES) {
        return FALSE;
    }

    if (!NT_SUCCESS(status)) {
        Context->Response->responseFlags |=
            KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENUM_FAILED;
        KswordARKDeleteTreeRecordFailure(Context, Frame->PathLengthChars, status);
        return FALSE;
    }

    if (ioStatusBlock.Information == 0U ||
        ioStatusBlock.Information > KSWORD_ARK_DELETE_TREE_BATCH_BYTES) {
        return FALSE;
    }

    Frame->BatchBytes = (ULONG)ioStatusBlock.Information;
    Frame->BatchOffset = 0U;
    Frame->BatchValid = TRUE;
    return TRUE;
}

static BOOLEAN
KswordARKDeleteTreeValidateEntry(
    _In_ const KSWORD_ARK_DELETE_TREE_FRAME* Frame,
    _In_ const FILE_BOTH_DIR_INFORMATION* Entry
    )
/*++

Routine Description:

    校验目录项完全落在批次缓冲内。中文说明：文件系统返回的是变长记录，
    不校验就直接按 NextEntryOffset 前进会越界读非分页池。

Arguments:

    Frame - 当前帧，提供批次边界。
    Entry - 待校验目录项。

Return Value:

    TRUE 表示记录长度合法。

--*/
{
    ULONG headerBytes;
    ULONG requiredBytes;

    headerBytes = (ULONG)FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
    if (Frame->BatchOffset > Frame->BatchBytes ||
        (Frame->BatchBytes - Frame->BatchOffset) < headerBytes) {
        return FALSE;
    }

    if (Entry->FileNameLength > (Frame->BatchBytes - Frame->BatchOffset - headerBytes)) {
        return FALSE;
    }
    if ((Entry->FileNameLength % sizeof(WCHAR)) != 0U) {
        return FALSE;
    }

    if (Entry->NextEntryOffset != 0U) {
        requiredBytes = headerBytes + Entry->FileNameLength;
        if (Entry->NextEntryOffset < requiredBytes ||
            Entry->NextEntryOffset > (Frame->BatchBytes - Frame->BatchOffset)) {
            return FALSE;
        }
    }
    return TRUE;
}

static VOID
KswordARKDeleteTreeRun(
    _Inout_ PKSWORD_ARK_DELETE_TREE_CONTEXT Context
    )
/*++

Routine Description:

    后序删除主循环：栈顶目录逐批枚举，文件与重解析点直接删除，普通子目录
    压栈进入；某层枚举结束后弹栈删除目录自身。

Arguments:

    Context - 已压入根目录帧的递归上下文。

Return Value:

    无；结果全部写入 Context->Response。

--*/
{
    PKSWORD_ARK_DELETE_TREE_FRAME frame;
    FILE_BOTH_DIR_INFORMATION* entry;
    ULONG childLengthChars;
    ULONG nextEntryOffset;
    ULONG entryAttributes;
    BOOLEAN entryIsDirectory;
    BOOLEAN entryIsReparsePoint;
    BOOLEAN descended;

    while (Context->FrameCount > 0U && !Context->Aborted) {
        frame = &Context->Frames[Context->FrameCount - 1U];

        if (!frame->BatchValid) {
            if (!KswordARKDeleteTreeFetchBatch(Context, frame)) {
                KswordARKDeleteTreePopDirectory(Context);
                continue;
            }
        }

        descended = FALSE;
        while (frame->BatchOffset < frame->BatchBytes) {
            entry = (FILE_BOTH_DIR_INFORMATION*)(frame->BatchBuffer + frame->BatchOffset);
            if (!KswordARKDeleteTreeValidateEntry(frame, entry)) {
                Context->Response->responseFlags |=
                    KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENUM_FAILED;
                KswordARKDeleteTreeRecordFailure(
                    Context,
                    frame->PathLengthChars,
                    STATUS_INVALID_BUFFER_SIZE);
                frame->BatchOffset = frame->BatchBytes;
                break;
            }

            nextEntryOffset = entry->NextEntryOffset;
            entryAttributes = entry->FileAttributes;
            entryIsDirectory = ((entryAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL) ? TRUE : FALSE;
            entryIsReparsePoint = ((entryAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0UL) ? TRUE : FALSE;

            if (nextEntryOffset == 0U) {
                frame->BatchOffset = frame->BatchBytes;
            }
            else {
                frame->BatchOffset += nextEntryOffset;
            }

            if (KswordARKDeleteTreeIsDotEntry(entry)) {
                continue;
            }

            Context->Response->visitedCount += 1U;
            if (Context->Response->visitedCount > (ULONG)KSWORD_ARK_DELETE_PATH_MAX_ENTRIES) {
                Context->Response->responseFlags |=
                    KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENTRY_LIMITED;
                Context->Aborted = TRUE;
                break;
            }

            if (!KswordARKDeleteTreeAppendChildName(
                    Context,
                    frame->PathLengthChars,
                    entry->FileName,
                    entry->FileNameLength,
                    &childLengthChars)) {
                KswordARKDeleteTreeRecordFailure(
                    Context,
                    frame->PathLengthChars,
                    STATUS_NAME_TOO_LONG);
                if (Context->Aborted) {
                    break;
                }
                continue;
            }

            if (entryIsDirectory && entryIsReparsePoint) {
                // 重解析点目录只删链接本身，绝不跟进目标，否则会删到链接指向的真实数据。
                Context->Response->skippedReparseCount += 1U;
                Context->Response->responseFlags |=
                    KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_REPARSE_SKIPPED;
                (VOID)KswordARKDeleteTreeDeleteNode(Context, childLengthChars, TRUE);
                Context->PathBuffer[frame->PathLengthChars] = L'\0';
                if (Context->Aborted) {
                    break;
                }
                continue;
            }

            if (entryIsDirectory) {
                if (KswordARKDeleteTreePushDirectory(Context, childLengthChars)) {
                    descended = TRUE;
                    break;
                }
                // 打不开或已达深度上限：按叶子兜底删除，空目录仍可成功。
                (VOID)KswordARKDeleteTreeDeleteNode(Context, childLengthChars, TRUE);
                Context->PathBuffer[frame->PathLengthChars] = L'\0';
                if (Context->Aborted) {
                    break;
                }
                continue;
            }

            (VOID)KswordARKDeleteTreeDeleteNode(Context, childLengthChars, FALSE);
            Context->PathBuffer[frame->PathLengthChars] = L'\0';
            if (Context->Aborted) {
                break;
            }
        }

        if (descended) {
            continue;
        }

        if (frame->BatchOffset >= frame->BatchBytes) {
            frame->BatchValid = FALSE;
        }
    }
}

NTSTATUS
KswordARKDriverDeletePathTree(
    _In_ const KSWORD_ARK_DELETE_PATH_REQUEST* Request,
    _Inout_ KSWORD_ARK_DELETE_PATH_RESPONSE* Response
    )
/*++

Routine Description:

    递归删除请求路径。中文说明：目录先在 R0 内展开成后序序列再逐个删除，
    重解析点只删链接本身；深度、条目总数超限时以 PARTIAL 结束并置位对应标志，
    绝不静默截断。

Arguments:

    Request - 已由 IOCTL handler 快照并校验过的删除请求。
    Response - 已初始化过 size/version/requestFlags 的统计回执。

Return Value:

    STATUS_SUCCESS 表示遍历过程本身完成（成功与否看 Response->deleteStatus）；
    参数非法或资源不足时返回对应 NTSTATUS。

--*/
{
    KSWORD_ARK_DELETE_TREE_CONTEXT context;
    ULONG rootAttributes = 0UL;
    ULONG rootLengthChars;
    BOOLEAN continueOnError;
    NTSTATUS status;

    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    rootLengthChars = (ULONG)Request->pathLengthChars;
    if (rootLengthChars == 0U || rootLengthChars >= KSWORD_ARK_DELETE_PATH_MAX_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    // 以反斜杠结尾的路径指向卷根一类的容器，递归删除卷根不是本功能的语义。
    if (Request->path[rootLengthChars - 1U] == L'\\') {
        return STATUS_INVALID_PARAMETER;
    }

    continueOnError =
        ((Request->flags & KSWORD_ARK_DELETE_PATH_FLAG_CONTINUE_ON_ERROR) != 0UL) ? TRUE : FALSE;

    status = KswordARKDeleteTreePrepareContext(
        &context,
        Response,
        Request->flags & KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK,
        continueOnError);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(
        context.PathBuffer,
        Request->path,
        (SIZE_T)rootLengthChars * sizeof(WCHAR));
    context.PathBuffer[rootLengthChars] = L'\0';

    status = KswordARKDeleteTreeQueryAttributes(
        context.PathBuffer,
        rootLengthChars,
        &rootAttributes);
    if (!NT_SUCCESS(status)) {
        KswordARKDeleteTreeRecordFailure(&context, rootLengthChars, status);
        Response->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_FAILED;
        KswordARKDeleteTreeReleaseContext(&context);
        return STATUS_SUCCESS;
    }

    Response->visitedCount += 1U;

    if ((rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0UL) {
        (VOID)KswordARKDeleteTreeDeleteNode(&context, rootLengthChars, FALSE);
    }
    else if ((rootAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0UL) {
        Response->skippedReparseCount += 1U;
        Response->responseFlags |= KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_REPARSE_SKIPPED;
        (VOID)KswordARKDeleteTreeDeleteNode(&context, rootLengthChars, TRUE);
    }
    else if (KswordARKDeleteTreePushDirectory(&context, rootLengthChars)) {
        KswordARKDeleteTreeRun(&context);
    }
    else {
        // 根目录打不开时仍尝试直接删除：空目录场景下这是正确且足够的路径。
        (VOID)KswordARKDeleteTreeDeleteNode(&context, rootLengthChars, TRUE);
    }

    if (Response->failedCount == 0U &&
        (Response->responseFlags &
            (KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_DEPTH_LIMITED |
             KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENTRY_LIMITED |
             KSWORD_ARK_DELETE_PATH_RESPONSE_FLAG_ENUM_FAILED)) == 0UL) {
        Response->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED;
    }
    else if ((Response->deletedFileCount + Response->deletedDirectoryCount) > 0U) {
        Response->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_PARTIAL;
    }
    else {
        Response->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_FAILED;
    }

    KswordARKDeleteTreeReleaseContext(&context);
    return STATUS_SUCCESS;
}
