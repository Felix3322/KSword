/*++

Module Name:

    file_directory_query.c

Abstract:

    通过文件系统驱动在 R0 分页枚举已挂载目录，并把经过边界校验的固定行返回 R3。
    本模块只调用公开 Zw 文件接口，不解析或解引用 NTFS/FAT/exFAT 私有内核结构。

Environment:

    Kernel-mode Driver Framework，调用线程必须位于 PASSIVE_LEVEL。

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"

#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000UL
#endif

// 查询缓冲保持为 64 KiB，既能批量接收目录项，又不会随用户目录大小无限增长。
#define KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES (64UL * 1024UL)
#define KSWORD_ARK_DIRECTORY_POOL_TAG 'dFsK'
#define KSWORD_ARK_DIRECTORY_SCAN_POOL_TAG 'sFsK'

/*
 * 目录续扫缓存。
 *
 * R3 取一个目录要分很多页，而每页原本都重新打开目录、restartScan、再逐项跳过
 * 前 startIndex 条。跳过本身不做转换，但 ZwQueryDirectoryFile 要让文件系统
 * 重新走一遍目录索引，于是总代价随页数平方增长——几千个文件的目录就能明显
 * 卡住界面。
 *
 * 这里把上一次的目录句柄和扫描进度留下来：R3 的分页循环是在同一个驱动句柄上
 * 连续发起的，下一页的 startIndex 必然等于上一页的 nextIndex，此时直接在原句柄
 * 上继续 ZwQueryDirectoryFile 即可，一次目录只需要枚举一遍。
 *
 * 只留一个槽位就够：分页循环中间没有用户交互，不会被打断。左右面板交替枚举时
 * 会互相踢掉缓存，那时退化回"每页重开"的旧行为，结果依然正确，只是慢。
 *
 * 用 InterlockedExchangePointer 做取出/放回，避免为此引入需要初始化的锁对象：
 * 取出即独占，ZwCreateFile/ZwClose 一律在独占期间于 PASSIVE_LEVEL 执行。
 */
typedef struct _KSWORD_ARK_DIRECTORY_SCAN_STATE
{
    HANDLE DirectoryHandle;   // 保持打开的目录句柄。
    ULONG NextVisibleIndex;   // 下一次应当从哪个可见条目索引继续。
    HANDLE OwnerProcessId;    // 建立该句柄的进程，跨进程一律不复用。
    USHORT PathLengthChars;   // 目录路径字符数。
    WCHAR Path[KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS]; // 目录路径。

    /*
     * 上一次 ZwQueryDirectoryFile 取回但没消费完的那批原生数据。
     * 页满是在原生缓冲中间发生的：文件系统一次返回上百条，而协议页可能只装得下
     * 其中一部分。此时文件系统的扫描位置已经在整批之后，剩下那些条目再也读不回来，
     * 因此必须连缓冲本身一起留到下一页继续解析，否则会静默丢条目。
     */
    PVOID PendingBuffer;      // 未消费完的原生缓冲；所有权归本结构。
    ULONG PendingBytes;       // 该缓冲中的有效字节数。
    ULONG PendingOffset;      // 下次应当从哪个偏移继续解析。
} KSWORD_ARK_DIRECTORY_SCAN_STATE, *PKSWORD_ARK_DIRECTORY_SCAN_STATE;

static PVOID volatile g_KswordARKDirectoryScanState = NULL;

static PVOID
KswordARKDirectoryAllocate(
    _In_ SIZE_T BufferBytes
    )
/*++

Routine Description:

    为一次 ZwQueryDirectoryFile 分配固定大小的非分页临时缓冲。

Arguments:

    BufferBytes - 请求字节数。

Return Value:

    成功返回缓冲地址，失败返回 NULL；调用方使用 KswordARKDirectoryFree 释放。

--*/
{
    if (BufferBytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(
        NonPagedPoolNx,
        BufferBytes,
        KSWORD_ARK_DIRECTORY_POOL_TAG);
#pragma warning(pop)
}

static VOID
KswordARKDirectoryFree(
    _In_opt_ PVOID Buffer
    )
/*++

Routine Description:

    释放目录枚举临时缓冲；NULL 输入允许直接返回。

Arguments:

    Buffer - KswordARKDirectoryAllocate 返回的地址。

Return Value:

    无。

--*/
{
    if (Buffer != NULL) {
        ExFreePoolWithTag(Buffer, KSWORD_ARK_DIRECTORY_POOL_TAG);
    }
}

static PKSWORD_ARK_DIRECTORY_SCAN_STATE
KswordARKDirectoryScanStateAcquire(
    VOID
    )
/*++

Routine Description:

    原子取出续扫缓存并置空槽位。取出即独占：调用方在归还前是该句柄的唯一持有者，
    因此后续的 ZwClose/ZwQueryDirectoryFile 不需要额外加锁。

Arguments:

    无。

Return Value:

    缓存指针；槽位为空时返回 NULL。

--*/
{
    return (PKSWORD_ARK_DIRECTORY_SCAN_STATE)InterlockedExchangePointer(
        (PVOID volatile*)&g_KswordARKDirectoryScanState,
        NULL);
}

static VOID
KswordARKDirectoryScanStateFree(
    _In_opt_ PKSWORD_ARK_DIRECTORY_SCAN_STATE ScanState
    )
/*++

Routine Description:

    关闭续扫缓存持有的目录句柄并释放缓存本身。要求 PASSIVE_LEVEL。

Arguments:

    ScanState - 待释放的缓存；NULL 允许直接返回。

Return Value:

    无。

--*/
{
    if (ScanState == NULL) {
        return;
    }
    if (ScanState->DirectoryHandle != NULL) {
        ZwClose(ScanState->DirectoryHandle);
    }
    if (ScanState->PendingBuffer != NULL) {
        KswordARKDirectoryFree(ScanState->PendingBuffer);
    }
    ExFreePoolWithTag(ScanState, KSWORD_ARK_DIRECTORY_SCAN_POOL_TAG);
}

static VOID
KswordARKDirectoryScanStatePublish(
    _In_ PKSWORD_ARK_DIRECTORY_SCAN_STATE ScanState
    )
/*++

Routine Description:

    把续扫缓存放回槽位。若期间另一个请求已经放回了自己的缓存，则丢弃后来者，
    保证任何时刻至多只有一个句柄被缓存。

Arguments:

    ScanState - 要发布的缓存。

Return Value:

    无。

--*/
{
    PKSWORD_ARK_DIRECTORY_SCAN_STATE previous =
        (PKSWORD_ARK_DIRECTORY_SCAN_STATE)InterlockedExchangePointer(
            (PVOID volatile*)&g_KswordARKDirectoryScanState,
            ScanState);
    if (previous != NULL) {
        KswordARKDirectoryScanStateFree(previous);
    }
}

VOID
KswordARKDriverResetDirectoryScanCache(
    VOID
    )
/*++

Routine Description:

    释放续扫缓存。驱动卸载路径必须调用，否则会带着一个未关闭的目录句柄退出。

Arguments:

    无。

Return Value:

    无。

--*/
{
    KswordARKDirectoryScanStateFree(KswordARKDirectoryScanStateAcquire());
}

static BOOLEAN
KswordARKDirectoryIsDotEntry(
    _In_ const FILE_ID_BOTH_DIR_INFORMATION* NativeEntry
    )
/*++

Routine Description:

    判断原生目录项是否为“.”或“..”，这两项不进入 R3 可见索引。

Arguments:

    NativeEntry - 已完成长度校验的原生目录项。

Return Value:

    TRUE 表示点目录项，FALSE 表示普通可见条目。

--*/
{
    if (NativeEntry == NULL) {
        return FALSE;
    }

    if (NativeEntry->FileNameLength == sizeof(WCHAR) &&
        NativeEntry->FileName[0] == L'.') {
        return TRUE;
    }

    return NativeEntry->FileNameLength == (2U * sizeof(WCHAR)) &&
        NativeEntry->FileName[0] == L'.' &&
        NativeEntry->FileName[1] == L'.';
}

static NTSTATUS
KswordARKDirectoryOpenForEnumeration(
    _In_ const KSWORD_ARK_ENUM_DIRECTORY_REQUEST* Request,
    _Out_ HANDLE* DirectoryHandleOut
    )
/*++

Routine Description:

    以只读、全共享、内核句柄方式打开请求目录，避免枚举动作引入额外占用冲突。

Arguments:

    Request - 已由 IOCTL handler 验证的 NT 路径请求。
    DirectoryHandleOut - 接收目录句柄，成功后由调用方 ZwClose。

Return Value:

    ZwCreateFile 返回的 NTSTATUS。

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    if (Request == NULL || DirectoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DirectoryHandleOut = NULL;

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)Request->path;
    targetPath.Length = (USHORT)(Request->pathLengthChars * sizeof(WCHAR));
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

static VOID
KswordARKDirectoryQueryFileSystemName(
    _In_ HANDLE DirectoryHandle,
    _Inout_ KSWORD_ARK_ENUM_DIRECTORY_RESPONSE* Response
    )
/*++

Routine Description:

    查询当前目录句柄所属文件系统名，并在成功时设置 FS_NAME_PRESENT。

Arguments:

    DirectoryHandle - 已打开的目录句柄。
    Response - 当前协议响应头。

Return Value:

    无；文件系统名查询失败不会影响目录项枚举。

--*/
{
    UCHAR informationBuffer[
        sizeof(FILE_FS_ATTRIBUTE_INFORMATION) +
        (KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS * sizeof(WCHAR))];
    FILE_FS_ATTRIBUTE_INFORMATION* attributeInformation = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    ULONG availableNameChars = 0UL;
    ULONG sourceNameChars = 0UL;
    ULONG copyNameChars = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (DirectoryHandle == NULL || Response == NULL) {
        return;
    }

    RtlZeroMemory(informationBuffer, sizeof(informationBuffer));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwQueryVolumeInformationFile(
        DirectoryHandle,
        &ioStatusBlock,
        informationBuffer,
        (ULONG)sizeof(informationBuffer),
        FileFsAttributeInformation);
    if (!NT_SUCCESS(status) ||
        ioStatusBlock.Information < FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)) {
        return;
    }

    attributeInformation = (FILE_FS_ATTRIBUTE_INFORMATION*)informationBuffer;
    availableNameChars = (ULONG)(
        (ioStatusBlock.Information -
            FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)) /
        sizeof(WCHAR));
    sourceNameChars = (ULONG)(attributeInformation->FileSystemNameLength / sizeof(WCHAR));
    copyNameChars = sourceNameChars;
    if (copyNameChars > availableNameChars) {
        copyNameChars = availableNameChars;
    }
    if (copyNameChars >= KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS) {
        copyNameChars = KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS - 1UL;
    }

    if (copyNameChars != 0UL) {
        RtlCopyMemory(
            Response->fileSystemName,
            attributeInformation->FileSystemName,
            copyNameChars * sizeof(WCHAR));
        Response->fileSystemName[copyNameChars] = L'\0';
        Response->fileSystemNameLengthChars = copyNameChars;
        Response->responseFlags |=
            KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_FS_NAME_PRESENT;
    }
}

static NTSTATUS
KswordARKDirectoryConsumeNativeBuffer(
    _In_reads_bytes_(NativeBytes) const UCHAR* NativeBuffer,
    _In_ ULONG NativeBytes,
    _In_ ULONG StartIndex,
    _In_ ULONG MaximumRows,
    _Inout_ ULONG* VisibleIndex,
    _Inout_ KSWORD_ARK_ENUM_DIRECTORY_RESPONSE* Response,
    _Out_ BOOLEAN* PageCompleteOut,
    _Out_ ULONG* NextOffsetOut
    )
/*++

Routine Description:

    校验并转换一个 FILE_ID_BOTH_DIR_INFORMATION 链，按可见索引跳过前页条目。

Arguments:

    NativeBuffer/NativeBytes - ZwQueryDirectoryFile 返回的原生缓冲及有效长度。
    StartIndex - 当前页首个可见条目索引。
    MaximumRows - 协议输出页容量。
    VisibleIndex - 跨原生缓冲累计的可见条目索引。
    Response - 接收固定协议行。
    PageCompleteOut - TRUE 表示已经发现下一页条目，应停止本次扫描。
    NextOffsetOut - 本缓冲中尚未消费的起始偏移。页满提前退出时它指向那个还没被
        收下的条目；正常走完则等于 NativeBytes。续扫必须靠它把这批剩余数据接着
        处理完，否则页满时丢弃的那部分条目会永久消失。

Return Value:

    STATUS_SUCCESS 表示缓冲链有效；STATUS_DATA_ERROR 表示文件系统返回了越界链。

--*/
{
    ULONG nativeOffset = 0UL;
    const ULONG nativeHeaderBytes =
        FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);

    if (NativeBuffer == NULL ||
        VisibleIndex == NULL ||
        Response == NULL ||
        PageCompleteOut == NULL ||
        NextOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *PageCompleteOut = FALSE;
    *NextOffsetOut = NativeBytes;

    while (nativeOffset < NativeBytes) {
        const FILE_ID_BOTH_DIR_INFORMATION* nativeEntry = NULL;
        KSWORD_ARK_DIRECTORY_ENTRY* outputEntry = NULL;
        ULONG remainingBytes = NativeBytes - nativeOffset;
        ULONG nameChars = 0UL;
        ULONG copyNameChars = 0UL;
        ULONG minimumEntryBytes = 0UL;

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

        if (!KswordARKDirectoryIsDotEntry(nativeEntry)) {
            if (*VisibleIndex < StartIndex) {
                *VisibleIndex += 1UL;
            }
            else if (Response->rowCount >= MaximumRows) {
                Response->responseFlags |=
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE;
                // 这一条还没被收下，续扫必须从它开始，不能跳过。
                *NextOffsetOut = nativeOffset;
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

NTSTATUS
KswordARKDriverEnumerateDirectory(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_ENUM_DIRECTORY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    打开目录并从头扫描到 startIndex，返回最多 maxEntries 个经过验证的固定协议行。

Arguments:

    OutputBuffer/OutputBufferLength - METHOD_BUFFERED 输出视图及长度。
    Request - handler 已复制并校验的固定请求快照。
    BytesWrittenOut - 接收协议头与有效行总字节数。

Return Value:

    缓冲本身有效时返回 STATUS_SUCCESS；目录语义失败写入 queryStatus/lastStatus。

--*/
{
    KSWORD_ARK_ENUM_DIRECTORY_RESPONSE* response = NULL;
    HANDLE directoryHandle = NULL;
    PKSWORD_ARK_DIRECTORY_SCAN_STATE scanState = NULL;
    BOOLEAN reusedScanState = FALSE;
    ULONG pendingBytes = 0UL;
    ULONG pendingOffset = 0UL;
    PVOID nativeBuffer = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    ULONG maximumRowsByBuffer = 0UL;
    ULONG maximumRows = 0UL;
    ULONG visibleIndex = 0UL;
    BOOLEAN restartScan = TRUE;
    BOOLEAN pageComplete = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    maximumRowsByBuffer = (ULONG)(
        (OutputBufferLength - KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
    maximumRows = Request->maxEntries;
    if (maximumRows > maximumRowsByBuffer) {
        maximumRows = maximumRowsByBuffer;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_ENUM_DIRECTORY_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_DIRECTORY_ENUM_PROTOCOL_VERSION;
    response->size = (ULONG)KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE;
    response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE;
    response->rowSize = (ULONG)sizeof(KSWORD_ARK_DIRECTORY_ENTRY);
    response->startIndex = Request->startIndex;
    response->nextIndex = Request->startIndex;
    response->openStatus = STATUS_UNSUCCESSFUL;
    response->lastStatus = STATUS_UNSUCCESSFUL;
    *BytesWrittenOut = KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        maximumRows == 0UL ||
        Request->version != KSWORD_ARK_DIRECTORY_ENUM_PROTOCOL_VERSION ||
        Request->size != (ULONG)sizeof(*Request)) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_INVALID_REQUEST;
        response->lastStatus = KeGetCurrentIrql() != PASSIVE_LEVEL
            ? STATUS_INVALID_DEVICE_STATE
            : STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    /*
     * 优先接着上一页继续扫。命中条件是同一进程、同一目录、且请求的起始索引
     * 正好是上次留下的续扫位置——这正是 R3 分页循环的形态。命中时不重新打开
     * 目录，也不 restartScan，直接在原句柄上取下一批，整个目录只枚举一遍。
     */
    scanState = KswordARKDirectoryScanStateAcquire();
    if (scanState != NULL) {
        if (scanState->DirectoryHandle != NULL &&
            scanState->OwnerProcessId == PsGetCurrentProcessId() &&
            scanState->NextVisibleIndex == Request->startIndex &&
            scanState->PathLengthChars == Request->pathLengthChars &&
            RtlEqualMemory(
                scanState->Path,
                Request->path,
                (SIZE_T)Request->pathLengthChars * sizeof(WCHAR))) {
            directoryHandle = scanState->DirectoryHandle;
            visibleIndex = scanState->NextVisibleIndex;
            restartScan = FALSE;
            reusedScanState = TRUE;
        }
        else {
            // 不是接续请求：旧句柄没有价值，立刻释放，避免占着目录不放。
            KswordARKDirectoryScanStateFree(scanState);
            scanState = NULL;
        }
    }

    if (!reusedScanState) {
        status = KswordARKDirectoryOpenForEnumeration(Request, &directoryHandle);
        response->openStatus = status;
        response->lastStatus = status;
        if (!NT_SUCCESS(status)) {
            response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_OPEN_FAILED;
            return STATUS_SUCCESS;
        }
    }
    else {
        // 续扫时没有重新打开动作，打开状态沿用成功语义。
        response->openStatus = STATUS_SUCCESS;
        response->lastStatus = STATUS_SUCCESS;
    }

    KswordARKDirectoryQueryFileSystemName(directoryHandle, response);

    // 续扫时接管上一页没消费完的那批原生数据，连同它的缓冲一起，
    // 从记录的偏移继续解析；否则新分配一块。
    if (reusedScanState && scanState->PendingBuffer != NULL) {
        nativeBuffer = scanState->PendingBuffer;
        pendingBytes = scanState->PendingBytes;
        pendingOffset = scanState->PendingOffset;
        scanState->PendingBuffer = NULL;
        scanState->PendingBytes = 0UL;
        scanState->PendingOffset = 0UL;
    }
    else {
        nativeBuffer = KswordARKDirectoryAllocate(
            KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES);
    }
    if (nativeBuffer == NULL) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        if (scanState != NULL) {
            // 句柄归 scanState 所有，连同缓存一起释放。
            KswordARKDirectoryScanStateFree(scanState);
        }
        else {
            ZwClose(directoryHandle);
        }
        return STATUS_SUCCESS;
    }

    for (;;) {
        ULONG consumedOffset = 0UL;

        // 只有把手上这批消费干净了才去要新数据。
        if (pendingOffset >= pendingBytes) {
            RtlZeroMemory(nativeBuffer, KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES);
            RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
            status = ZwQueryDirectoryFile(
                directoryHandle,
                NULL,
                NULL,
                NULL,
                &ioStatusBlock,
                nativeBuffer,
                KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES,
                FileIdBothDirectoryInformation,
                FALSE,
                NULL,
                restartScan);
            restartScan = FALSE;

            if (status == STATUS_NO_MORE_FILES) {
                response->lastStatus = STATUS_SUCCESS;
                break;
            }
            if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
                response->lastStatus = status;
                response->queryStatus = response->rowCount == 0UL
                    ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                    : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
                break;
            }
            if (ioStatusBlock.Information == 0U ||
                ioStatusBlock.Information > KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES) {
                response->lastStatus = STATUS_DATA_ERROR;
                response->queryStatus = response->rowCount == 0UL
                    ? KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED
                    : KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL;
                break;
            }

            pendingBytes = (ULONG)ioStatusBlock.Information;
            pendingOffset = 0UL;
        }

        status = KswordARKDirectoryConsumeNativeBuffer(
            (const UCHAR*)nativeBuffer + pendingOffset,
            pendingBytes - pendingOffset,
            Request->startIndex,
            maximumRows,
            &visibleIndex,
            response,
            &pageComplete,
            &consumedOffset);
        // consumedOffset 是相对本次传入起点的，累加回全局偏移。
        pendingOffset += consumedOffset;
        if (!NT_SUCCESS(status)) {
            response->lastStatus = status;
            response->queryStatus = response->rowCount == 0UL
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
    response->size = (ULONG)(
        KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
        (response->rowCount * sizeof(KSWORD_ARK_DIRECTORY_ENTRY)));
    *BytesWrittenOut = response->size;

    /*
     * 还有后续页时把句柄和进度留下，下一页就能接着扫；否则立即关闭。
     * 只在语义正常（OK/PARTIAL 之外的失败说明句柄状态已不可信）且确实还有
     * 更多条目时才缓存，避免把一个出错的扫描留给下一次请求继续用。
     */
    {
        const BOOLEAN moreAvailable =
            (response->responseFlags &
                KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE) != 0UL;
        const BOOLEAN semanticOk =
            response->queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK;

        if (moreAvailable && semanticOk) {
            if (scanState == NULL) {
#pragma warning(push)
#pragma warning(disable:4996)
                scanState = (PKSWORD_ARK_DIRECTORY_SCAN_STATE)ExAllocatePoolWithTag(
                    NonPagedPoolNx,
                    sizeof(KSWORD_ARK_DIRECTORY_SCAN_STATE),
                    KSWORD_ARK_DIRECTORY_SCAN_POOL_TAG);
#pragma warning(pop)
            }
            if (scanState != NULL) {
                RtlZeroMemory(scanState, sizeof(*scanState));
                scanState->DirectoryHandle = directoryHandle;
                scanState->NextVisibleIndex = response->nextIndex;
                scanState->OwnerProcessId = PsGetCurrentProcessId();
                scanState->PathLengthChars = Request->pathLengthChars;
                RtlCopyMemory(
                    scanState->Path,
                    Request->path,
                    (SIZE_T)Request->pathLengthChars * sizeof(WCHAR));
                // 连未消费完的原生缓冲一起留下：页满一定发生在这批数据中间，
                // 丢掉它就等于丢掉本批剩余的目录项。
                if (pendingOffset < pendingBytes) {
                    scanState->PendingBuffer = nativeBuffer;
                    scanState->PendingBytes = pendingBytes;
                    scanState->PendingOffset = pendingOffset;
                    nativeBuffer = NULL;
                }
                // 所有权移交缓存，本函数不再关闭该句柄。
                directoryHandle = NULL;
                KswordARKDirectoryScanStatePublish(scanState);
                scanState = NULL;
            }
        }
    }

    if (scanState != NULL) {
        // 走到这里说明缓存没有被发布出去，句柄由它持有，一并释放。
        KswordARKDirectoryScanStateFree(scanState);
    }
    else if (directoryHandle != NULL) {
        ZwClose(directoryHandle);
    }

    // 缓冲若已随缓存移交则为 NULL，这里只释放仍归本函数所有的那块。
    KswordARKDirectoryFree(nativeBuffer);
    return STATUS_SUCCESS;
}
