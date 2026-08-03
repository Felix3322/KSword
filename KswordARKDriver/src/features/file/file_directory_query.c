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
    _Out_ BOOLEAN* PageCompleteOut
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
        PageCompleteOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *PageCompleteOut = FALSE;

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

    status = KswordARKDirectoryOpenForEnumeration(Request, &directoryHandle);
    response->openStatus = status;
    response->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_OPEN_FAILED;
        return STATUS_SUCCESS;
    }

    KswordARKDirectoryQueryFileSystemName(directoryHandle, response);
    nativeBuffer = KswordARKDirectoryAllocate(
        KSWORD_ARK_DIRECTORY_NATIVE_BUFFER_BYTES);
    if (nativeBuffer == NULL) {
        response->queryStatus = KSWORD_ARK_DIRECTORY_ENUM_STATUS_QUERY_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(directoryHandle);
        return STATUS_SUCCESS;
    }

    for (;;) {
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

        status = KswordARKDirectoryConsumeNativeBuffer(
            (const UCHAR*)nativeBuffer,
            (ULONG)ioStatusBlock.Information,
            Request->startIndex,
            maximumRows,
            &visibleIndex,
            response,
            &pageComplete);
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

    KswordARKDirectoryFree(nativeBuffer);
    ZwClose(directoryHandle);
    return STATUS_SUCCESS;
}
