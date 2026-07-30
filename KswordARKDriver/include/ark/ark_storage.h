#pragma once

#include <ntddk.h>

#include "driver/KswordArkStorageIoctl.h"
#include "driver/KswordArkStorageForensicsIoctl.h"

EXTERN_C_START

NTSTATUS
KswordARKStorageQueryVolumeStackAudit(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKStorageQueryBitLockerFveAudit(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKStorageQueryMountMgrMappingAudit(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKStorageQueryFileSystemIntegrityAudit(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKStorageQueryRawDiskBackend(
    _In_ const KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST* Request,
    _Out_ KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE* Response
    );

NTSTATUS
KswordARKStorageReadRawDisk(
    _In_ const KSWORD_ARK_RAW_DISK_READ_REQUEST* Request,
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

NTSTATUS
KswordARKStorageWriteRawDisk(
    _In_ const KSWORD_ARK_RAW_DISK_WRITE_REQUEST* Request,
    _In_ size_t InputBufferLength,
    _Out_ KSWORD_ARK_RAW_DISK_WRITE_RESPONSE* Response
    );

EXTERN_C_END
