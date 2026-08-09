#pragma once

#include "KswordArkProcessIoctl.h"
#include "KswordArkFileIoctl.h"

// ============================================================
// KswordArkFileIrpIoctl.h
// 作用：
// - 定义"自建 IRP 直发文件系统栈"的唯一 R3/R0 协议；
// - 目录枚举接口复用 KSWORD_ARK_DIRECTORY_ENTRY 行格式，只改变请求下发的栈层，
//   让 R3 能把 IRP 视图与 ZwQueryDirectoryFile 视图逐行对比；
// - 通用提交接口允许构造全部 28 个 IRP_MJ_*，写语义与危险 major 要求显式令牌，
//   由 R0 再执行一次目标类型与参数预检。
// 说明：
// - 本协议只向"由 FILE_OBJECT 解析出的设备栈"发送 IRP，不接受 R3 直接传入
//   任意 DEVICE_OBJECT 地址，避免把内核裸指针交给用户态构造。
// ============================================================

#define KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_FILE_IRP_ENUM_DIRECTORY 0x90AUL
#define KSWORD_ARK_IOCTL_FUNCTION_FILE_IRP_SUBMIT         0x90BUL

#define IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_FILE_IRP_ENUM_DIRECTORY, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS)

#define IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_FILE_IRP_SUBMIT, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

// ------------------------------------------------------------
// 目标栈层
// ------------------------------------------------------------
// RELATED：IoGetRelatedDeviceObject(FileObject)，等价于 Zw* 进入的栈顶，
//          结果应与 IOCTL_KSWORD_ARK_ENUM_DIRECTORY 一致，用作对照基线。
// BASE_FS：IoGetBaseFileSystemDeviceObject(FileObject)，跳过挂在文件系统之上的
//          legacy filter 层，直达文件系统基础设备。
// VPB_FS ：VPB->DeviceObject，直连当前卷已挂载的文件系统设备对象。
// DEVICE ：FileObject->DeviceObject，卷设备本身（不做文件系统语义解析）。
#define KSWORD_ARK_FILE_IRP_LAYER_RELATED 0UL
#define KSWORD_ARK_FILE_IRP_LAYER_BASE_FS 1UL
#define KSWORD_ARK_FILE_IRP_LAYER_VPB_FS  2UL
#define KSWORD_ARK_FILE_IRP_LAYER_DEVICE  3UL
#define KSWORD_ARK_FILE_IRP_LAYER_MAX     3UL

// ------------------------------------------------------------
// 请求标志
// ------------------------------------------------------------
// UI_CONFIRMED：写语义或危险 major 必须置位，且 confirmationToken 必须匹配。
// SKIP_CLEANUP_CLOSE：表达"调用方打算自己配对 CLEANUP/CLOSE"的意图。R0 出于
//          防泄漏考虑仍然无条件收尾——一次 IOCTL 返回后 R3 已无法再引用该内核
//          文件对象，跳过收尾等于永久泄漏文件对象与卷引用。该标志目前只影响
//          R3 侧的语义标注，不改变 R0 的释放行为。
// OPEN_REPARSE_POINT：CREATE 阶段附加 FILE_OPEN_REPARSE_POINT。
// DIRECTORY_INTENT：CREATE 阶段附加 FILE_DIRECTORY_FILE。
// RESTART_SCAN：DIRECTORY_CONTROL 阶段置 SL_RESTART_SCAN。
// RETURN_SINGLE_ENTRY：DIRECTORY_CONTROL 阶段置 SL_RETURN_SINGLE_ENTRY。
// USE_RAW_CREATE_ONLY：只执行 CREATE 并返回结果，不发送后续 major。
#define KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED       0x00000001UL
#define KSWORD_ARK_FILE_IRP_FLAG_SKIP_CLEANUP_CLOSE 0x00000002UL
#define KSWORD_ARK_FILE_IRP_FLAG_OPEN_REPARSE_POINT 0x00000004UL
#define KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT   0x00000008UL
#define KSWORD_ARK_FILE_IRP_FLAG_RESTART_SCAN       0x00000010UL
#define KSWORD_ARK_FILE_IRP_FLAG_RETURN_SINGLE_ENTRY 0x00000020UL
#define KSWORD_ARK_FILE_IRP_FLAG_CREATE_ONLY        0x00000040UL
#define KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS    0x00000080UL

#define KSWORD_ARK_FILE_IRP_FLAG_ALL \
    (KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED | \
     KSWORD_ARK_FILE_IRP_FLAG_SKIP_CLEANUP_CLOSE | \
     KSWORD_ARK_FILE_IRP_FLAG_OPEN_REPARSE_POINT | \
     KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT | \
     KSWORD_ARK_FILE_IRP_FLAG_RESTART_SCAN | \
     KSWORD_ARK_FILE_IRP_FLAG_RETURN_SINGLE_ENTRY | \
     KSWORD_ARK_FILE_IRP_FLAG_CREATE_ONLY | \
     KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS)

// ------------------------------------------------------------
// 协议级状态（与 IRP 自身的 NTSTATUS 分开，避免把通信成功当成语义成功）
// ------------------------------------------------------------
#define KSWORD_ARK_FILE_IRP_STATUS_OK                  0UL
#define KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST     1UL
#define KSWORD_ARK_FILE_IRP_STATUS_OPEN_FAILED         2UL
#define KSWORD_ARK_FILE_IRP_STATUS_LAYER_UNAVAILABLE   3UL
#define KSWORD_ARK_FILE_IRP_STATUS_ALLOC_FAILED        4UL
#define KSWORD_ARK_FILE_IRP_STATUS_MAJOR_NOT_ALLOWED   5UL
#define KSWORD_ARK_FILE_IRP_STATUS_CONFIRMATION_REQUIRED 6UL
#define KSWORD_ARK_FILE_IRP_STATUS_TIMEOUT             7UL
#define KSWORD_ARK_FILE_IRP_STATUS_IRP_FAILED          8UL
#define KSWORD_ARK_FILE_IRP_STATUS_BUFFER_TOO_SMALL    9UL
#define KSWORD_ARK_FILE_IRP_STATUS_DENIED_BY_POLICY    10UL
#define KSWORD_ARK_FILE_IRP_STATUS_MAX                 10UL

// ------------------------------------------------------------
// 阶段标志：告诉 R3 本次实际走完了哪些阶段，未置位的阶段状态字段无意义。
// ------------------------------------------------------------
#define KSWORD_ARK_FILE_IRP_STAGE_CREATE     0x00000001UL
#define KSWORD_ARK_FILE_IRP_STAGE_OPERATION  0x00000002UL
#define KSWORD_ARK_FILE_IRP_STAGE_CLEANUP    0x00000004UL
#define KSWORD_ARK_FILE_IRP_STAGE_CLOSE      0x00000008UL
#define KSWORD_ARK_FILE_IRP_STAGE_CANCELLED  0x00000010UL
#define KSWORD_ARK_FILE_IRP_STAGE_OUTPUT_TRUNCATED 0x00000020UL

// 写语义 major 与非文件系统 major 都要求 UI_CONFIRMED + 该令牌。
#define KSWORD_ARK_FILE_IRP_CONFIRMATION_TOKEN 0x4B495250UL

#define KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS 1024U
#define KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS 256U
#define KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES  (64UL * 1024UL)
#define KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES (256UL * 1024UL)
#define KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS 10000UL
#define KSWORD_ARK_FILE_IRP_MAX_TIMEOUT_MS     60000UL
#define KSWORD_ARK_FILE_IRP_MAJOR_COUNT 28UL

// KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST：一次"打开 → 发送目标 major → 收尾"的完整描述。
// 各 major 只读取自己需要的字段，未使用字段必须为 0，便于 R0 做严格拒绝。
typedef struct _KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long confirmationToken;

    unsigned long majorFunction;      // IRP_MJ_*（0..27）。
    unsigned long minorFunction;      // IRP_MN_*，不适用时为 0。
    unsigned long targetLayer;        // KSWORD_ARK_FILE_IRP_LAYER_*。
    unsigned long timeoutMs;          // 0 表示使用默认超时。

    unsigned long desiredAccess;      // CREATE 阶段 ACCESS_MASK。
    unsigned long shareAccess;        // CREATE 阶段共享位。
    unsigned long createDisposition;  // CREATE 阶段 FILE_OPEN/FILE_CREATE/...
    unsigned long createOptions;      // CREATE 阶段 FILE_* 选项。
    unsigned long fileAttributes;     // CREATE 阶段属性。

    unsigned long informationClass;   // QUERY/SET_INFORMATION、DIRECTORY_CONTROL、
                                      // QUERY/SET_VOLUME_INFORMATION 的信息类。
    unsigned long controlCode;        // DEVICE_CONTROL / FILE_SYSTEM_CONTROL 的控制码。
    unsigned long securityInformation;// QUERY/SET_SECURITY 的 SECURITY_INFORMATION。

    unsigned long inputBytes;         // 紧跟结构体的内联输入长度。
    unsigned long outputBytes;        // 期望的输出缓冲长度。
    unsigned long lockKey;            // LOCK_CONTROL 的 Key。
    unsigned long reserved0;

    unsigned long long byteOffset;    // READ/WRITE/LOCK_CONTROL 的起始偏移。
    unsigned long long lockLength;    // LOCK_CONTROL 的字节数。

    unsigned short pathLengthChars;   // NT 路径字符数，不含结尾 NUL。
    unsigned short patternLengthChars;// DIRECTORY_CONTROL 的文件名通配符字符数。
    unsigned long reserved1;

    wchar_t path[KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS];
    wchar_t pattern[KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS];
    unsigned char inputData[1];       // 变长；实际长度由 inputBytes 决定。
} KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST,
  *PKSWORD_ARK_FILE_IRP_SUBMIT_REQUEST;

#define KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE \
    ((unsigned long)FIELD_OFFSET(KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST, inputData))

// KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE：固定头 + 变长输出数据。
// 每个阶段的 NTSTATUS 单独保留，UI 才能区分"打开失败"与"目标 major 被拒绝"。
typedef struct _KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;             // KSWORD_ARK_FILE_IRP_STATUS_*。
    unsigned long stageFlags;         // KSWORD_ARK_FILE_IRP_STAGE_*。

    unsigned long majorFunction;
    unsigned long minorFunction;
    unsigned long targetLayer;
    unsigned long outputBytes;        // 实际写入 outputData 的字节数。

    long createStatus;
    long operationStatus;
    long cleanupStatus;
    long closeStatus;

    unsigned long long information;   // 目标 major 的 IoStatus.Information。
    unsigned long long fileObjectAddress;
    unsigned long long targetDeviceAddress;
    unsigned long long targetDriverAddress;
    unsigned long long relatedDeviceAddress;
    unsigned long long baseFsDeviceAddress;
    unsigned long long vpbDeviceAddress;
    unsigned long long dispatchAddress; // 目标驱动上该 major 的 MajorFunction 入口。

    unsigned long targetStackSize;
    unsigned long targetDeviceFlags;
    unsigned long driverNameLengthChars;
    unsigned long deviceNameLengthChars;

    wchar_t driverName[KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS];
    wchar_t deviceName[KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS];
    unsigned char outputData[1];      // 变长；实际长度由 outputBytes 决定。
} KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE,
  *PKSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE;

#define KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE \
    ((unsigned long)FIELD_OFFSET(KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE, outputData))

// ------------------------------------------------------------
// IRP 直发目录枚举
// ------------------------------------------------------------
// 复用 KSWORD_ARK_DIRECTORY_ENTRY 行格式与分页语义，只增加 targetLayer；
// R3 用同一路径分别取 RELATED 与 BASE_FS/VPB_FS 两份结果做差集，
// 差集即"只有绕过过滤层才能看见"的条目。
typedef struct _KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long targetLayer;
    unsigned long startIndex;
    unsigned long maxEntries;
    unsigned short pathLengthChars;
    unsigned short reserved;
    wchar_t path[KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS];
} KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST,
  *PKSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST;

typedef struct _KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long queryStatus;        // 复用 KSWORD_ARK_DIRECTORY_ENUM_STATUS_*。
    unsigned long responseFlags;      // 复用 KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_*。
    unsigned long rowSize;
    unsigned long rowCount;
    unsigned long startIndex;
    unsigned long nextIndex;
    long openStatus;
    long lastStatus;
    unsigned long targetLayer;        // R0 实际使用的栈层，可能因不可用而回退。
    unsigned long fileSystemNameLengthChars;
    unsigned long long targetDeviceAddress;
    unsigned long long targetDriverAddress;
    unsigned long driverNameLengthChars;
    unsigned long reserved;
    wchar_t fileSystemName[KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS];
    wchar_t driverName[KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS];
    KSWORD_ARK_DIRECTORY_ENTRY rows[1];
} KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE,
  *PKSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE;

#define KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE \
    ((unsigned long)FIELD_OFFSET(KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE, rows))
