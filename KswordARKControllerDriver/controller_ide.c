#include "controller.h"

/* Legacy task-file register offsets and ATA commands used by 48-bit PIO. */
#define IDE_REG_DATA 0U
#define IDE_REG_ERROR_FEATURES 1U
#define IDE_REG_SECTOR_COUNT 2U
#define IDE_REG_LBA_LOW 3U
#define IDE_REG_LBA_MID 4U
#define IDE_REG_LBA_HIGH 5U
#define IDE_REG_DEVICE 6U
#define IDE_REG_STATUS_COMMAND 7U
#define IDE_DEVICE_CONTROL_NIEN 0x02U
#define IDE_STATUS_ERROR 0x01U
#define IDE_STATUS_DRQ 0x08U
#define IDE_STATUS_DEVICE_FAULT 0x20U
#define IDE_STATUS_BUSY 0x80U
#define IDE_CMD_IDENTIFY 0xECU
#define IDE_CMD_READ_PIO_EXT 0x24U
#define IDE_CMD_WRITE_PIO_EXT 0x34U
#define IDE_CMD_FLUSH_EXT 0xEAU

typedef enum _KSCC_IDE_WAIT_CONDITION {
    KsccIdeWaitCommandComplete = 0,
    KsccIdeWaitDataReady = 1
} KSCC_IDE_WAIT_CONDITION;

/* Bound legacy-port polling to sixty seconds at 50 microseconds per sample. */
static ULONG
KsccIdePollCount(
    _In_ ULONG TimeoutMilliseconds)
{
    ULONG milliseconds;

    milliseconds = TimeoutMilliseconds == 0U ? 5000U : TimeoutMilliseconds;
    if (milliseconds > 60000U) {
        milliseconds = 60000U;
    }
    return milliseconds * 20U;
}

/*
 * Distinguish a PIO data phase (BSY=0, DRQ=1) from final command completion
 * (BSY=0, DRQ=0).  ERR/DF is terminal in either state.
 */
static NTSTATUS
KsccIdeWait(
    _In_ PUCHAR TaskFile,
    _In_ KSCC_IDE_WAIT_CONDITION Condition,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ UCHAR* FinalStatus)
{
    ULONG polls;
    UCHAR status;

    polls = KsccIdePollCount(TimeoutMilliseconds);
    while (polls != 0U) {
        status = READ_PORT_UCHAR(TaskFile + IDE_REG_STATUS_COMMAND);
        if ((status & IDE_STATUS_BUSY) == 0U) {
            *FinalStatus = status;
            if ((status & (IDE_STATUS_ERROR | IDE_STATUS_DEVICE_FAULT)) != 0U) {
                return STATUS_IO_DEVICE_ERROR;
            }
            if ((Condition == KsccIdeWaitDataReady &&
                 (status & IDE_STATUS_DRQ) != 0U) ||
                (Condition == KsccIdeWaitCommandComplete &&
                 (status & IDE_STATUS_DRQ) == 0U)) {
                return STATUS_SUCCESS;
            }
        }
        KeStallExecutionProcessor(50U);
        polls -= 1U;
    }
    status = READ_PORT_UCHAR(TaskFile + IDE_REG_STATUS_COMMAND);
    *FinalStatus = status;
    if ((status & IDE_STATUS_BUSY) == 0U) {
        if ((status & (IDE_STATUS_ERROR | IDE_STATUS_DEVICE_FAULT)) != 0U) {
            return STATUS_IO_DEVICE_ERROR;
        }
        if ((Condition == KsccIdeWaitDataReady &&
             (status & IDE_STATUS_DRQ) != 0U) ||
            (Condition == KsccIdeWaitCommandComplete &&
             (status & IDE_STATUS_DRQ) == 0U)) {
            return STATUS_SUCCESS;
        }
    }
    return STATUS_IO_TIMEOUT;
}

/* Program the high-order then low-order task-file bytes for one LBA48 command. */
static VOID
KsccIdeProgramLba48(
    _In_ PUCHAR TaskFile,
    _In_ ULONGLONG Lba,
    _In_ USHORT SectorCount)
{
    WRITE_PORT_UCHAR(TaskFile + IDE_REG_SECTOR_COUNT, (UCHAR)(SectorCount >> 8U));
    WRITE_PORT_UCHAR(TaskFile + IDE_REG_LBA_LOW, (UCHAR)(Lba >> 24U));
    WRITE_PORT_UCHAR(TaskFile + IDE_REG_LBA_MID, (UCHAR)(Lba >> 32U));
    WRITE_PORT_UCHAR(TaskFile + IDE_REG_LBA_HIGH, (UCHAR)(Lba >> 40U));
    WRITE_PORT_UCHAR(TaskFile + IDE_REG_SECTOR_COUNT, (UCHAR)SectorCount);
    WRITE_PORT_UCHAR(TaskFile + IDE_REG_LBA_LOW, (UCHAR)Lba);
    WRITE_PORT_UCHAR(TaskFile + IDE_REG_LBA_MID, (UCHAR)(Lba >> 8U));
    WRITE_PORT_UCHAR(TaskFile + IDE_REG_LBA_HIGH, (UCHAR)(Lba >> 16U));
}

/* Convert ATA word-swapped ASCII identity fields to trimmed Unicode. */
static VOID
KsccIdeCopyAtaText(
    _In_reads_(WordCount) const USHORT* Words,
    _In_ ULONG WordCount,
    _Out_writes_(DestinationChars) WCHAR* Destination,
    _In_ ULONG DestinationChars)
{
    ULONG wordIndex;
    ULONG outputIndex;

    outputIndex = 0U;
    for (wordIndex = 0U;
         wordIndex < WordCount && outputIndex + 1U < DestinationChars;
         ++wordIndex) {
        Destination[outputIndex++] = (WCHAR)(UCHAR)(Words[wordIndex] >> 8U);
        if (outputIndex + 1U < DestinationChars) {
            Destination[outputIndex++] = (WCHAR)(UCHAR)Words[wordIndex];
        }
    }
    while (outputIndex != 0U && Destination[outputIndex - 1U] == L' ') {
        outputIndex -= 1U;
    }
    Destination[outputIndex] = L'\0';
}

/*
 * IDENTIFY the master device on the translated command block.  A controller
 * with no PnP-assigned task-file range cannot reach this function.
 */
NTSTATUS
KsccIdeInitialize(
    _Inout_ KSCC_DEVICE_CONTEXT* Context)
{
    PUCHAR taskFile;
    UCHAR statusByte;
    USHORT identify[256];
    NTSTATUS status;
    ULONGLONG sectors;
    ULONG logicalSectorSize;
    ULONG physicalSectorSize;

    if (Context->IoPortCount != 2U ||
        Context->IoPorts[0] == NULL ||
        Context->IoPorts[1] == NULL ||
        Context->IoPortLengths[0] != 8U ||
        Context->IoPortLengths[1] != 1U) {
        return STATUS_NOT_SUPPORTED;
    }
    taskFile = Context->IoPorts[0];
    Context->PortOrNamespace = 0U;
    Context->IdeControlPortIndex = 1U;
    Context->HardwareActivated = TRUE;
    WRITE_PORT_UCHAR(
        Context->IoPorts[Context->IdeControlPortIndex],
        IDE_DEVICE_CONTROL_NIEN);
    WRITE_PORT_UCHAR(taskFile + IDE_REG_DEVICE, 0x40U);
    status = KsccIdeWait(
        taskFile,
        KsccIdeWaitCommandComplete,
        5000U,
        &statusByte);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    WRITE_PORT_UCHAR(taskFile + IDE_REG_STATUS_COMMAND, IDE_CMD_IDENTIFY);
    status = KsccIdeWait(
        taskFile,
        KsccIdeWaitDataReady,
        5000U,
        &statusByte);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    READ_PORT_BUFFER_USHORT(
        (PUSHORT)(taskFile + IDE_REG_DATA),
        identify,
        RTL_NUMBER_OF(identify));
    status = KsccIdeWait(
        taskFile,
        KsccIdeWaitCommandComplete,
        5000U,
        &statusByte);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if ((identify[83] & (1U << 10U)) == 0U ||
        (identify[83] & (1U << 13U)) == 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    logicalSectorSize = 512U;
    physicalSectorSize = 512U;
    if ((identify[106] & 0xC000U) == 0x4000U) {
        if ((identify[106] & (1U << 12U)) != 0U) {
            ULONG wordsPerLogicalSector;

            wordsPerLogicalSector =
                ((ULONG)identify[118] << 16U) | identify[117];
            if (wordsPerLogicalSector == 0U ||
                wordsPerLogicalSector > (MAXULONG / 2U)) {
                return STATUS_DEVICE_DATA_ERROR;
            }
            logicalSectorSize = wordsPerLogicalSector * 2U;
        }
        if ((identify[106] & (1U << 13U)) != 0U) {
            ULONG exponent;

            exponent = identify[106] & 0x0FU;
            if (exponent > 15U ||
                logicalSectorSize > (MAXULONG >> exponent)) {
                return STATUS_INTEGER_OVERFLOW;
            }
            physicalSectorSize = logicalSectorSize << exponent;
        } else {
            physicalSectorSize = logicalSectorSize;
        }
    }

    sectors =
        ((ULONGLONG)identify[103] << 48U) |
        ((ULONGLONG)identify[102] << 32U) |
        ((ULONGLONG)identify[101] << 16U) |
        identify[100];
    Context->ControllerType = KSWORD_ARK_STORAGE_CONTROLLER_TYPE_IDE;
    Context->LogicalSectorSize = logicalSectorSize;
    Context->PhysicalSectorSize = physicalSectorSize;
    Context->Capabilities =
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_READ |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_WRITE |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_FLUSH |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_PIO;
    if (sectors > MAXULONGLONG / logicalSectorSize) {
        return STATUS_INTEGER_OVERFLOW;
    }
    Context->CapacityBytes = sectors * logicalSectorSize;
    KsccIdeCopyAtaText(
        identify + 27,
        20U,
        Context->Model,
        KSWORD_ARK_STORAGE_CONTROLLER_MODEL_CHARS);
    KsccIdeCopyAtaText(
        identify + 10,
        10U,
        Context->Serial,
        KSWORD_ARK_STORAGE_CONTROLLER_SERIAL_CHARS);
    RtlStringCchCopyW(
        Context->Detail,
        KSWORD_ARK_STORAGE_CONTROLLER_DETAIL_CHARS,
        L"Exclusive IDE task-file; system/live volume status is unverified");
    return STATUS_SUCCESS;
}

/* Mask device interrupts and prove that the task file is no longer busy. */
NTSTATUS
KsccIdeStop(
    _Inout_ KSCC_DEVICE_CONTEXT* Context)
{
    UCHAR statusByte;

    if (Context->PortOrNamespace >= Context->IoPortCount ||
        Context->IdeControlPortIndex >= Context->IoPortCount) {
        return STATUS_DEVICE_NOT_READY;
    }
    WRITE_PORT_UCHAR(
        Context->IoPorts[Context->IdeControlPortIndex],
        IDE_DEVICE_CONTROL_NIEN);
    return KsccIdeWait(
        Context->IoPorts[Context->PortOrNamespace],
        KsccIdeWaitCommandComplete,
        5000U,
        &statusByte);
}

/* Execute a sector-by-sector LBA48 PIO transfer on the owned task file. */
NTSTATUS
KsccIdeTransfer(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ BOOLEAN Write,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR* Buffer,
    _In_ ULONG Length,
    _In_ ULONG Flags,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus)
{
    PUCHAR taskFile;
    ULONGLONG lba;
    ULONG sectorCount;
    ULONG sectorIndex;
    NTSTATUS status;
    UCHAR statusByte;

    UNREFERENCED_PARAMETER(Flags);
    if ((Offset % Context->LogicalSectorSize) != 0ULL ||
        (Length % Context->LogicalSectorSize) != 0U) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    sectorCount = Length / Context->LogicalSectorSize;
    if (sectorCount == 0U || sectorCount > 65535U) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    taskFile = Context->IoPorts[Context->PortOrNamespace];
    lba = Offset / Context->LogicalSectorSize;
    WRITE_PORT_UCHAR(taskFile + IDE_REG_DEVICE, 0x40U);
    KsccIdeProgramLba48(taskFile, lba, (USHORT)sectorCount);
    WRITE_PORT_UCHAR(
        taskFile + IDE_REG_STATUS_COMMAND,
        Write ? IDE_CMD_WRITE_PIO_EXT : IDE_CMD_READ_PIO_EXT);

    for (sectorIndex = 0U; sectorIndex < sectorCount; ++sectorIndex) {
        PUSHORT sectorBuffer;
        ULONG wordsPerSector;

        status = KsccIdeWait(
            taskFile,
            KsccIdeWaitDataReady,
            TimeoutMilliseconds,
            &statusByte);
        *ControllerStatus = statusByte;
        if (!NT_SUCCESS(status)) {
            return status;
        }
        sectorBuffer = (PUSHORT)(
            Buffer + (sectorIndex * Context->LogicalSectorSize));
        wordsPerSector = Context->LogicalSectorSize / sizeof(USHORT);
        if (Write) {
            WRITE_PORT_BUFFER_USHORT(
                (PUSHORT)(taskFile + IDE_REG_DATA),
                sectorBuffer,
                wordsPerSector);
        } else {
            READ_PORT_BUFFER_USHORT(
                (PUSHORT)(taskFile + IDE_REG_DATA),
                sectorBuffer,
                wordsPerSector);
        }
    }
    status = KsccIdeWait(
        taskFile,
        KsccIdeWaitCommandComplete,
        TimeoutMilliseconds,
        &statusByte);
    *ControllerStatus = statusByte;
    return status;
}

/* Flush the device write cache after a requested durable IDE write. */
NTSTATUS
KsccIdeFlush(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus)
{
    UCHAR statusByte;
    NTSTATUS status;

    WRITE_PORT_UCHAR(
        Context->IoPorts[Context->PortOrNamespace] + IDE_REG_STATUS_COMMAND,
        IDE_CMD_FLUSH_EXT);
    status = KsccIdeWait(
        Context->IoPorts[Context->PortOrNamespace],
        KsccIdeWaitCommandComplete,
        TimeoutMilliseconds,
        &statusByte);
    *ControllerStatus = statusByte;
    return status;
}
