#include "controller.h"

/*
 * AHCI register constants follow the Intel AHCI 1.3.1 HBA memory layout.
 * Only slot zero is used because the companion driver serializes all requests.
 */
#define AHCI_GHC_CAP 0x00U
#define AHCI_GHC_GHC 0x04U
#define AHCI_GHC_PI 0x0CU
#define AHCI_GHC_AE 0x80000000U
#define AHCI_GHC_IE 0x00000002U
#define AHCI_PORT_BASE 0x100U
#define AHCI_PORT_STRIDE 0x80U
#define AHCI_PX_CLB 0x00U
#define AHCI_PX_CLBU 0x04U
#define AHCI_PX_FB 0x08U
#define AHCI_PX_FBU 0x0CU
#define AHCI_PX_IS 0x10U
#define AHCI_PX_IE 0x14U
#define AHCI_PX_CMD 0x18U
#define AHCI_PX_TFD 0x20U
#define AHCI_PX_SIG 0x24U
#define AHCI_PX_SSTS 0x28U
#define AHCI_PX_SERR 0x30U
#define AHCI_PX_SACT 0x34U
#define AHCI_PX_CI 0x38U
#define AHCI_PXCMD_ST 0x00000001U
#define AHCI_PXCMD_FRE 0x00000010U
#define AHCI_PXCMD_FR 0x00004000U
#define AHCI_PXCMD_CR 0x00008000U
#define AHCI_TFD_ERR 0x00000001U
#define AHCI_TFD_DRQ 0x00000008U
#define AHCI_TFD_BSY 0x00000080U
#define AHCI_PXIS_TFES 0x40000000U
#define AHCI_SIG_ATA 0x00000101U
#define AHCI_ATA_IDENTIFY 0xECU
#define AHCI_ATA_READ_DMA_EXT 0x25U
#define AHCI_ATA_WRITE_DMA_EXT 0x35U
#define AHCI_ATA_WRITE_DMA_FUA_EXT 0x3DU
#define AHCI_ATA_FLUSH_CACHE_EXT 0xEAU

typedef struct _KSCC_AHCI_COMMAND_HEADER {
    USHORT Flags;
    USHORT PrdtLength;
    ULONG BytesTransferred;
    ULONG CommandTableLow;
    ULONG CommandTableHigh;
    ULONG Reserved[4];
} KSCC_AHCI_COMMAND_HEADER;

typedef struct _KSCC_AHCI_PRDT {
    ULONG DataBaseLow;
    ULONG DataBaseHigh;
    ULONG Reserved;
    ULONG ByteCountAndInterrupt;
} KSCC_AHCI_PRDT;

typedef struct _KSCC_AHCI_COMMAND_TABLE {
    UCHAR CommandFis[64];
    UCHAR AtapiCommand[16];
    UCHAR Reserved[48];
    KSCC_AHCI_PRDT Prdt[1];
} KSCC_AHCI_COMMAND_TABLE;

/* Read a 32-bit MMIO register without allowing compiler reordering. */
static ULONG
KsccAhciRead32(
    _In_ PUCHAR Base,
    _In_ ULONG Offset)
{
    return READ_REGISTER_ULONG((volatile ULONG*)(Base + Offset));
}

/* Write a 32-bit MMIO register without caching the store. */
static VOID
KsccAhciWrite32(
    _In_ PUCHAR Base,
    _In_ ULONG Offset,
    _In_ ULONG Value)
{
    WRITE_REGISTER_ULONG((volatile ULONG*)(Base + Offset), Value);
}

/* Convert a millisecond timeout into bounded 50-microsecond polling steps. */
static ULONG
KsccAhciPollCount(
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
 * Validate a complete Px register window before forming an MMIO pointer.
 * PI is controller-supplied, so every implemented bit must fit inside the
 * translated BAR rather than relying on the architectural maximum size.
 */
static BOOLEAN
KsccAhciGetPortWindow(
    _In_ const KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONG PortIndex,
    _Out_ PUCHAR* Port)
{
    ULONG offset;
    ULONG barLength;

    if (Port == NULL ||
        PortIndex >= 32U ||
        Context->RegisterBarIndex >= Context->BarCount ||
        Context->Bars[Context->RegisterBarIndex] == NULL ||
        PortIndex > (MAXULONG - AHCI_PORT_BASE) / AHCI_PORT_STRIDE) {
        return FALSE;
    }
    offset = AHCI_PORT_BASE + (PortIndex * AHCI_PORT_STRIDE);
    barLength = Context->BarLengths[Context->RegisterBarIndex];
    if (offset > barLength ||
        AHCI_PORT_STRIDE > barLength - offset) {
        return FALSE;
    }
    *Port = Context->Bars[Context->RegisterBarIndex] + offset;
    return TRUE;
}

/*
 * Stop command processing before FIS reception.  AHCI requires ST to clear
 * and CR to become zero before FRE is cleared and FR is polled to zero.
 */
static NTSTATUS
KsccAhciStopEngine(
    _In_ PUCHAR Port,
    _In_ ULONG TimeoutMilliseconds)
{
    ULONG command;
    ULONG polls;

    command = KsccAhciRead32(Port, AHCI_PX_CMD);
    command &= ~AHCI_PXCMD_ST;
    KsccAhciWrite32(Port, AHCI_PX_CMD, command);
    polls = KsccAhciPollCount(TimeoutMilliseconds);
    while (polls != 0U) {
        command = KsccAhciRead32(Port, AHCI_PX_CMD);
        if ((command & AHCI_PXCMD_CR) == 0U) {
            break;
        }
        KeStallExecutionProcessor(50U);
        polls -= 1U;
    }
    if (polls == 0U) {
        return STATUS_IO_TIMEOUT;
    }
    command &= ~AHCI_PXCMD_FRE;
    KsccAhciWrite32(Port, AHCI_PX_CMD, command);
    polls = KsccAhciPollCount(TimeoutMilliseconds);
    while (polls != 0U) {
        command = KsccAhciRead32(Port, AHCI_PX_CMD);
        if ((command & AHCI_PXCMD_FR) == 0U) {
            return STATUS_SUCCESS;
        }
        KeStallExecutionProcessor(50U);
        polls -= 1U;
    }
    return STATUS_IO_TIMEOUT;
}

/* Start FIS reception before enabling command processing, as required by AHCI. */
static VOID
KsccAhciStartEngine(
    _In_ PUCHAR Port)
{
    ULONG command;

    command = KsccAhciRead32(Port, AHCI_PX_CMD);
    command |= AHCI_PXCMD_FRE;
    KsccAhciWrite32(Port, AHCI_PX_CMD, command);
    command |= AHCI_PXCMD_ST;
    KsccAhciWrite32(Port, AHCI_PX_CMD, command);
}

/*
 * Submit one non-NCQ ATA command through slot zero.  Data is always a
 * controller-owned common buffer, so one PRDT entry is sufficient.
 */
static NTSTATUS
KsccAhciIssue(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ UCHAR Command,
    _In_ ULONGLONG Lba,
    _In_ USHORT SectorCount,
    _In_ ULONG TransferBytes,
    _In_ BOOLEAN Write,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus)
{
    PUCHAR port;
    KSCC_AHCI_COMMAND_HEADER* header;
    KSCC_AHCI_COMMAND_TABLE* table;
    UCHAR* fis;
    ULONG polls;
    ULONG value;
    ULONG interruptStatus;
    ULONG serialError;

    if (!KsccAhciGetPortWindow(
            Context,
            Context->PortOrNamespace,
            &port)) {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    header = (KSCC_AHCI_COMMAND_HEADER*)Context->Command.Virtual;
    table = (KSCC_AHCI_COMMAND_TABLE*)Context->Auxiliary.Virtual;
    RtlZeroMemory(header, sizeof(*header));
    RtlZeroMemory(table, Context->Auxiliary.Length);

    header->Flags = 5U;
    if (Write) {
        header->Flags |= 0x0040U;
    }
    header->PrdtLength = TransferBytes == 0U ? 0U : 1U;
    header->CommandTableLow = Context->Auxiliary.Logical.LowPart;
    header->CommandTableHigh = (ULONG)Context->Auxiliary.Logical.HighPart;
    if (TransferBytes != 0U) {
        table->Prdt[0].DataBaseLow = Context->Data.Logical.LowPart;
        table->Prdt[0].DataBaseHigh = (ULONG)Context->Data.Logical.HighPart;
        /* IOC remains clear: this backend is polling-only. */
        table->Prdt[0].ByteCountAndInterrupt = TransferBytes - 1U;
    }

    fis = table->CommandFis;
    fis[0] = 0x27U;
    fis[1] = 0x80U;
    fis[2] = Command;
    fis[4] = (UCHAR)(Lba & 0xFFULL);
    fis[5] = (UCHAR)((Lba >> 8U) & 0xFFULL);
    fis[6] = (UCHAR)((Lba >> 16U) & 0xFFULL);
    fis[7] = 0x40U;
    fis[8] = (UCHAR)((Lba >> 24U) & 0xFFULL);
    fis[9] = (UCHAR)((Lba >> 32U) & 0xFFULL);
    fis[10] = (UCHAR)((Lba >> 40U) & 0xFFULL);
    fis[12] = (UCHAR)(SectorCount & 0xFFU);
    fis[13] = (UCHAR)((SectorCount >> 8U) & 0xFFU);

    polls = KsccAhciPollCount(TimeoutMilliseconds);
    while (polls != 0U) {
        value = KsccAhciRead32(port, AHCI_PX_TFD);
        if ((value & (AHCI_TFD_BSY | AHCI_TFD_DRQ)) == 0U &&
            (KsccAhciRead32(port, AHCI_PX_CI) & 1U) == 0U &&
            (KsccAhciRead32(port, AHCI_PX_SACT) & 1U) == 0U) {
            break;
        }
        KeStallExecutionProcessor(50U);
        polls -= 1U;
    }
    if (polls == 0U) {
        *ControllerStatus = value;
        return STATUS_IO_TIMEOUT;
    }
    KsccAhciWrite32(port, AHCI_PX_IS, 0xFFFFFFFFU);
    KsccAhciWrite32(port, AHCI_PX_SERR, 0xFFFFFFFFU);
    KsccAhciWrite32(port, AHCI_PX_CI, 1U);
    polls = KsccAhciPollCount(TimeoutMilliseconds);
    while (polls != 0U) {
        value = KsccAhciRead32(port, AHCI_PX_CI);
        if ((value & 1U) == 0U) {
            value = KsccAhciRead32(port, AHCI_PX_TFD);
            interruptStatus = KsccAhciRead32(port, AHCI_PX_IS);
            serialError = KsccAhciRead32(port, AHCI_PX_SERR);
            *ControllerStatus =
                value |
                (interruptStatus & AHCI_PXIS_TFES) |
                (serialError != 0U ? 0x80000000U : 0U);
            if ((value & AHCI_TFD_ERR) != 0U ||
                (interruptStatus & AHCI_PXIS_TFES) != 0U ||
                serialError != 0U) {
                return STATUS_IO_DEVICE_ERROR;
            }
            return STATUS_SUCCESS;
        }
        KeStallExecutionProcessor(50U);
        polls -= 1U;
    }
    *ControllerStatus = KsccAhciRead32(port, AHCI_PX_TFD);
    return STATUS_IO_TIMEOUT;
}

/* Convert ATA word-swapped ASCII identity text to a bounded Unicode string. */
static VOID
KsccAhciCopyAtaText(
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
        UCHAR first;
        UCHAR second;

        first = (UCHAR)(Words[wordIndex] >> 8U);
        second = (UCHAR)(Words[wordIndex] & 0xFFU);
        Destination[outputIndex++] = (WCHAR)first;
        if (outputIndex + 1U < DestinationChars) {
            Destination[outputIndex++] = (WCHAR)second;
        }
    }
    while (outputIndex != 0U && Destination[outputIndex - 1U] == L' ') {
        outputIndex -= 1U;
    }
    Destination[outputIndex] = L'\0';
}

/*
 * Initialize one SATA port after validating PI, DET/IPM, and ATA signature.
 * The code owns CLB/FB/CTBA and never reuses buffers from another driver.
 */
NTSTATUS
KsccAhciInitialize(
    _Inout_ KSCC_DEVICE_CONTEXT* Context)
{
    PUCHAR abar;
    ULONG cap;
    ULONG pi;
    ULONG portIndex;
    PUCHAR port;
    ULONG status;
    NTSTATUS ntStatus;
    USHORT* identify;
    ULONGLONG sectors;
    ULONG logicalSectorSize;
    ULONG physicalSectorSize;

    if (Context->RegisterBarIndex >= Context->BarCount ||
        Context->Bars[Context->RegisterBarIndex] == NULL ||
        Context->BarLengths[Context->RegisterBarIndex] <
        AHCI_PORT_BASE + AHCI_PORT_STRIDE) {
        return STATUS_NOT_SUPPORTED;
    }
    abar = Context->Bars[Context->RegisterBarIndex];
    cap = KsccAhciRead32(abar, AHCI_GHC_CAP);
    pi = KsccAhciRead32(abar, AHCI_GHC_PI);
    if (pi == 0U || cap == 0xFFFFFFFFU) {
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * Validate every PI-advertised port before reading even the first Px
     * register.  A malformed PI cannot redirect polling beyond the BAR.
     */
    for (portIndex = 0U; portIndex < 32U; ++portIndex) {
        if ((pi & (1UL << portIndex)) != 0U &&
            !KsccAhciGetPortWindow(Context, portIndex, &port)) {
            return STATUS_DEVICE_CONFIGURATION_ERROR;
        }
    }
    for (portIndex = 0U; portIndex < 32U; ++portIndex) {
        ULONG ssts;

        if ((pi & (1UL << portIndex)) == 0U) {
            continue;
        }
        if (!KsccAhciGetPortWindow(Context, portIndex, &port)) {
            return STATUS_DEVICE_CONFIGURATION_ERROR;
        }
        ssts = KsccAhciRead32(port, AHCI_PX_SSTS);
        if ((ssts & 0x0FU) != 3U || ((ssts >> 8U) & 0x0FU) != 1U) {
            continue;
        }
        if (KsccAhciRead32(port, AHCI_PX_SIG) == AHCI_SIG_ATA) {
            Context->PortOrNamespace = portIndex;
            break;
        }
    }
    if (portIndex == 32U) {
        return STATUS_NO_SUCH_DEVICE;
    }

    ntStatus = KsccAllocateDmaRegion(Context, &Context->Command, 1024U);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }
    ntStatus = KsccAllocateDmaRegion(Context, &Context->Completion, 256U);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }
    ntStatus = KsccAllocateDmaRegion(
        Context,
        &Context->Data,
        KSWORD_ARK_STORAGE_CONTROLLER_MAX_TRANSFER_BYTES);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }
    ntStatus = KsccAllocateDmaRegion(Context, &Context->Auxiliary, 256U);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }
    if ((cap & 0x80000000U) == 0U &&
        (Context->Command.Logical.HighPart != 0 ||
         Context->Completion.Logical.HighPart != 0 ||
         Context->Data.Logical.HighPart != 0 ||
         Context->Auxiliary.Logical.HighPart != 0)) {
        return STATUS_NOT_SUPPORTED;
    }

    Context->HardwareActivated = TRUE;
    KsccAhciWrite32(
        abar,
        AHCI_GHC_GHC,
        (KsccAhciRead32(abar, AHCI_GHC_GHC) | AHCI_GHC_AE) &
            ~AHCI_GHC_IE);
    KsccAhciWrite32(port, AHCI_PX_IE, 0U);
    if ((KsccAhciRead32(abar, AHCI_GHC_GHC) & AHCI_GHC_IE) != 0U ||
        KsccAhciRead32(port, AHCI_PX_IE) != 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    ntStatus = KsccAhciStopEngine(port, 5000U);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }
    KsccAhciWrite32(port, AHCI_PX_CLB, Context->Command.Logical.LowPart);
    KsccAhciWrite32(port, AHCI_PX_CLBU, (ULONG)Context->Command.Logical.HighPart);
    KsccAhciWrite32(port, AHCI_PX_FB, Context->Completion.Logical.LowPart);
    KsccAhciWrite32(port, AHCI_PX_FBU, (ULONG)Context->Completion.Logical.HighPart);
    KsccAhciWrite32(port, AHCI_PX_SERR, 0xFFFFFFFFU);
    KsccAhciWrite32(port, AHCI_PX_IS, 0xFFFFFFFFU);
    KsccAhciStartEngine(port);

    ntStatus = KsccAhciIssue(
        Context,
        AHCI_ATA_IDENTIFY,
        0ULL,
        0U,
        512U,
        FALSE,
        5000U,
        &status);
    if (!NT_SUCCESS(ntStatus)) {
        return ntStatus;
    }
    identify = (USHORT*)Context->Data.Virtual;
    if ((identify[49] & (1U << 8U)) == 0U ||
        (identify[83] & (1U << 10U)) == 0U ||
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
        (ULONGLONG)identify[100];
    if (sectors == 0ULL) {
        sectors = ((ULONGLONG)identify[61] << 16U) | identify[60];
    }

    Context->ControllerType = KSWORD_ARK_STORAGE_CONTROLLER_TYPE_AHCI;
    Context->LogicalSectorSize = logicalSectorSize;
    Context->PhysicalSectorSize = physicalSectorSize;
    Context->Capabilities =
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_READ |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_WRITE |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_FLUSH |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_DMA;
    if ((cap & 0x80000000U) != 0U) {
        Context->Capabilities |=
            KSWORD_ARK_STORAGE_CONTROLLER_CAP_64BIT_DMA;
    }
    if ((identify[84] & (1U << 6U)) != 0U) {
        Context->Capabilities |= KSWORD_ARK_STORAGE_CONTROLLER_CAP_FUA;
    }
    if (sectors > MAXULONGLONG / logicalSectorSize) {
        return STATUS_INTEGER_OVERFLOW;
    }
    Context->CapacityBytes = sectors * logicalSectorSize;
    KsccAhciCopyAtaText(
        identify + 27,
        20U,
        Context->Model,
        KSWORD_ARK_STORAGE_CONTROLLER_MODEL_CHARS);
    KsccAhciCopyAtaText(
        identify + 10,
        10U,
        Context->Serial,
        KSWORD_ARK_STORAGE_CONTROLLER_SERIAL_CHARS);
    RtlStringCchCopyW(
        Context->Detail,
        KSWORD_ARK_STORAGE_CONTROLLER_DETAIL_CHARS,
        L"Exclusive AHCI queues; system/live volume status is unverified");
    return STATUS_SUCCESS;
}

/* Stop AHCI command processing before DMA buffers are released. */
NTSTATUS
KsccAhciStop(
    _Inout_ KSCC_DEVICE_CONTEXT* Context)
{
    PUCHAR port;

    if (!KsccAhciGetPortWindow(
            Context,
            Context->PortOrNamespace,
            &port)) {
        return STATUS_DEVICE_NOT_READY;
    }
    KsccAhciWrite32(port, AHCI_PX_IE, 0U);
    return KsccAhciStopEngine(port, 5000U);
}

/* Execute an aligned DMA EXT transfer and copy through the owned common buffer. */
NTSTATUS
KsccAhciTransfer(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ BOOLEAN Write,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR* Buffer,
    _In_ ULONG Length,
    _In_ ULONG Flags,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus)
{
    UCHAR command;
    ULONGLONG lba;
    USHORT sectors;
    NTSTATUS status;

    if ((Offset % Context->LogicalSectorSize) != 0ULL ||
        (Length % Context->LogicalSectorSize) != 0U) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    if (Length == 0U || Length > Context->Data.Length) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (Write &&
        (Flags & KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FUA) != 0U &&
        (Context->Capabilities &
         KSWORD_ARK_STORAGE_CONTROLLER_CAP_FUA) == 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    lba = Offset / Context->LogicalSectorSize;
    if (Length / Context->LogicalSectorSize > MAXUSHORT) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    sectors = (USHORT)(Length / Context->LogicalSectorSize);
    if (Write) {
        RtlCopyMemory(Context->Data.Virtual, Buffer, Length);
        command =
            (Flags & KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FUA) != 0U &&
            (Context->Capabilities &
             KSWORD_ARK_STORAGE_CONTROLLER_CAP_FUA) != 0U
            ? AHCI_ATA_WRITE_DMA_FUA_EXT
            : AHCI_ATA_WRITE_DMA_EXT;
    } else {
        command = AHCI_ATA_READ_DMA_EXT;
    }
    status = KsccAhciIssue(
        Context,
        command,
        lba,
        sectors,
        Length,
        Write,
        TimeoutMilliseconds,
        ControllerStatus);
    if (NT_SUCCESS(status) && !Write) {
        RtlCopyMemory(Buffer, Context->Data.Virtual, Length);
    }
    return status;
}

/* Issue ATA FLUSH CACHE EXT through the same serialized slot. */
NTSTATUS
KsccAhciFlush(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus)
{
    return KsccAhciIssue(
        Context,
        AHCI_ATA_FLUSH_CACHE_EXT,
        0ULL,
        0U,
        0U,
        FALSE,
        TimeoutMilliseconds,
        ControllerStatus);
}
