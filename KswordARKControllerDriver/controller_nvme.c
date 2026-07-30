#include "controller.h"

/* NVMe controller register offsets and command opcodes from NVM Express 2.x. */
#define NVME_REG_CAP 0x0000U
#define NVME_REG_VS 0x0008U
#define NVME_REG_INTMS 0x000CU
#define NVME_REG_CC 0x0014U
#define NVME_REG_CSTS 0x001CU
#define NVME_REG_AQA 0x0024U
#define NVME_REG_ASQ 0x0028U
#define NVME_REG_ACQ 0x0030U
#define NVME_REG_DOORBELL 0x1000U
#define NVME_CC_ENABLE 0x00000001U
#define NVME_CC_SHN_NORMAL 0x00004000U
#define NVME_CSTS_READY 0x00000001U
#define NVME_CSTS_SHST_MASK 0x0000000CU
#define NVME_CSTS_SHST_COMPLETE 0x00000008U
#define NVME_ADMIN_CREATE_IOSQ 0x01U
#define NVME_ADMIN_CREATE_IOCQ 0x05U
#define NVME_ADMIN_IDENTIFY 0x06U
#define NVME_IO_FLUSH 0x00U
#define NVME_IO_WRITE 0x01U
#define NVME_IO_READ 0x02U
#define NVME_QUEUE_ENTRIES 64U
#define NVME_SQ_BYTES 4096U
#define NVME_CQ_BYTES 4096U

typedef struct _KSCC_NVME_COMMAND {
    ULONG Dword0;
    ULONG NamespaceId;
    ULONGLONG Reserved;
    ULONGLONG MetadataPointer;
    ULONGLONG Prp1;
    ULONGLONG Prp2;
    ULONG Cdw10;
    ULONG Cdw11;
    ULONG Cdw12;
    ULONG Cdw13;
    ULONG Cdw14;
    ULONG Cdw15;
} KSCC_NVME_COMMAND;

typedef struct _KSCC_NVME_COMPLETION {
    ULONG Result;
    ULONG Reserved;
    USHORT SqHead;
    USHORT SqId;
    USHORT CommandId;
    USHORT Status;
} KSCC_NVME_COMPLETION;

/* Read one 32-bit NVMe MMIO register. */
static ULONG
KsccNvmeRead32(
    _In_ PUCHAR Base,
    _In_ ULONG Offset)
{
    return READ_REGISTER_ULONG((volatile ULONG*)(Base + Offset));
}

/* Read one naturally aligned 64-bit NVMe MMIO register as two dwords. */
static ULONGLONG
KsccNvmeRead64(
    _In_ PUCHAR Base,
    _In_ ULONG Offset)
{
    ULONG low;
    ULONG high;

    low = KsccNvmeRead32(Base, Offset);
    high = KsccNvmeRead32(Base, Offset + sizeof(ULONG));
    return ((ULONGLONG)high << 32U) | low;
}

/* Write one 32-bit NVMe MMIO register. */
static VOID
KsccNvmeWrite32(
    _In_ PUCHAR Base,
    _In_ ULONG Offset,
    _In_ ULONG Value)
{
    WRITE_REGISTER_ULONG((volatile ULONG*)(Base + Offset), Value);
}

/* Write one 64-bit NVMe MMIO register as architected low/high dwords. */
static VOID
KsccNvmeWrite64(
    _In_ PUCHAR Base,
    _In_ ULONG Offset,
    _In_ ULONGLONG Value)
{
    KsccNvmeWrite32(Base, Offset, (ULONG)Value);
    KsccNvmeWrite32(Base, Offset + sizeof(ULONG), (ULONG)(Value >> 32U));
}

/* Return the doorbell byte stride encoded in CAP.DSTRD. */
static ULONG
KsccNvmeDoorbellStride(
    _In_ KSCC_DEVICE_CONTEXT* Context)
{
    ULONGLONG cap;
    ULONG encoded;

    cap = KsccNvmeRead64(
        Context->Bars[Context->RegisterBarIndex],
        NVME_REG_CAP);
    encoded = (ULONG)((cap >> 32U) & 0x0FULL);
    return 4U << encoded;
}

/* Bound polling to at most sixty seconds with a 50-microsecond interval. */
static ULONG
KsccNvmePollCount(
    _In_ ULONG TimeoutMilliseconds)
{
    ULONG milliseconds;

    milliseconds = TimeoutMilliseconds == 0U ? 5000U : TimeoutMilliseconds;
    if (milliseconds > 60000U) {
        milliseconds = 60000U;
    }
    return milliseconds * 20U;
}

/* Wait for CSTS.RDY to match the requested state. */
static NTSTATUS
KsccNvmeWaitReady(
    _In_ KSCC_DEVICE_CONTEXT* Context,
    _In_ BOOLEAN Ready,
    _In_ ULONG TimeoutMilliseconds)
{
    ULONG polls;
    ULONG expected;

    polls = KsccNvmePollCount(TimeoutMilliseconds);
    expected = Ready ? NVME_CSTS_READY : 0U;
    while (polls != 0U) {
        if ((KsccNvmeRead32(
                 Context->Bars[Context->RegisterBarIndex],
                 NVME_REG_CSTS) &
             NVME_CSTS_READY) == expected) {
            return STATUS_SUCCESS;
        }
        KeStallExecutionProcessor(50U);
        polls -= 1U;
    }
    Context->RequiresReset = TRUE;
    Context->RiskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_TIMEOUT;
    return STATUS_IO_TIMEOUT;
}

/*
 * Build PRP1/PRP2 for a physically contiguous WDF common buffer.  Transfers
 * beyond two pages use a controller-owned PRP list with one entry per page.
 */
static NTSTATUS
KsccNvmeBuildPrp(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONG Length,
    _Out_ ULONGLONG* Prp1,
    _Out_ ULONGLONG* Prp2)
{
    ULONGLONG address;
    ULONG firstBytes;
    ULONG remaining;
    ULONG entries;
    ULONG index;
    ULONGLONG* list;

    address = (ULONGLONG)Context->Data.Logical.QuadPart;
    *Prp1 = address;
    firstBytes = PAGE_SIZE - (ULONG)(address & (PAGE_SIZE - 1U));
    if (Length <= firstBytes) {
        *Prp2 = 0ULL;
        return STATUS_SUCCESS;
    }
    remaining = Length - firstBytes;
    address += firstBytes;
    if (remaining <= PAGE_SIZE) {
        *Prp2 = address;
        return STATUS_SUCCESS;
    }

    entries = (remaining + PAGE_SIZE - 1U) / PAGE_SIZE;
    if (entries * sizeof(ULONGLONG) > Context->Prp.Length) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    list = (ULONGLONG*)Context->Prp.Virtual;
    RtlZeroMemory(list, Context->Prp.Length);
    for (index = 0U; index < entries; ++index) {
        list[index] = address + ((ULONGLONG)index * PAGE_SIZE);
    }
    *Prp2 = (ULONGLONG)Context->Prp.Logical.QuadPart;
    return STATUS_SUCCESS;
}

/*
 * Submit an admin command to queue zero and consume its phase-tagged
 * completion.  The queue size is fixed at 64 and commands are serialized.
 */
static NTSTATUS
KsccNvmeAdminCommand(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ const KSCC_NVME_COMMAND* Command,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus)
{
    KSCC_NVME_COMMAND* submission;
    KSCC_NVME_COMPLETION* completion;
    KSCC_NVME_COMMAND commandCopy;
    ULONG stride;
    ULONG polls;
    USHORT status;

    commandCopy = *Command;
    commandCopy.Dword0 =
        (commandCopy.Dword0 & 0x0000FFFFU) |
        ((Context->NvmeAdminTail & 0xFFFFU) << 16U);
    submission = (KSCC_NVME_COMMAND*)Context->Command.Virtual;
    submission[Context->NvmeAdminTail] = commandCopy;
    KeMemoryBarrier();
    Context->NvmeAdminTail =
        (Context->NvmeAdminTail + 1U) % NVME_QUEUE_ENTRIES;
    stride = KsccNvmeDoorbellStride(Context);
    KsccNvmeWrite32(
        Context->Bars[Context->RegisterBarIndex],
        NVME_REG_DOORBELL,
        Context->NvmeAdminTail);

    completion = (KSCC_NVME_COMPLETION*)Context->Completion.Virtual;
    polls = KsccNvmePollCount(TimeoutMilliseconds);
    while (polls != 0U) {
        status = completion[Context->NvmeAdminHead].Status;
        if ((status & 1U) == Context->NvmeAdminPhase) {
            *ControllerStatus = status;
            Context->NvmeAdminHead += 1U;
            if (Context->NvmeAdminHead == NVME_QUEUE_ENTRIES) {
                Context->NvmeAdminHead = 0U;
                Context->NvmeAdminPhase ^= 1U;
            }
            KsccNvmeWrite32(
                Context->Bars[Context->RegisterBarIndex],
                NVME_REG_DOORBELL + stride,
                Context->NvmeAdminHead);
            return (status & 0xFFFEU) == 0U
                ? STATUS_SUCCESS
                : STATUS_IO_DEVICE_ERROR;
        }
        KeStallExecutionProcessor(50U);
        polls -= 1U;
    }
    Context->RequiresReset = TRUE;
    Context->RiskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_TIMEOUT;
    return STATUS_IO_TIMEOUT;
}

/* Submit one NVM I/O command through queue pair one. */
static NTSTATUS
KsccNvmeIoCommand(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ const KSCC_NVME_COMMAND* Command,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus)
{
    KSCC_NVME_COMMAND* submission;
    KSCC_NVME_COMPLETION* completion;
    KSCC_NVME_COMMAND commandCopy;
    ULONG stride;
    ULONG polls;
    USHORT status;

    commandCopy = *Command;
    commandCopy.Dword0 =
        (commandCopy.Dword0 & 0x0000FFFFU) |
        ((Context->NvmeIoTail & 0xFFFFU) << 16U);
    submission = (KSCC_NVME_COMMAND*)Context->Auxiliary.Virtual;
    completion = (KSCC_NVME_COMPLETION*)
        ((UCHAR*)Context->Auxiliary.Virtual + NVME_SQ_BYTES);
    submission[Context->NvmeIoTail] = commandCopy;
    KeMemoryBarrier();
    Context->NvmeIoTail = (Context->NvmeIoTail + 1U) % NVME_QUEUE_ENTRIES;
    stride = KsccNvmeDoorbellStride(Context);
    KsccNvmeWrite32(
        Context->Bars[Context->RegisterBarIndex],
        NVME_REG_DOORBELL + (2U * stride),
        Context->NvmeIoTail);

    polls = KsccNvmePollCount(TimeoutMilliseconds);
    while (polls != 0U) {
        status = completion[Context->NvmeIoHead].Status;
        if ((status & 1U) == Context->NvmeIoPhase) {
            *ControllerStatus = status;
            Context->NvmeIoHead += 1U;
            if (Context->NvmeIoHead == NVME_QUEUE_ENTRIES) {
                Context->NvmeIoHead = 0U;
                Context->NvmeIoPhase ^= 1U;
            }
            KsccNvmeWrite32(
                Context->Bars[Context->RegisterBarIndex],
                NVME_REG_DOORBELL + (3U * stride),
                Context->NvmeIoHead);
            return (status & 0xFFFEU) == 0U
                ? STATUS_SUCCESS
                : STATUS_IO_DEVICE_ERROR;
        }
        KeStallExecutionProcessor(50U);
        polls -= 1U;
    }
    Context->RequiresReset = TRUE;
    Context->RiskFlags |= KSWORD_ARK_STORAGE_CONTROLLER_RISK_TIMEOUT;
    return STATUS_IO_TIMEOUT;
}

/* Copy a fixed-width, space-padded NVMe ASCII field to Unicode. */
static VOID
KsccNvmeCopyText(
    _In_reads_(SourceLength) const UCHAR* Source,
    _In_ ULONG SourceLength,
    _Out_writes_(DestinationChars) WCHAR* Destination,
    _In_ ULONG DestinationChars)
{
    ULONG length;
    ULONG index;

    length = SourceLength;
    while (length != 0U && Source[length - 1U] == ' ') {
        length -= 1U;
    }
    if (length >= DestinationChars) {
        length = DestinationChars - 1U;
    }
    for (index = 0U; index < length; ++index) {
        Destination[index] = (WCHAR)Source[index];
    }
    Destination[length] = L'\0';
}

/*
 * Reset the PnP-owned controller, establish admin queues, select an active
 * namespace, then create one physically-contiguous I/O queue pair.
 */
NTSTATUS
KsccNvmeInitialize(
    _Inout_ KSCC_DEVICE_CONTEXT* Context)
{
    PUCHAR bar;
    ULONGLONG cap;
    ULONG version;
    ULONG controllerStatus;
    KSCC_NVME_COMMAND command;
    NTSTATUS status;
    const UCHAR* identify;
    ULONGLONG namespaceSize;
    UCHAR numberOfLbaFormats;
    UCHAR formatIndex;
    UCHAR lbaDataSize;
    USHORT metadataBytes;
    UCHAR mdts;
    ULONG namespaceId;
    ULONGLONG ioSqAddress;
    ULONGLONG ioCqAddress;

    if (Context->BarLengths[Context->RegisterBarIndex] <
        NVME_REG_DOORBELL + 16U) {
        return STATUS_NOT_SUPPORTED;
    }
    bar = Context->Bars[Context->RegisterBarIndex];
    cap = KsccNvmeRead64(bar, NVME_REG_CAP);
    version = KsccNvmeRead32(bar, NVME_REG_VS);
    if (cap == MAXULONGLONG || version == 0U || version == MAXULONG) {
        return STATUS_NOT_SUPPORTED;
    }
    if ((cap & 0xFFFFULL) + 1ULL < NVME_QUEUE_ENTRIES ||
        ((cap >> 37U) & 1ULL) == 0ULL ||
        ((cap >> 48U) & 0x0FULL) != 0ULL) {
        return STATUS_NOT_SUPPORTED;
    }
    if (NVME_REG_DOORBELL +
            (4U * (4U << (ULONG)((cap >> 32U) & 0x0FULL))) >
        Context->BarLengths[Context->RegisterBarIndex]) {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    status = KsccAllocateDmaRegion(Context, &Context->Command, NVME_SQ_BYTES);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KsccAllocateDmaRegion(Context, &Context->Completion, NVME_CQ_BYTES);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KsccAllocateDmaRegion(
        Context,
        &Context->Data,
        KSWORD_ARK_STORAGE_CONTROLLER_MAX_TRANSFER_BYTES);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KsccAllocateDmaRegion(
        Context,
        &Context->Auxiliary,
        NVME_SQ_BYTES + NVME_CQ_BYTES);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KsccAllocateDmaRegion(Context, &Context->Prp, PAGE_SIZE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Context->HardwareActivated = TRUE;
    /*
     * This companion does not connect a WDF interrupt.  Mask every NVMe
     * vector and require the mask to read back before queue activation.
     */
    KsccNvmeWrite32(bar, NVME_REG_INTMS, MAXULONG);
    if (KsccNvmeRead32(bar, NVME_REG_INTMS) != MAXULONG) {
        return STATUS_NOT_SUPPORTED;
    }
    KsccNvmeWrite32(bar, NVME_REG_CC, 0U);
    status = KsccNvmeWaitReady(Context, FALSE, 5000U);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Context->NvmeAdminTail = 0U;
    Context->NvmeAdminHead = 0U;
    Context->NvmeAdminPhase = 1U;
    Context->NvmeIoTail = 0U;
    Context->NvmeIoHead = 0U;
    Context->NvmeIoPhase = 1U;
    KsccNvmeWrite32(
        bar,
        NVME_REG_AQA,
        ((NVME_QUEUE_ENTRIES - 1U) << 16U) | (NVME_QUEUE_ENTRIES - 1U));
    KsccNvmeWrite64(
        bar,
        NVME_REG_ASQ,
        (ULONGLONG)Context->Command.Logical.QuadPart);
    KsccNvmeWrite64(
        bar,
        NVME_REG_ACQ,
        (ULONGLONG)Context->Completion.Logical.QuadPart);
    KsccNvmeWrite32(bar, NVME_REG_CC, NVME_CC_ENABLE | (6U << 16U) | (4U << 20U));
    status = KsccNvmeWaitReady(Context, TRUE, 5000U);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&command, sizeof(command));
    command.Dword0 = NVME_ADMIN_IDENTIFY;
    command.NamespaceId = 0U;
    command.Prp1 = (ULONGLONG)Context->Data.Logical.QuadPart;
    command.Cdw10 = 1U;
    status = KsccNvmeAdminCommand(Context, &command, 5000U, &controllerStatus);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    identify = (const UCHAR*)Context->Data.Virtual;
    KsccNvmeCopyText(
        identify + 24U,
        40U,
        Context->Model,
        KSWORD_ARK_STORAGE_CONTROLLER_MODEL_CHARS);
    KsccNvmeCopyText(
        identify + 4U,
        20U,
        Context->Serial,
        KSWORD_ARK_STORAGE_CONTROLLER_SERIAL_CHARS);
    mdts = identify[77U];
    if (mdts != 0U && mdts < 16U) {
        ULONG mdtsBytes;

        mdtsBytes = PAGE_SIZE << mdts;
        if (mdtsBytes < Context->MaximumTransferBytes) {
            Context->MaximumTransferBytes = mdtsBytes;
        }
    }

    /*
     * Discover the first active namespace rather than assuming NSID 1.
     * CNS=2 returns the active namespace list in ascending order.
     */
    RtlZeroMemory(Context->Data.Virtual, Context->Data.Length);
    RtlZeroMemory(&command, sizeof(command));
    command.Dword0 = NVME_ADMIN_IDENTIFY;
    command.NamespaceId = 0U;
    command.Prp1 = (ULONGLONG)Context->Data.Logical.QuadPart;
    command.Cdw10 = 2U;
    status = KsccNvmeAdminCommand(Context, &command, 5000U, &controllerStatus);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlCopyMemory(&namespaceId, Context->Data.Virtual, sizeof(namespaceId));
    if (namespaceId == 0U) {
        return STATUS_NO_SUCH_DEVICE;
    }

    RtlZeroMemory(Context->Data.Virtual, Context->Data.Length);
    RtlZeroMemory(&command, sizeof(command));
    command.Dword0 = NVME_ADMIN_IDENTIFY;
    command.NamespaceId = namespaceId;
    command.Prp1 = (ULONGLONG)Context->Data.Logical.QuadPart;
    command.Cdw10 = 0U;
    status = KsccNvmeAdminCommand(Context, &command, 5000U, &controllerStatus);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    identify = (const UCHAR*)Context->Data.Virtual;
    RtlCopyMemory(&namespaceSize, identify, sizeof(namespaceSize));
    numberOfLbaFormats = identify[25U];
    formatIndex = identify[26U] & 0x0FU;
    if (formatIndex > numberOfLbaFormats ||
        (identify[26U] & 0x10U) != 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    RtlCopyMemory(
        &metadataBytes,
        identify + 128U + (formatIndex * 4U),
        sizeof(metadataBytes));
    if (metadataBytes != 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    lbaDataSize = identify[128U + (formatIndex * 4U) + 2U];
    if (lbaDataSize < 9U || lbaDataSize > 16U) {
        return STATUS_DEVICE_DATA_ERROR;
    }
    Context->LogicalSectorSize = 1UL << lbaDataSize;
    Context->PhysicalSectorSize = Context->LogicalSectorSize;
    if (namespaceSize >
        MAXULONGLONG / (ULONGLONG)Context->LogicalSectorSize) {
        return STATUS_INTEGER_OVERFLOW;
    }
    Context->CapacityBytes = namespaceSize * Context->LogicalSectorSize;

    ioSqAddress = (ULONGLONG)Context->Auxiliary.Logical.QuadPart;
    ioCqAddress = ioSqAddress + NVME_SQ_BYTES;
    RtlZeroMemory(&command, sizeof(command));
    command.Dword0 = NVME_ADMIN_CREATE_IOCQ;
    command.Prp1 = ioCqAddress;
    command.Cdw10 = ((NVME_QUEUE_ENTRIES - 1U) << 16U) | 1U;
    command.Cdw11 = 1U;
    status = KsccNvmeAdminCommand(Context, &command, 5000U, &controllerStatus);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&command, sizeof(command));
    command.Dword0 = NVME_ADMIN_CREATE_IOSQ;
    command.Prp1 = ioSqAddress;
    command.Cdw10 = ((NVME_QUEUE_ENTRIES - 1U) << 16U) | 1U;
    command.Cdw11 = (1U << 16U) | 1U;
    status = KsccNvmeAdminCommand(Context, &command, 5000U, &controllerStatus);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Context->ControllerType = KSWORD_ARK_STORAGE_CONTROLLER_TYPE_NVME;
    Context->PortOrNamespace = namespaceId;
    Context->Capabilities =
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_READ |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_WRITE |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_FLUSH |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_FUA |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_DMA |
        KSWORD_ARK_STORAGE_CONTROLLER_CAP_64BIT_DMA;
    RtlStringCchCopyW(
        Context->Detail,
        KSWORD_ARK_STORAGE_CONTROLLER_DETAIL_CHARS,
        L"Exclusive NVMe queues; system/live volume status is unverified");
    return STATUS_SUCCESS;
}

/* Disable the controller and prove RDY=0 before queue memory can be released. */
NTSTATUS
KsccNvmeStop(
    _Inout_ KSCC_DEVICE_CONTEXT* Context)
{
    PUCHAR bar;
    NTSTATUS status;

    if (Context->Bars[Context->RegisterBarIndex] == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    bar = Context->Bars[Context->RegisterBarIndex];
    KsccNvmeWrite32(bar, NVME_REG_INTMS, MAXULONG);
    if (Context->WriteObserved && !Context->RequiresReset) {
        ULONG command;
        ULONG polls;

        command = KsccNvmeRead32(bar, NVME_REG_CC);
        KsccNvmeWrite32(bar, NVME_REG_CC, command | NVME_CC_SHN_NORMAL);
        polls = KsccNvmePollCount(5000U);
        while (polls != 0U) {
            if ((KsccNvmeRead32(bar, NVME_REG_CSTS) &
                 NVME_CSTS_SHST_MASK) == NVME_CSTS_SHST_COMPLETE) {
                break;
            }
            KeStallExecutionProcessor(50U);
            polls -= 1U;
        }
        if (polls == 0U) {
            Context->RiskFlags |=
                KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE;
        }
    }
    KsccNvmeWrite32(
        bar,
        NVME_REG_CC,
        0U);
    status = KsccNvmeWaitReady(Context, FALSE, 5000U);
    return status;
}

/* Execute one selected-namespace read or write with PRP chaining and optional FUA. */
NTSTATUS
KsccNvmeTransfer(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ BOOLEAN Write,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) UCHAR* Buffer,
    _In_ ULONG Length,
    _In_ ULONG Flags,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus)
{
    KSCC_NVME_COMMAND command;
    ULONGLONG lba;
    ULONG blockCount;
    NTSTATUS status;

    if ((Offset % Context->LogicalSectorSize) != 0ULL ||
        (Length % Context->LogicalSectorSize) != 0U) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    if (Length == 0U || Length > Context->Data.Length) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (Write) {
        RtlCopyMemory(Context->Data.Virtual, Buffer, Length);
    }
    RtlZeroMemory(&command, sizeof(command));
    command.Dword0 = Write ? NVME_IO_WRITE : NVME_IO_READ;
    command.NamespaceId = Context->PortOrNamespace;
    status = KsccNvmeBuildPrp(Context, Length, &command.Prp1, &command.Prp2);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    lba = Offset / Context->LogicalSectorSize;
    blockCount = Length / Context->LogicalSectorSize;
    if (blockCount == 0U || blockCount > 65536U) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    command.Cdw10 = (ULONG)lba;
    command.Cdw11 = (ULONG)(lba >> 32U);
    command.Cdw12 = blockCount - 1U;
    if ((Flags & KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FUA) != 0U) {
        command.Cdw12 |= 1UL << 30U;
    }
    status = KsccNvmeIoCommand(
        Context,
        &command,
        TimeoutMilliseconds,
        ControllerStatus);
    if (NT_SUCCESS(status) && !Write) {
        RtlCopyMemory(Buffer, Context->Data.Virtual, Length);
    }
    return status;
}

/* Submit the NVM Flush command to namespace one. */
NTSTATUS
KsccNvmeFlush(
    _Inout_ KSCC_DEVICE_CONTEXT* Context,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ ULONG* ControllerStatus)
{
    KSCC_NVME_COMMAND command;

    RtlZeroMemory(&command, sizeof(command));
    command.Dword0 = NVME_IO_FLUSH;
    command.NamespaceId = Context->PortOrNamespace;
    return KsccNvmeIoCommand(
        Context,
        &command,
        TimeoutMilliseconds,
        ControllerStatus);
}
