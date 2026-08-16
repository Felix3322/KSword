/*++

Module Name:

    bugcheck_svga.c

Abstract:

    VMware SVGA-II detection, framebuffer/FIFO access, and crash-safe panel drawing.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_font.h"
#include "bugcheck_layout.h"

#define KSW_SVGA_PCI_MAX_BUSES 256UL
#define KSW_SVGA_PCI_MAX_DEVICES 32UL
#define KSW_SVGA_PCI_MAX_FUNCTIONS 8UL

#define KSW_SVGA_PCI_BAR_IO 0x00000001UL
#define KSW_SVGA_PCI_BAR_MEM_TYPE_MASK 0x00000006UL
#define KSW_SVGA_PCI_BAR_MEM_TYPE_64 0x00000004UL
#define KSW_SVGA_PCI_BAR_IO_MASK 0xFFFFFFFCUL
#define KSW_SVGA_PCI_BAR_MEM_MASK 0xFFFFFFF0UL

#define KSW_SVGA_ID_INVALID 0xFFFFFFFFUL
#define KSW_SVGA_ID_0 0x90000000UL
#define KSW_SVGA_ID_1 0x90000001UL
#define KSW_SVGA_ID_2 0x90000002UL
#define KSW_SVGA_ID_3 0x90000003UL

#define KSW_SVGA_INDEX_PORT 0UL
#define KSW_SVGA_VALUE_PORT 1UL

#define KSW_SVGA_REG_ID 0UL
#define KSW_SVGA_REG_ENABLE 1UL
#define KSW_SVGA_REG_WIDTH 2UL
#define KSW_SVGA_REG_HEIGHT 3UL
#define KSW_SVGA_REG_DEPTH 6UL
#define KSW_SVGA_REG_BITS_PER_PIXEL 7UL
#define KSW_SVGA_REG_RED_MASK 9UL
#define KSW_SVGA_REG_GREEN_MASK 10UL
#define KSW_SVGA_REG_BLUE_MASK 11UL
#define KSW_SVGA_REG_BYTES_PER_LINE 12UL
#define KSW_SVGA_REG_FB_START 13UL
#define KSW_SVGA_REG_FB_OFFSET 14UL
#define KSW_SVGA_REG_VRAM_SIZE 15UL
#define KSW_SVGA_REG_FB_SIZE 16UL
#define KSW_SVGA_REG_CAPABILITIES 17UL
#define KSW_SVGA_REG_MEM_SIZE 19UL
#define KSW_SVGA_REG_CONFIG_DONE 20UL
#define KSW_SVGA_REG_SYNC 21UL
#define KSW_SVGA_REG_BUSY 22UL

#define KSW_SVGA_FIFO_MIN 0UL
#define KSW_SVGA_FIFO_MAX 1UL
#define KSW_SVGA_FIFO_NEXT_CMD 2UL
#define KSW_SVGA_FIFO_STOP 3UL
#define KSW_SVGA_FIFO_HEADER_DWORDS 4UL
#define KSW_SVGA_CMD_UPDATE 1UL

typedef struct _KSW_SVGA_PCI_BAR
{
    BOOLEAN Present;
    BOOLEAN IoSpace;
    BOOLEAN Is64Bit;
    ULONGLONG Address;
} KSW_SVGA_PCI_BAR, *PKSW_SVGA_PCI_BAR;

#if defined(_AMD64_) || defined(_M_AMD64)

static VOID
KswordARKSvgaWriteRegister(
    _In_ ULONG IoBase,
    _In_ ULONG Register,
    _In_ ULONG Value
    )
{
    WRITE_PORT_ULONG(
        (PULONG)(ULONG_PTR)(IoBase + KSW_SVGA_INDEX_PORT),
        Register);
    WRITE_PORT_ULONG(
        (PULONG)(ULONG_PTR)(IoBase + KSW_SVGA_VALUE_PORT),
        Value);
}

static ULONG
KswordARKSvgaReadRegister(
    _In_ ULONG IoBase,
    _In_ ULONG Register
    )
{
    WRITE_PORT_ULONG(
        (PULONG)(ULONG_PTR)(IoBase + KSW_SVGA_INDEX_PORT),
        Register);
    return READ_PORT_ULONG(
        (PULONG)(ULONG_PTR)(IoBase + KSW_SVGA_VALUE_PORT));
}

static ULONG
KswordARKSvgaProbeId(
    _In_ ULONG IoBase
    )
{
    static const ULONG ids[] = {
        KSW_SVGA_ID_3,
        KSW_SVGA_ID_2,
        KSW_SVGA_ID_1,
        KSW_SVGA_ID_0
    };
    ULONG index;

    for (index = 0; index < RTL_NUMBER_OF(ids); ++index) {
        KswordARKSvgaWriteRegister(IoBase, KSW_SVGA_REG_ID, ids[index]);
        if (KswordARKSvgaReadRegister(IoBase, KSW_SVGA_REG_ID) == ids[index]) {
            return ids[index];
        }
    }
    return KSW_SVGA_ID_INVALID;
}

static VOID
KswordARKSvgaParseBar(
    _In_ ULONG RawBar,
    _In_ ULONG NextRawBar,
    _Out_ PKSW_SVGA_PCI_BAR Bar
    )
{
    RtlZeroMemory(Bar, sizeof(*Bar));
    if (RawBar == 0 || RawBar == 0xFFFFFFFFUL) {
        return;
    }

    Bar->Present = TRUE;
    if ((RawBar & KSW_SVGA_PCI_BAR_IO) != 0) {
        Bar->IoSpace = TRUE;
        Bar->Address = RawBar & KSW_SVGA_PCI_BAR_IO_MASK;
        return;
    }

    Bar->Is64Bit =
        ((RawBar & KSW_SVGA_PCI_BAR_MEM_TYPE_MASK) == KSW_SVGA_PCI_BAR_MEM_TYPE_64)
            ? TRUE
            : FALSE;
    Bar->Address = RawBar & KSW_SVGA_PCI_BAR_MEM_MASK;
    if (Bar->Is64Bit) {
        Bar->Address |= ((ULONGLONG)NextRawBar << 32);
    }
}

static BOOLEAN
KswordARKSvgaFindVmwareDisplay(
    _Out_ PPCI_COMMON_CONFIG Config,
    _Out_writes_(KSWORD_ARK_PCI_BAR_COUNT) PKSW_SVGA_PCI_BAR Bars,
    _Out_ PULONG BusOut,
    _Out_ PULONG DeviceOut,
    _Out_ PULONG FunctionOut
    )
{
    ULONG bus;
    ULONG device;
    ULONG function;
    ULONG bytesRead;
    ULONG barIndex;
    PCI_SLOT_NUMBER slot;
    PCI_COMMON_CONFIG config;

    RtlZeroMemory(Config, sizeof(*Config));
    RtlZeroMemory(Bars, sizeof(KSW_SVGA_PCI_BAR) * KSWORD_ARK_PCI_BAR_COUNT);

    for (bus = 0; bus < KSW_SVGA_PCI_MAX_BUSES; ++bus) {
        for (device = 0; device < KSW_SVGA_PCI_MAX_DEVICES; ++device) {
            for (function = 0; function < KSW_SVGA_PCI_MAX_FUNCTIONS; ++function) {
                RtlZeroMemory(&slot, sizeof(slot));
                slot.u.bits.DeviceNumber = device;
                slot.u.bits.FunctionNumber = function;
                RtlZeroMemory(&config, sizeof(config));

#pragma warning(push)
#pragma warning(disable: 4996)
                bytesRead = HalGetBusDataByOffset(
                    PCIConfiguration,
                    bus,
                    slot.u.AsULONG,
                    &config,
                    0,
                    sizeof(config));
#pragma warning(pop)
                if (bytesRead < PCI_COMMON_HDR_LENGTH ||
                    config.VendorID != KSWORD_ARK_VMWARE_VENDOR_ID ||
                    config.BaseClass != 0x03 ||
                    (config.HeaderType & 0x7FUL) != PCI_DEVICE_TYPE) {
                    continue;
                }

                *Config = config;
                for (barIndex = 0; barIndex < KSWORD_ARK_PCI_BAR_COUNT; ++barIndex) {
                    const ULONG nextRawBar = (barIndex + 1UL) < KSWORD_ARK_PCI_BAR_COUNT
                        ? config.u.type0.BaseAddresses[barIndex + 1UL]
                        : 0;
                    KswordARKSvgaParseBar(
                        config.u.type0.BaseAddresses[barIndex],
                        nextRawBar,
                        &Bars[barIndex]);
                }

                *BusOut = bus;
                *DeviceOut = device;
                *FunctionOut = function;
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOLEAN
KswordARKSvgaValidateGeometry(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    ULONGLONG visibleBytes;
    ULONG bytesPerPixel;

    if (Context->Width == 0 || Context->Height == 0 ||
        Context->Width > 16384UL || Context->Height > 16384UL ||
        (Context->Bpp != 15UL && Context->Bpp != 16UL &&
         Context->Bpp != 24UL && Context->Bpp != 32UL)) {
        return FALSE;
    }

    bytesPerPixel = (Context->Bpp + 7UL) / 8UL;
    if (bytesPerPixel == 0 ||
        Context->Pitch < Context->Width * bytesPerPixel ||
        Context->Pitch > (1024UL * 1024UL)) {
        return FALSE;
    }

    visibleBytes = (ULONGLONG)Context->Pitch * Context->Height;
    if (visibleBytes == 0 || visibleBytes > (256ULL * 1024ULL * 1024ULL)) {
        return FALSE;
    }
    if (Context->FbSize != 0 &&
        ((ULONGLONG)Context->FbOffset >= Context->FbSize ||
         visibleBytes + Context->FbOffset > Context->FbSize)) {
        return FALSE;
    }

    Context->FramebufferLength = (SIZE_T)visibleBytes;
    return TRUE;
}

NTSTATUS
KswordARKBugcheckSvgaInitialize(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    PCI_COMMON_CONFIG config;
    KSW_SVGA_PCI_BAR bars[KSWORD_ARK_PCI_BAR_COUNT];
    PKSW_SVGA_PCI_BAR fifoBar;
    ULONG bus;
    ULONG device;
    ULONG function;
    ULONG svgaId;
    ULONG fifoBytes;
    PHYSICAL_ADDRESS physical;
    PVOID mapped;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Context, sizeof(*Context));
    RtlZeroMemory(&config, sizeof(config));
    RtlZeroMemory(bars, sizeof(bars));

    if (!KswordARKSvgaFindVmwareDisplay(
            &config,
            bars,
            &bus,
            &device,
            &function)) {
        return STATUS_NOT_SUPPORTED;
    }

    // Require the VMware SVGA-II port/framebuffer BAR layout before touching it.
    if (!bars[0].Present || !bars[0].IoSpace ||
        !bars[1].Present || bars[1].IoSpace ||
        bars[0].Address == 0 || bars[0].Address > MAXULONG) {
        return STATUS_NOT_SUPPORTED;
    }

    svgaId = KswordARKSvgaProbeId((ULONG)bars[0].Address);
    if (svgaId == KSW_SVGA_ID_INVALID) {
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    Context->Found = TRUE;
    Context->Bus = bus;
    Context->Device = device;
    Context->Function = function;
    Context->VendorId = config.VendorID;
    Context->DeviceId = config.DeviceID;
    Context->IoBase = (ULONG)bars[0].Address;
    Context->Width = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_WIDTH);
    Context->Height = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_HEIGHT);
    Context->Depth = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_DEPTH);
    Context->Bpp = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_BITS_PER_PIXEL);
    Context->Pitch = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_BYTES_PER_LINE);
    Context->FbOffset = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_FB_OFFSET);
    Context->FbSize = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_FB_SIZE);
    Context->VramSize = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_VRAM_SIZE);
    Context->RedMask = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_RED_MASK);
    Context->GreenMask = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_GREEN_MASK);
    Context->BlueMask = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_BLUE_MASK);
    Context->Capabilities = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_CAPABILITIES);

    if (!KswordARKSvgaValidateGeometry(Context) ||
        bars[1].Address > (ULONGLONG)MAXLONGLONG - Context->FbOffset) {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    physical.QuadPart = (LONGLONG)(bars[1].Address + Context->FbOffset);
    mapped = MmMapIoSpace(physical, Context->FramebufferLength, MmNonCached);
    if (mapped == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Context->FramebufferPhysical = physical;
    Context->Framebuffer = (volatile UCHAR*)mapped;
    Context->Mapped = TRUE;

    fifoBar = bars[1].Is64Bit ? &bars[3] : &bars[2];
    if (fifoBar->Present && !fifoBar->IoSpace) {
        fifoBytes = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_MEM_SIZE);
        if (fifoBytes >= 4096UL && fifoBytes <= (16UL * 1024UL * 1024UL)) {
            physical.QuadPart = (LONGLONG)fifoBar->Address;
            mapped = MmMapIoSpace(physical, fifoBytes, MmNonCached);
            if (mapped != NULL) {
                Context->FifoPhysical = physical;
                Context->FifoLength = fifoBytes;
                Context->Fifo = (volatile ULONG*)mapped;
                Context->FifoMapped = TRUE;
            }
        }
    }

    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckSvgaShutdown(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }
    if (Context->FifoMapped && Context->Fifo != NULL) {
        MmUnmapIoSpace((PVOID)Context->Fifo, Context->FifoLength);
    }
    if (Context->Mapped && Context->Framebuffer != NULL) {
        MmUnmapIoSpace((PVOID)Context->Framebuffer, Context->FramebufferLength);
    }
    RtlZeroMemory(Context, sizeof(*Context));
}

static VOID
KswordARKSvgaPortSyncNoLog(
    _In_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    ULONG spin;

    if (Context == NULL || Context->IoBase == 0) {
        return;
    }
    KswordARKSvgaWriteRegister(Context->IoBase, KSW_SVGA_REG_SYNC, 1UL);
    for (spin = 0; spin < 1000000UL; ++spin) {
        if (KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_BUSY) == 0) {
            break;
        }
        KeStallExecutionProcessor(1);
    }
}

VOID
KswordARKBugcheckSvgaModeSetNoLog(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    ULONG configDone;

    if (Context == NULL || !Context->Mapped ||
        Context->Framebuffer == NULL || Context->IoBase == 0) {
        return;
    }

    configDone = KswordARKSvgaReadRegister(Context->IoBase, KSW_SVGA_REG_CONFIG_DONE);
    if (configDone == 0) {
        configDone = 1;
    }
    KswordARKSvgaWriteRegister(Context->IoBase, KSW_SVGA_REG_ENABLE, 0UL);
    KeStallExecutionProcessor(1000);
    KswordARKSvgaWriteRegister(Context->IoBase, KSW_SVGA_REG_WIDTH, Context->Width);
    KswordARKSvgaWriteRegister(Context->IoBase, KSW_SVGA_REG_HEIGHT, Context->Height);
    KswordARKSvgaWriteRegister(Context->IoBase, KSW_SVGA_REG_BITS_PER_PIXEL, Context->Bpp);
    KswordARKSvgaWriteRegister(Context->IoBase, KSW_SVGA_REG_ENABLE, 1UL);
    KswordARKSvgaWriteRegister(Context->IoBase, KSW_SVGA_REG_CONFIG_DONE, configDone);
    KeStallExecutionProcessor(1000);
    KswordARKSvgaPortSyncNoLog(Context);
}

static BOOLEAN
KswordARKSvgaFifoUpdateNoLog(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context,
    _In_ ULONG X,
    _In_ ULONG Y,
    _In_ ULONG Width,
    _In_ ULONG Height
    )
{
    volatile ULONG* fifo;
    ULONG min;
    ULONG max;
    ULONG next;
    ULONG stop;
    ULONG freeBytes;
    ULONG values[5];
    ULONG index;

    if (Context == NULL || !Context->FifoMapped || Context->Fifo == NULL ||
        Context->FifoLength < (KSW_SVGA_FIFO_HEADER_DWORDS * sizeof(ULONG))) {
        return FALSE;
    }

    fifo = Context->Fifo;
    min = fifo[KSW_SVGA_FIFO_MIN];
    max = fifo[KSW_SVGA_FIFO_MAX];
    next = fifo[KSW_SVGA_FIFO_NEXT_CMD];
    stop = fifo[KSW_SVGA_FIFO_STOP];
    if (min < KSW_SVGA_FIFO_HEADER_DWORDS * sizeof(ULONG) ||
        max > Context->FifoLength || min >= max ||
        next < min || next >= max || stop < min || stop >= max ||
        ((min | max | next | stop) & 3UL) != 0) {
        return FALSE;
    }

    if (next >= stop) {
        freeBytes = (max - next) + (stop - min);
    } else {
        freeBytes = stop - next;
    }
    if (freeBytes <= sizeof(values)) {
        return FALSE;
    }

    values[0] = KSW_SVGA_CMD_UPDATE;
    values[1] = X;
    values[2] = Y;
    values[3] = Width;
    values[4] = Height;
    for (index = 0; index < RTL_NUMBER_OF(values); ++index) {
        fifo[next / sizeof(ULONG)] = values[index];
        next += sizeof(ULONG);
        if (next == max) {
            next = min;
        }
    }
    KeMemoryBarrier();
    fifo[KSW_SVGA_FIFO_NEXT_CMD] = next;
    KeMemoryBarrier();
    KswordARKSvgaPortSyncNoLog(Context);
    return TRUE;
}

static ULONG
KswordARKSvgaPackChannel(
    _In_ UCHAR Value,
    _In_ ULONG Mask
    )
{
    ULONG shift = 0;
    ULONG bits = 0;
    ULONG work = Mask;
    ULONG maximum;

    if (Mask == 0) {
        return 0;
    }
    while ((work & 1UL) == 0) {
        ++shift;
        work >>= 1;
    }
    while ((work & 1UL) != 0) {
        ++bits;
        work >>= 1;
    }
    maximum = bits >= 31 ? MAXULONG : ((1UL << bits) - 1UL);
    return ((((ULONG)Value * maximum) + 127UL) / 255UL) << shift;
}

static ULONG
KswordARKSvgaPixelFromRgb(
    _In_ PKSWORD_ARK_SVGA_CONTEXT Context,
    _In_ UCHAR Red,
    _In_ UCHAR Green,
    _In_ UCHAR Blue
    )
{
    ULONG redMask = Context->RedMask;
    ULONG greenMask = Context->GreenMask;
    ULONG blueMask = Context->BlueMask;

    if (redMask == 0 || greenMask == 0 || blueMask == 0) {
        if (Context->Bpp == 15) {
            redMask = 0x7C00UL;
            greenMask = 0x03E0UL;
            blueMask = 0x001FUL;
        } else if (Context->Bpp == 16) {
            redMask = 0xF800UL;
            greenMask = 0x07E0UL;
            blueMask = 0x001FUL;
        } else {
            redMask = 0x00FF0000UL;
            greenMask = 0x0000FF00UL;
            blueMask = 0x000000FFUL;
        }
    }

    return KswordARKSvgaPackChannel(Red, redMask) |
           KswordARKSvgaPackChannel(Green, greenMask) |
           KswordARKSvgaPackChannel(Blue, blueMask);
}

static VOID
KswordARKSvgaWritePixel(
    _In_ PKSWORD_ARK_SVGA_CONTEXT Context,
    _In_ ULONG X,
    _In_ ULONG Y,
    _In_ ULONG Pixel
    )
{
    volatile UCHAR* destination;
    ULONG bytesPerPixel;

    if (Context == NULL || !Context->Mapped || Context->Framebuffer == NULL ||
        X >= Context->Width || Y >= Context->Height) {
        return;
    }
    bytesPerPixel = (Context->Bpp + 7UL) / 8UL;
    destination = Context->Framebuffer + ((SIZE_T)Y * Context->Pitch) +
                  ((SIZE_T)X * bytesPerPixel);
    if (bytesPerPixel == 4) {
        *(volatile ULONG*)destination = Pixel;
    } else if (bytesPerPixel == 3) {
        destination[0] = (UCHAR)(Pixel & 0xFF);
        destination[1] = (UCHAR)((Pixel >> 8) & 0xFF);
        destination[2] = (UCHAR)((Pixel >> 16) & 0xFF);
    } else if (bytesPerPixel == 2) {
        *(volatile USHORT*)destination = (USHORT)Pixel;
    }
}

static VOID
KswordARKSvgaFillRect(
    _In_ PKSWORD_ARK_SVGA_CONTEXT Context,
    _In_ ULONG Left,
    _In_ ULONG Top,
    _In_ ULONG Right,
    _In_ ULONG Bottom,
    _In_ ULONG Pixel
    )
{
    ULONG x;
    ULONG y;

    if (Context == NULL || Left >= Context->Width || Top >= Context->Height) {
        return;
    }
    if (Right > Context->Width) {
        Right = Context->Width;
    }
    if (Bottom > Context->Height) {
        Bottom = Context->Height;
    }
    for (y = Top; y < Bottom; ++y) {
        for (x = Left; x < Right; ++x) {
            KswordARKSvgaWritePixel(Context, x, y, Pixel);
        }
    }
}

static VOID
KswordARKSvgaDrawCharacter(
    _In_ PKSWORD_ARK_SVGA_CONTEXT Context,
    _In_ ULONG X,
    _In_ ULONG Y,
    _In_ CHAR Character,
    _In_ ULONG Color,
    _In_ ULONG Scale
    )
{
    ULONG row;
    ULONG column;
    ULONG dx;
    ULONG dy;
    UCHAR bits;
    ULONG glyphIndex;

    if ((UCHAR)Character < KSWORD_ARK_BUGCHECK_FONT_FIRST ||
        (UCHAR)Character > KSWORD_ARK_BUGCHECK_FONT_LAST) {
        Character = '?';
    }
    if (Scale == 0) {
        Scale = 1;
    }

    glyphIndex = (UCHAR)Character - KSWORD_ARK_BUGCHECK_FONT_FIRST;
    for (row = 0; row < KSWORD_ARK_BUGCHECK_FONT_HEIGHT; ++row) {
        bits = g_KswordArkBugcheckFont8x12[glyphIndex][row];
        for (column = 0; column < KSWORD_ARK_BUGCHECK_FONT_WIDTH; ++column) {
            if ((bits & (0x80U >> column)) == 0) {
                continue;
            }
            for (dy = 0; dy < Scale; ++dy) {
                for (dx = 0; dx < Scale; ++dx) {
                    KswordARKSvgaWritePixel(
                        Context,
                        X + column * Scale + dx,
                        Y + row * Scale + dy,
                        Color);
                }
            }
        }
    }
}

static VOID
KswordARKSvgaDrawText(
    _In_ PKSWORD_ARK_SVGA_CONTEXT Context,
    _In_ ULONG X,
    _In_ ULONG Y,
    _In_z_ PCSTR Text,
    _In_ ULONG Color,
    _In_ ULONG Scale
    )
{
    ULONG cursor = X;

    if (Text == NULL) {
        return;
    }
    while (*Text != '\0') {
        KswordARKSvgaDrawCharacter(Context, cursor, Y, *Text, Color, Scale);
        cursor += (KSWORD_ARK_BUGCHECK_FONT_WIDTH + 1UL) * Scale;
        if (cursor >= Context->Width) {
            break;
        }
        ++Text;
    }
}

static BOOLEAN
KswordARKSvgaDrawBitmap(
    _In_ PKSWORD_ARK_BUGCHECK_STATE State,
    _In_ ULONG DestinationX,
    _In_ ULONG DestinationY,
    _In_ ULONG DestinationWidth,
    _In_ ULONG DestinationHeight
    )
{
    ULONG backgroundBlue;
    ULONG backgroundGreen;
    ULONG backgroundRed;
    ULONG width;
    ULONG height;
    ULONG x;
    ULONG y;
    ULONG pixel;

    if (State == NULL || DestinationWidth == 0 || DestinationHeight == 0 ||
        InterlockedCompareExchange(&State->Bitmap.Valid, 1, 1) == 0 ||
        DestinationX >= State->Svga.Width || DestinationY >= State->Svga.Height) {
        return FALSE;
    }

    width = DestinationWidth;
    height = DestinationHeight;
    if (DestinationX + width > State->Svga.Width) {
        width = State->Svga.Width - DestinationX;
    }
    if (DestinationY + height > State->Svga.Height) {
        height = State->Svga.Height - DestinationY;
    }

    backgroundRed = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED;
    backgroundGreen = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN;
    backgroundBlue = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE;
    for (y = 0; y < height; ++y) {
        ULONG sourceY;

        sourceY = (y * State->Bitmap.Height) / height;
        for (x = 0; x < width; ++x) {
            ULONG alpha;
            ULONG sourceBlue;
            ULONG sourceGreen;
            ULONG sourceRed;
            ULONG sourceX;
            const UCHAR* source;

            sourceX = (x * State->Bitmap.Width) / width;
            source = g_KswordArkBugcheckBitmapPixels +
                ((SIZE_T)sourceY * State->Bitmap.Stride) +
                ((SIZE_T)sourceX * 4UL);
            sourceBlue = source[0];
            sourceGreen = source[1];
            sourceRed = source[2];
            alpha = source[3];
            pixel = KswordARKSvgaPixelFromRgb(
                &State->Svga,
                (UCHAR)((sourceRed * alpha +
                         backgroundRed * (255UL - alpha)) / 255UL),
                (UCHAR)((sourceGreen * alpha +
                         backgroundGreen * (255UL - alpha)) / 255UL),
                (UCHAR)((sourceBlue * alpha +
                         backgroundBlue * (255UL - alpha)) / 255UL));
            KswordARKSvgaWritePixel(
                &State->Svga,
                DestinationX + x,
                DestinationY + y,
                pixel);
        }
    }
    return TRUE;
}

typedef struct _KSWORD_ARK_SVGA_LAYOUT_CONTEXT
{
    PKSWORD_ARK_SVGA_CONTEXT Svga;
    ULONG Colors[KswordArkBugcheckLayoutColorCount];
    ULONG Border;
} KSWORD_ARK_SVGA_LAYOUT_CONTEXT, *PKSWORD_ARK_SVGA_LAYOUT_CONTEXT;

static NTSTATUS
KswordARKSvgaLayoutDrawText(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_z_ PCSTR Text,
    _In_ ULONG ColorIndex
    )
{
    PKSWORD_ARK_SVGA_LAYOUT_CONTEXT layout;

    layout = (PKSWORD_ARK_SVGA_LAYOUT_CONTEXT)Context;
    if (layout == NULL || layout->Svga == NULL || Text == NULL ||
        X < 0 || Y < 0 ||
        ColorIndex >= (ULONG)KswordArkBugcheckLayoutColorCount) {
        return STATUS_INVALID_PARAMETER;
    }

    KswordARKSvgaDrawText(
        layout->Svga,
        (ULONG)X,
        (ULONG)Y,
        Text,
        layout->Colors[ColorIndex],
        1UL);
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKSvgaLayoutDrawFrame(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ KSWORD_ARK_BUGCHECK_LAYOUT_FRAME Frame
    )
{
    PKSWORD_ARK_SVGA_LAYOUT_CONTEXT layout;
    ULONG width;
    ULONG height;
    ULONG left;
    ULONG top;

    layout = (PKSWORD_ARK_SVGA_LAYOUT_CONTEXT)Context;
    if (layout == NULL || layout->Svga == NULL || X < 0 || Y < 0 ||
        !KswordARKBugcheckLayoutGetFrameMetrics(Frame, &width, &height)) {
        return STATUS_INVALID_PARAMETER;
    }

    left = (ULONG)X;
    top = (ULONG)Y;
    // Draw one-pixel outlines without allocating any crash-time resources.
    KswordARKSvgaFillRect(
        layout->Svga,
        left,
        top,
        left + width,
        top + 1UL,
        layout->Border);
    KswordARKSvgaFillRect(
        layout->Svga,
        left,
        top + height - 1UL,
        left + width,
        top + height,
        layout->Border);
    KswordARKSvgaFillRect(
        layout->Svga,
        left,
        top,
        left + 1UL,
        top + height,
        layout->Border);
    KswordARKSvgaFillRect(
        layout->Svga,
        left + width - 1UL,
        top,
        left + width,
        top + height,
        layout->Border);
    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckSvgaDrawPanelNoLog(
    _Inout_ PKSWORD_ARK_BUGCHECK_STATE State
    )
{
    KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS canvas;
    KSWORD_ARK_SVGA_LAYOUT_CONTEXT layout;
    PKSWORD_ARK_SVGA_CONTEXT svga;
    LONG originX;
    ULONG background;
    ULONG callbackMask;

    if (State == NULL ||
        InterlockedCompareExchange(&State->Active, 1, 1) == 0) {
        return;
    }
    svga = &State->Svga;
    if (!svga->Mapped || svga->Framebuffer == NULL ||
        svga->Width < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH ||
        svga->Height < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT) {
        return;
    }

    RtlZeroMemory(&layout, sizeof(layout));
    layout.Svga = svga;
    background = KswordARKSvgaPixelFromRgb(
        svga,
        KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED,
        KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN,
        KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE);
    layout.Colors[KswordArkBugcheckLayoutColorText] =
        KswordARKSvgaPixelFromRgb(
            svga,
            KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_RED,
            KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_GREEN,
            KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_BLUE);
    layout.Colors[KswordArkBugcheckLayoutColorAccent] =
        KswordARKSvgaPixelFromRgb(
            svga,
            KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_RED,
            KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_GREEN,
            KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_BLUE);
    layout.Colors[KswordArkBugcheckLayoutColorMuted] =
        KswordARKSvgaPixelFromRgb(
            svga,
            KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_RED,
            KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_GREEN,
            KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_BLUE);
    layout.Colors[KswordArkBugcheckLayoutColorWarning] =
        KswordARKSvgaPixelFromRgb(
            svga,
            KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_RED,
            KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_GREEN,
            KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_BLUE);
    layout.Border = KswordARKSvgaPixelFromRgb(
        svga,
        KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_RED,
        KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_GREEN,
        KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_BLUE);

    KswordARKSvgaFillRect(
        svga,
        0UL,
        0UL,
        svga->Width,
        svga->Height,
        background);
    originX = KswordARKBugcheckLayoutOriginX(
        svga->Width,
        svga->Height);
    if (!KswordARKSvgaDrawBitmap(
            State,
            (ULONG)(originX + KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X),
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y,
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_WIDTH,
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_HEIGHT)) {
        // The text fallback deliberately uses the requested KSwordDEV brand.
        KswordARKSvgaDrawText(
            svga,
            (ULONG)(originX + KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X),
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y + 18UL,
            "KSWORDDEV",
            layout.Colors[KswordArkBugcheckLayoutColorAccent],
            2UL);
        KswordARKSvgaDrawText(
            svga,
            (ULONG)(originX + KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X),
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y + 50UL,
            "KERNEL TOOLKIT",
            layout.Colors[KswordArkBugcheckLayoutColorMuted],
            1UL);
    }

    callbackMask = 0UL;
    if (State->ClassicRegistered) {
        callbackMask |= 0x1UL;
    }
    if (State->SecondaryRegistered) {
        callbackMask |= 0x2UL;
    }
    if (State->DumpIoRegistered) {
        callbackMask |= 0x4UL;
    }
    if (State->TriageRegistered) {
        callbackMask |= 0x8UL;
    }

    RtlZeroMemory(&canvas, sizeof(canvas));
    canvas.Context = &layout;
    canvas.Width = svga->Width;
    canvas.Height = svga->Height;
    canvas.DrawText = KswordARKSvgaLayoutDrawText;
    canvas.DrawFrame = KswordARKSvgaLayoutDrawFrame;
    (VOID)KswordARKBugcheckLayoutDraw(
        &canvas,
        &State->Diagnostics,
        callbackMask,
        State->ModuleCount);

    KeMemoryBarrier();
    if (!KswordARKSvgaFifoUpdateNoLog(
            svga,
            0UL,
            0UL,
            svga->Width,
            svga->Height)) {
        KswordARKSvgaPortSyncNoLog(svga);
    }
}

#else

NTSTATUS
KswordARKBugcheckSvgaInitialize(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(*Context));
    }
    return STATUS_NOT_SUPPORTED;
}

VOID
KswordARKBugcheckSvgaShutdown(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(*Context));
    }
}

VOID
KswordARKBugcheckSvgaModeSetNoLog(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    UNREFERENCED_PARAMETER(Context);
}

VOID
KswordARKBugcheckSvgaDrawPanelNoLog(
    _Inout_ PKSWORD_ARK_BUGCHECK_STATE State
    )
{
    UNREFERENCED_PARAMETER(State);
}

#endif
