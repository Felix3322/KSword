#pragma once

#include "ark/ark_dyndata.h"

EXTERN_C_START

// KSW_RUNTIME_KERNEL_LAYOUT contains only offsets and RVAs recovered from
// public layouts, exports, and live structural validation. A negative member
// is unavailable, so callers never have to interpret a guessed zero value.
typedef struct _KSW_RUNTIME_KERNEL_LAYOUT
{
    LONG KldrInLoadOrderLinks;
    LONG KldrDllBase;
    LONG KldrSizeOfImage;
    LONG KldrFullDllName;
    LONG KldrBaseDllName;
    LONG DoDriverStart;
    LONG DoDriverSize;
    LONG DoDriverSection;
    LONG DoMajorFunction;
    LONG DoFastIoDispatch;
    LONG DoDriverUnload;
    LONG RtlAvlBalancedRoot;
    LONG RtlAvlOrderedPointer;
    LONG RtlAvlWhichOrderedElement;
    LONG RtlAvlNumberGenericTableElements;
    LONG RtlAvlDepthOfTree;
    LONG RtlAvlRestartKey;
    LONG RtlAvlDeleteCount;
    LONG RtlAvlTypeSize;
    LONG UldName;
    LONG UldStartAddress;
    LONG UldEndAddress;
    LONG UldCurrentTime;
    LONG UldTypeSize;
    LONG PiDdbDriverName;
    LONG PiDdbTimeDateStamp;
    LONG PiDdbLoadStatus;
    LONG PiDdbTypeSize;
    LONG PsLoadedModuleListRva;
    LONG MmUnloadedDriversRva;
    LONG MmLastUnloadedDriverRva;
    LONG PiDDBCacheTableRva;
    LONG PiDDBLockRva;
    LONG KeServiceDescriptorTableShadowRva;
} KSW_RUNTIME_KERNEL_LAYOUT, *PKSW_RUNTIME_KERNEL_LAYOUT;

VOID
KswordARKDriverResolveKernelFallbackLayout(
    _In_opt_ PDRIVER_OBJECT ValidationDriverObject,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* NtoskrnlIdentity,
    _Out_ PKSW_RUNTIME_KERNEL_LAYOUT LayoutOut
    );

EXTERN_C_END
