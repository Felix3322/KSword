#pragma once

#include "../dyndata/dyndata_v4_internal.h"

EXTERN_C_START

NTSTATUS
KswordARKWorkQueueResolveRuntimeLayout(
    _Out_ KSW_DYN_V4_WORK_QUEUE_LAYOUT* LayoutOut
    );

NTSTATUS
KswordARKWorkQueueResolveActiveExWorkerField(
    _Out_ KSW_DYN_V4_BIT_FIELD_LAYOUT* FieldOut
    );

EXTERN_C_END
