#pragma once

#include <ntddk.h>

/*
 * Push locks require normal kernel APC delivery to remain disabled for the
 * complete acquire/release interval.  These helpers make that contract part
 * of every KSword-owned push-lock operation, including early-return paths.
 */
static __forceinline
VOID
KswordARKAcquirePushLockShared(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(Lock);
}

static __forceinline
VOID
KswordARKReleasePushLockShared(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    ExReleasePushLockShared(Lock);
    KeLeaveCriticalRegion();
}

static __forceinline
VOID
KswordARKAcquirePushLockExclusive(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(Lock);
}

static __forceinline
VOID
KswordARKReleasePushLockExclusive(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    ExReleasePushLockExclusive(Lock);
    KeLeaveCriticalRegion();
}
