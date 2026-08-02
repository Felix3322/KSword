# Controller research companion

This optional PnP function driver is for a dedicated, non-boot storage
controller that has been manually rebound from the Windows inbox storage
driver. It is not a lower filter and does not claim that ordinary storage IRPs
are direct controller access. Its minimum supported operating system is
Windows 10 version 2004 (build 19041), matching the ExAllocatePool2 runtime
contract used by the driver.

The driver validates the PnP compatible ID and PCI class tuple before touching
translated resources. It maps only resources assigned by PnP, allocates its own
DMA queues through KMDF, and publishes a device interface for user-mode
enumeration. AHCI uses an owned command list, received-FIS area, command table,
and PRDT. NVMe uses owned admin and I/O queue pairs plus PRPs. Legacy IDE uses
the translated task-file ports with LBA48 PIO. All three backends explicitly
mask device interrupts and use bounded polling only.

The device interface ACL permits only SYSTEM and local administrators, and the
function device accepts only one open handle at a time.

Writes require an exclusive session, generation match, confirmation token,
expected-before SHA-256 when supplied, an unconditional cache flush, reread
verification, and audit. An FUA request is rejected when the selected backend
does not report FUA support; the user-mode research page requests FUA only when
the queried capability advertises it.
One verified original-byte snapshot is retained for an explicit conditional
rollback. These checks are not an atomic disk transaction and cannot eliminate
firmware-cache, concurrent-device, media, or power-loss failure.

Only NVMe exposes the explicit controlled-reset command because CC.EN/RDY gives
that backend a verifiable reset contract. AHCI and legacy IDE reset requests
return not-supported instead of claiming an unverified recovery.

Never bind this INF to the controller that hosts Windows, paging, crash-dump,
hibernation, or any mounted volume. The INF is demand-start and is intended for
manual Device Manager selection only.
