# KSword Cheat Engine executable plugin

The launcher and `KswordCheatEnginePlugin.dll` are KSword project components.

The packaged `payload/Cheat Engine/` directory is copied from the user's
locally installed Cheat Engine 7.6 distribution. Cheat Engine remains the work
of its original authors. Its official source is available at:

https://github.com/cheat-engine/cheat-engine

Original third-party notices shipped with Cheat Engine, including
`libiptlicense.txt` and `tcclib/COPYING`, are retained in the payload.

The package intentionally omits Cheat Engine's DBK/DBVM kernel payloads. Core
process open, virtual memory query, read, and write operations are redirected
by the bundled CE plugin to `ArkDriverClient` and the KSword driver.
