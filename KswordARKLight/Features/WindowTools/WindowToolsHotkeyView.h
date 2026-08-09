#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::WindowTools {

// CreateHotkeyProbeView creates the global hotkey occupancy page. Inputs are the
// tab-host parent HWND and initial bounds; output is the page HWND or nullptr on
// failure.
//
// Windows has no API that lists who owns which global hotkey. The registration
// table lives in win32k and is not exposed to user mode: EnumWindows tells you
// nothing about it, and NtQuerySystemInformation has no class for it. Without a
// kernel component the only way to learn whether a combination is taken is to
// try to take it -- RegisterHotKey succeeds exactly when nobody holds it.
//
// The tradeoff, and the reason this page never probes on its own: during the
// probe this process momentarily owns every combination it successfully
// registers. If the user happens to press one of them in that window of a few
// microseconds, the keystroke is delivered here and dropped instead of reaching
// its real owner. Combinations that the shell reserves (Win+L and friends)
// simply fail to register, which the page reports as occupied.
HWND CreateHotkeyProbeView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::WindowTools
