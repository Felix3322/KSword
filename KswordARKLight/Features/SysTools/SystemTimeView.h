#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::SysTools {

// CreateSystemTimeView creates the "系统时间" tab. Inputs are the tab parent and
// initial bounds; processing renders CollectSystemTimeInfo into a read-only
// pane and keeps a live clock line ticking; output is the page HWND or nullptr.
HWND CreateSystemTimeView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools
