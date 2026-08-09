#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::SysTools {

// CreateEventLogView creates the "事件日志" tab. Inputs are the tab parent and
// initial bounds; processing reads System/Application through QueryEventLog on a
// worker thread; output is the page HWND or nullptr.
HWND CreateEventLogView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools
