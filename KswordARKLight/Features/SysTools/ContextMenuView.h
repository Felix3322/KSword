#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::SysTools {

// CreateContextMenuView creates the "右键菜单" tab. Inputs are the tab parent and
// initial bounds; processing enumerates the shell registration points and routes
// every mutation through ContextMenuScanner's backup-then-delete actions; output
// is the page HWND or nullptr.
HWND CreateContextMenuView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools
