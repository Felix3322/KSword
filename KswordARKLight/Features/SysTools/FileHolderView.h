#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::SysTools {

// CreateFileHolderView creates the "文件占用" tab. Inputs are the tab parent and
// the initial bounds; processing drives ScanFileHolders on a worker thread and
// renders the matches; output is the page HWND or nullptr.
HWND CreateFileHolderView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools
