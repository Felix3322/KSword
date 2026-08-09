#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::NetTools {

// CreateNetToolsFeaturePage is the module facade for the network toolbox. Inputs
// are the dock parent HWND and bounds; processing creates one tab host carrying
// the connection, diagnostics and firewall pages; output is the child HWND or
// nullptr on failure.
HWND CreateNetToolsFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::NetTools
