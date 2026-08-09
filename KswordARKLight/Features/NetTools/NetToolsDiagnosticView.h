#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::NetTools {

// CreateNetToolsDiagnosticView creates the ping / traceroute / DNS tab. Inputs
// are the tab-host parent HWND and initial bounds; processing registers the
// window class once and creates the child page; output is the page HWND or
// nullptr on failure.
HWND CreateNetToolsDiagnosticView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::NetTools
