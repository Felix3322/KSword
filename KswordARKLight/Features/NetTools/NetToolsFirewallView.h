#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::NetTools {

// CreateNetToolsFirewallView creates the read-only firewall rule tab. Inputs are
// the tab-host parent HWND and initial bounds; processing registers the window
// class once and creates the child page; output is the page HWND or nullptr on
// failure.
HWND CreateNetToolsFirewallView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::NetTools
