#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Privilege {

// CreatePrivilegeView creates the token privilege page. Inputs are the dock
// parent HWND and initial bounds; output is the page HWND or nullptr.
HWND CreatePrivilegeView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Privilege
