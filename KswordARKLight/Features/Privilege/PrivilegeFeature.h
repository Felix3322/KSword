#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Privilege {

// CreatePrivilegeFeaturePage is the module facade for process token privileges.
// Inputs are the dock parent HWND and bounds; processing delegates to
// PrivilegeView and routes changes through PrivilegeActions; output is the child
// HWND or nullptr on failure.
HWND CreatePrivilegeFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Privilege
