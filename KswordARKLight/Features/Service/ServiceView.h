#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Service {

// CreateServiceView creates the service management page. Inputs are the dock
// parent HWND and initial bounds; processing registers the window class once and
// creates the child page; output is the page HWND or nullptr on failure.
HWND CreateServiceView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Service
