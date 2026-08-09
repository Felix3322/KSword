#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::Service {

// CreateServiceFeaturePage is the module facade for SCM service management.
// Inputs are the dock parent HWND and bounds; processing delegates to
// ServiceView and routes every mutation through ServiceActions; output is the
// child HWND or nullptr on failure.
HWND CreateServiceFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Service
