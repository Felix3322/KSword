#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::WindowTools {

// CreateCaptureProtectionView creates the window capture-protection page. Inputs
// are the tab-host parent HWND and initial bounds; output is the page HWND or
// nullptr on failure.
//
// Enumeration and the GetWindowDisplayAffinity query run on an AsyncSnapshotTask
// worker because they are read-only and the window count is unbounded.
// SetWindowDisplayAffinity does not: it mutates another window's state, so it
// stays on the UI thread together with the confirmation prompt that guards it.
HWND CreateCaptureProtectionView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::WindowTools
