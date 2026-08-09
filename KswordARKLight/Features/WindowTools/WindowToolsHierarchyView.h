#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::WindowTools {

// CreateWindowHierarchyView creates the window hierarchy diagnostics page.
// Inputs are the tab-host parent HWND and initial bounds; output is the page
// HWND or nullptr on failure.
//
// The window list is filled by a background enumeration, but the report for the
// selected window is built synchronously on the UI thread. That is deliberate:
// it is roughly twenty read-only calls, and it must describe the window as it is
// at the moment of selection rather than as it was when a worker got around to
// it -- ancestry, Z order and style bits all change while the user is looking.
HWND CreateWindowHierarchyView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::WindowTools
