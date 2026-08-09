#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::WindowTools {

// CreateClipboardInspectorView creates the clipboard inspection page. Inputs are
// the tab-host parent HWND and initial bounds; output is the page HWND or
// nullptr on failure.
//
// Everything on this page runs on the UI thread on purpose. OpenClipboard binds
// the clipboard to the calling thread and to a window that thread owns, so the
// AsyncSnapshotTask worker used elsewhere in this module cannot be used here:
// it neither owns the page HWND nor outlives the call long enough to hold the
// clipboard safely. The work is bounded anyway -- a clipboard carries a few
// dozen formats at most.
HWND CreateClipboardInspectorView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::WindowTools
