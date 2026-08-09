#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::WindowTools {

// CreateWindowToolsFeaturePage is the single entry point of this module. Inputs
// are the dock parent HWND and its bounds; processing creates the tab host plus
// its four diagnostic pages; output is the page HWND or nullptr on failure.
//
// This module sits beside Features/Window instead of inside it because the two
// answer different questions. The window list answers "which windows exist";
// these tabs answer questions about window-adjacent state that has no column in
// a list: who owns the clipboard right now, which windows opted out of screen
// capture, what a single window's ancestry and style bits actually decode to,
// and which global hotkey combinations are already taken.
HWND CreateWindowToolsFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::WindowTools
