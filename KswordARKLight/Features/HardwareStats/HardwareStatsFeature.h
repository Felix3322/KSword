#pragma once

#include "../../Core/Win32Lean.h"

namespace Ksword::Features::HardwareStats {

// CreateHardwareStatsFeaturePage is the module facade for the hardware
// statistics page. Inputs are the dock parent HWND and bounds; processing hosts
// four sub-views (performance counters, disk activity, USB topology and system
// buses) on one tab control; output is the child HWND or nullptr on failure.
//
// This page is deliberately separate from the existing hardware device tree:
// that page answers "what is installed", this one answers "what is it doing
// right now" and keeps live sampling out of a table meant to stay still.
HWND CreateHardwareStatsFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::HardwareStats
