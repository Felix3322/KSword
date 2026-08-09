#pragma once

#include "../../Core/Win32Lean.h"

#include <string>

namespace Ksword::Features::HardwareStats {

// CreatePerformanceView creates the live performance-counter table. Inputs are
// the tab parent HWND and bounds; processing owns its own PDH sampler and a one
// second timer; output is the child HWND or nullptr on failure.
HWND CreatePerformanceView(HWND parent, const RECT& bounds);

// RefreshPerformanceView takes one sample immediately without disturbing the
// automatic cadence. Input is the view HWND; nothing is returned because the
// result arrives asynchronously.
void RefreshPerformanceView(HWND view);

// ExportPerformanceViewTsv renders the currently visible rows as TSV. Input is
// the view HWND; output is empty when the view is not a performance view.
std::wstring ExportPerformanceViewTsv(HWND view);

} // namespace Ksword::Features::HardwareStats
