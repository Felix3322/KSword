#pragma once

#include "../../Core/Win32Lean.h"

#include <string>

namespace Ksword::Features::HardwareStats {

// CreateDiskActivityView creates the per-physical-disk activity table. Inputs
// are the tab parent HWND and bounds; processing owns its own PDH sampler over
// the PhysicalDisk object and a one second timer; output is the child HWND or
// nullptr on failure.
HWND CreateDiskActivityView(HWND parent, const RECT& bounds);

// ExportDiskActivityViewTsv renders the currently visible rows as TSV. Input is
// the view HWND; output is empty when the view is not a disk activity view.
std::wstring ExportDiskActivityViewTsv(HWND view);

} // namespace Ksword::Features::HardwareStats
