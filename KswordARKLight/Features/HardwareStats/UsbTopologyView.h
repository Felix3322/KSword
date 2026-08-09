#pragma once

#include "../../Core/Win32Lean.h"

#include <string>

namespace Ksword::Features::HardwareStats {

// CreateUsbTopologyView creates the USB device tree table. Inputs are the tab
// parent HWND and bounds; processing enumerates on a worker thread; output is
// the child HWND or nullptr on failure.
HWND CreateUsbTopologyView(HWND parent, const RECT& bounds);

// RefreshUsbTopologyView starts a new background enumeration. Input is the view
// HWND; nothing is returned because the result arrives asynchronously.
void RefreshUsbTopologyView(HWND view);

// ExportUsbTopologyViewTsv renders the currently visible rows as TSV. Input is
// the view HWND; output is empty when the view is not a USB topology view.
std::wstring ExportUsbTopologyViewTsv(HWND view);

} // namespace Ksword::Features::HardwareStats
