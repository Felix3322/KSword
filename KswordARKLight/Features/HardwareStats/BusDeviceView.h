#pragma once

#include "../../Core/Win32Lean.h"

#include <string>

namespace Ksword::Features::HardwareStats {

// CreateBusDeviceView creates the system bus table. Inputs are the tab parent
// HWND and bounds; processing enumerates devnodes and their arbitrated
// resources on a worker thread; output is the child HWND or nullptr on failure.
HWND CreateBusDeviceView(HWND parent, const RECT& bounds);

// RefreshBusDeviceView starts a new background enumeration. Input is the view
// HWND; nothing is returned because the result arrives asynchronously.
void RefreshBusDeviceView(HWND view);

// ExportBusDeviceViewTsv renders the currently visible rows as TSV. Input is the
// view HWND; output is empty when the view is not a bus device view.
std::wstring ExportBusDeviceViewTsv(HWND view);

} // namespace Ksword::Features::HardwareStats
