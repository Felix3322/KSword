#pragma once

#include "ModuleDescriptor.h"
#include "../Core/Win32Lean.h"

namespace Ksword::Ui {

// PlaceholderPage creates a blank child page for modules that fail to initialize.
// Inputs are parent, descriptor and rectangle; processing creates a child window;
// output is the page HWND.
HWND CreatePlaceholderPage(HWND parent, const ModuleDescriptor& descriptor, const RECT& bounds);

// UpdatePlaceholderPage rewrites the blank page title. Inputs are page HWND and
// descriptor; processing updates window text; no value is returned.
void UpdatePlaceholderPage(HWND page, const ModuleDescriptor& descriptor);

// SetPlaceholderPageLoading updates the visible state before a lazy dock page
// is materialized. The update is deliberately paint-only and never invokes the
// module factory, so a tab switch can provide immediate feedback. The progress
// bar is cleared, which is what the failure paths want: a page that will not
// finish loading must not leave a bar frozen part-way, since that reads as a
// hang rather than as an error.
void SetPlaceholderPageLoading(HWND page, bool loading, const std::wstring& status = L"");

// SetPlaceholderPageProgress reports one stage of the lazy materialization.
// Inputs are the placeholder HWND, the stage caption and a 0..100 percentage
// which is clamped; processing repaints synchronously and returns no value.
//
// The synchronous repaint is the whole point. Building a heavy module page owns
// the UI thread outright, and no queued WM_PAINT is served until it returns --
// by which time the placeholder has already been swapped out, so the user would
// have seen nothing at all. UpdateWindow dispatches WM_PAINT directly instead of
// posting it, which paints now without pumping the queue, so no message can
// re-enter materialization while a page is half-built.
void SetPlaceholderPageProgress(HWND page, const std::wstring& status, int progressPercent);

} // namespace Ksword::Ui
