#include "ProcessDetailFeature.h"

#include "ProcessDetailPage.h"

namespace Ksword::Features::ProcessDetail {

HWND CreateProcessDetailPage(
    HWND parent,
    DWORD processId,
    ULONGLONG expectedCreationTime100ns,
    const RECT& bounds) {
    return ProcessDetailPage::Create(parent, processId, expectedCreationTime100ns, bounds);
}

} // namespace Ksword::Features::ProcessDetail
