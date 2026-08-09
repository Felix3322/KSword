#include "PrivilegeFeature.h"

#include "PrivilegeView.h"

namespace Ksword::Features::Privilege {

HWND CreatePrivilegeFeaturePage(HWND parent, const RECT& bounds) {
    return CreatePrivilegeView(parent, bounds);
}

} // namespace Ksword::Features::Privilege
