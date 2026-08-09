#include "ServiceFeature.h"

#include "ServiceView.h"

namespace Ksword::Features::Service {

HWND CreateServiceFeaturePage(HWND parent, const RECT& bounds) {
    return CreateServiceView(parent, bounds);
}

} // namespace Ksword::Features::Service
