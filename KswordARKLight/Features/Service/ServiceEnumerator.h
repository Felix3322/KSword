#pragma once

#include "ServiceModel.h"

namespace Ksword::Features::Service {

// EnumerateServices reads every Win32 service and driver service from the SCM.
// There is no input; processing runs entirely on the calling thread and is safe
// to call from a worker; output is one snapshot plus a diagnostic string.
//
// Enumeration goes through ks::service::EnumerateServiceRecords, the same
// reusable layer the Qt build uses, rather than a second SCM reader written for
// this product: the pager, the config enrichment and the per-service error
// handling are subtle enough that two implementations would disagree in exactly
// the cases an audit cares about.
ServiceEnumerationResult EnumerateServices();

// QuerySingleService refreshes one row after an action completes. Input is the
// SCM short name; output carries success=false with a diagnostic when the
// service has since been deleted or became unreadable.
ServiceEnumerationResult QuerySingleService(const std::wstring& serviceName);

} // namespace Ksword::Features::Service
