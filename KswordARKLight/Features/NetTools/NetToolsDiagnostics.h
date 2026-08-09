#pragma once

#include "NetToolsModel.h"

#include <cstdint>
#include <string>

namespace Ksword::Features::NetTools {

// DiagnosticKind selects which probe the diagnostics tab runs. The three share
// one request/result pair because they all produce the same thing from the
// user's point of view: a block of text about one target.
enum class DiagnosticKind {
    Ping,
    TraceRoute,
    DnsLookup
};

// DiagnosticRequest is one probe description. The bounds are part of the request
// rather than constants inside the worker because every one of them multiplies
// into wall-clock time: a 30-hop trace at a 3-second timeout is a minute and a
// half of a thread doing nothing but waiting.
struct DiagnosticRequest {
    DiagnosticKind kind = DiagnosticKind::Ping;
    std::wstring target;
    std::uint16_t dnsRecordType = 0;      // DNS_TYPE_*, only read for DnsLookup.
    std::uint32_t echoCount = 4;          // Ping only.
    std::uint32_t maxHops = 30;           // TraceRoute only.
    std::uint32_t timeoutMs = 2000;       // Per probe.
};

// DiagnosticResult carries one completed probe. The text is already broken into
// CRLF lines for a multi-line EDIT, and the summary is the single line the page
// footer shows.
struct DiagnosticResult {
    bool success = false;
    std::wstring text;
    std::wstring summary;
};

// RunDiagnostic executes one probe to completion. Input is the request;
// processing blocks for up to (probe count x timeout) and therefore only ever
// runs on a worker thread; output is the formatted report.
//
// Ping and traceroute are IPv4-only here: IcmpSendEcho2 needs a bound source
// address for IPv6 and picking one silently would report a path the caller never
// asked about. A target that resolves only to IPv6 is reported as such instead.
DiagnosticResult RunDiagnostic(const DiagnosticRequest& request);

// DnsRecordTypeChoiceCount / DnsRecordTypeChoiceLabel / DnsRecordTypeChoiceValue
// expose the record types the tab offers, indexed by combo position. They live
// here so the view never has to include windns.h just to fill a drop-down, and
// so the labels and the DNS_TYPE_* values can never drift apart.
int DnsRecordTypeChoiceCount();
const wchar_t* DnsRecordTypeChoiceLabel(int index);
std::uint16_t DnsRecordTypeChoiceValue(int index);

} // namespace Ksword::Features::NetTools
