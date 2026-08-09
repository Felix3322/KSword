#pragma once

#include <cstdint>
#include <string>

namespace Ksword::Ui {

// NumericSortKey is the ordering value recovered from one visible table cell.
// Report ListViews sort by the text the user sees, so numeric columns degrade
// into lexicographic order: PIDs come out 1/10/100/11/2, an unpadded "0x2"
// sorts after "0x1FF", and "512 KiB" sorts after "4.0 MiB". Parsing the leading
// number back out of the display text restores true numeric order while leaving
// every existing formatting path untouched.
struct NumericSortKey {
    bool valid = false;           // False when the cell does not start with a number.
    bool negative = false;        // Sign is kept apart so the magnitude stays unsigned.
    std::uint64_t magnitude = 0;  // Integral part; byte counts for sized cells.
    double fraction = 0.0;        // [0,1) tail, used only for unitless decimals.
};

// ParseNumericSortKey extracts the leading number from one cell. Input is the
// display text; processing accepts "0x"-prefixed hexadecimal, plain decimals,
// and decimals followed by a byte unit (B/KB/KiB/MB/MiB/GB/GiB/TB/TiB) which are
// converted to bytes; output is a key whose valid flag is false when the cell
// carries no leading number. Trailing commentary such as the "(Access denied)"
// in "0xC0000022 (Access denied)" is ignored on purpose so status columns still
// sort by their code.
NumericSortKey ParseNumericSortKey(const std::wstring& cellText);

// CompareNumericSortKeys orders two parsed keys. Inputs are two keys; output
// follows the C comparison convention (negative, zero, positive). Numeric cells
// always sort ahead of non-numeric ones so a mixed column keeps its numbers
// grouped instead of interleaving them with "N/A" style placeholders.
int CompareNumericSortKeys(const NumericSortKey& left, const NumericSortKey& right);

// CompareCellsNumericAware is the drop-in replacement for a raw string compare
// inside a column sort. Inputs are two cell texts; processing compares
// numerically when both cells carry a leading number and falls back to a
// case-insensitive string compare otherwise, and also as the tie-break for
// numerically equal cells; output follows the C comparison convention.
int CompareCellsNumericAware(const std::wstring& left, const std::wstring& right);

} // namespace Ksword::Ui
