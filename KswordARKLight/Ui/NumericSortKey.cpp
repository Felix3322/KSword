#include "NumericSortKey.h"

#include <cstring>
#include <cwchar>
#include <cwctype>
#include <limits>

namespace Ksword::Ui {
namespace {

constexpr std::uint64_t kUnsignedMax = (std::numeric_limits<std::uint64_t>::max)();

// HexDigitValue converts one wide character to its hexadecimal value. Input is a
// candidate digit; output is 0..15, or -1 when the character ends the number.
int HexDigitValue(const wchar_t character) {
    if (character >= L'0' && character <= L'9') {
        return static_cast<int>(character - L'0');
    }
    if (character >= L'a' && character <= L'f') {
        return static_cast<int>(character - L'a') + 10;
    }
    if (character >= L'A' && character <= L'F') {
        return static_cast<int>(character - L'A') + 10;
    }
    return -1;
}

// UnitMultiplier maps one trailing unit word to its byte multiplier. Both the
// short spelling ("KB") and the IEC spelling ("KiB") are accepted: this project
// prints sizes with the IEC form, while text lifted straight out of driver
// payloads and Windows APIs often uses the short one. Unknown words fall back to
// 1 so an ordinary sentence after a number is never mistaken for a unit.
std::uint64_t UnitMultiplier(const std::wstring& unitWord) {
    constexpr std::uint64_t kKiB = 1024ULL;
    constexpr std::uint64_t kMiB = kKiB * 1024ULL;
    constexpr std::uint64_t kGiB = kMiB * 1024ULL;
    constexpr std::uint64_t kTiB = kGiB * 1024ULL;
    constexpr std::uint64_t kPiB = kTiB * 1024ULL;

    struct UnitEntry {
        const wchar_t* name;
        std::uint64_t multiplier;
    };
    static constexpr UnitEntry kUnits[] = {
        { L"B", 1ULL },
        { L"KB", kKiB }, { L"KIB", kKiB }, { L"K", kKiB },
        { L"MB", kMiB }, { L"MIB", kMiB }, { L"M", kMiB },
        { L"GB", kGiB }, { L"GIB", kGiB }, { L"G", kGiB },
        { L"TB", kTiB }, { L"TIB", kTiB }, { L"T", kTiB },
        { L"PB", kPiB }, { L"PIB", kPiB },
    };
    for (const UnitEntry& entry : kUnits) {
        if (::_wcsicmp(unitWord.c_str(), entry.name) == 0) {
            return entry.multiplier;
        }
    }
    return 1ULL;
}

// ParseHexMagnitude reads the digits after a "0x" prefix. Inputs are the cell
// text and the index of the first digit; processing saturates instead of
// wrapping so a malformed oversized literal still sorts last; output is false
// when no hexadecimal digit follows the prefix.
bool ParseHexMagnitude(const std::wstring& cellText, const std::size_t digitStart, std::uint64_t& magnitudeOut) {
    std::size_t cursor = digitStart;
    std::uint64_t value = 0;
    bool overflow = false;
    while (cursor < cellText.size()) {
        const int digit = HexDigitValue(cellText[cursor]);
        if (digit < 0) {
            break;
        }
        if (!overflow) {
            if (value > (kUnsignedMax - static_cast<std::uint64_t>(digit)) / 16ULL) {
                overflow = true;
            } else {
                value = value * 16ULL + static_cast<std::uint64_t>(digit);
            }
        }
        ++cursor;
    }
    if (cursor == digitStart) {
        return false;
    }
    magnitudeOut = overflow ? kUnsignedMax : value;
    return true;
}

} // namespace

NumericSortKey ParseNumericSortKey(const std::wstring& cellText) {
    NumericSortKey key{};

    std::size_t index = 0;
    while (index < cellText.size() && std::iswspace(cellText[index]) != 0) {
        ++index;
    }
    if (index < cellText.size() && (cellText[index] == L'-' || cellText[index] == L'+')) {
        key.negative = (cellText[index] == L'-');
        ++index;
    }
    if (index >= cellText.size()) {
        return key;
    }

    // Hexadecimal is only recognized behind an explicit "0x": a bare run of hex
    // characters cannot be told apart from an ordinary word such as "Added", and
    // silently reading one as a number would scramble text columns.
    if (cellText[index] == L'0' && index + 1 < cellText.size() &&
        (cellText[index + 1] == L'x' || cellText[index + 1] == L'X')) {
        std::uint64_t magnitude = 0;
        if (!ParseHexMagnitude(cellText, index + 2, magnitude)) {
            return key;
        }
        key.valid = true;
        key.magnitude = magnitude;
        return key;
    }

    const std::size_t wholeStart = index;
    std::uint64_t whole = 0;
    bool overflow = false;
    while (index < cellText.size() && cellText[index] >= L'0' && cellText[index] <= L'9') {
        const std::uint64_t digit = static_cast<std::uint64_t>(cellText[index] - L'0');
        if (!overflow) {
            if (whole > (kUnsignedMax - digit) / 10ULL) {
                overflow = true;
            } else {
                whole = whole * 10ULL + digit;
            }
        }
        ++index;
    }
    if (index == wholeStart) {
        return key;
    }

    double fraction = 0.0;
    if (index < cellText.size() && cellText[index] == L'.') {
        std::size_t cursor = index + 1;
        double scale = 0.1;
        while (cursor < cellText.size() && cellText[cursor] >= L'0' && cellText[cursor] <= L'9') {
            fraction += static_cast<double>(cellText[cursor] - L'0') * scale;
            scale *= 0.1;
            ++cursor;
        }
        // The dot is only consumed when digits follow it, so a sentence ending
        // in "42." keeps its period out of the number.
        if (cursor > index + 1) {
            index = cursor;
        } else {
            fraction = 0.0;
        }
    }

    std::size_t unitCursor = index;
    while (unitCursor < cellText.size() && std::iswspace(cellText[unitCursor]) != 0) {
        ++unitCursor;
    }
    const std::size_t unitStart = unitCursor;
    while (unitCursor < cellText.size() && std::iswalpha(cellText[unitCursor]) != 0) {
        ++unitCursor;
    }
    const std::uint64_t multiplier = unitCursor > unitStart
        ? UnitMultiplier(cellText.substr(unitStart, unitCursor - unitStart))
        : 1ULL;

    key.valid = true;
    if (multiplier > 1ULL) {
        // Sized cells collapse to a byte count so "4.5 MiB" and "4608 KiB"
        // compare equal instead of ordering by their printed digits. The
        // intermediate is long double because the multiply can exceed the range
        // an integer expression would keep exactly.
        const long double bytes =
            (static_cast<long double>(whole) + static_cast<long double>(fraction)) *
            static_cast<long double>(multiplier);
        key.magnitude = bytes >= static_cast<long double>(kUnsignedMax)
            ? kUnsignedMax
            : static_cast<std::uint64_t>(bytes);
        key.fraction = 0.0;
    } else {
        key.magnitude = overflow ? kUnsignedMax : whole;
        key.fraction = fraction;
    }
    return key;
}

int CompareNumericSortKeys(const NumericSortKey& left, const NumericSortKey& right) {
    if (!left.valid || !right.valid) {
        if (left.valid == right.valid) {
            return 0;
        }
        return left.valid ? -1 : 1;
    }
    if (left.negative != right.negative) {
        return left.negative ? -1 : 1;
    }
    // Below zero the ordering flips: the larger magnitude is the smaller number.
    const int sign = left.negative ? -1 : 1;
    if (left.magnitude != right.magnitude) {
        return left.magnitude < right.magnitude ? -sign : sign;
    }
    if (left.fraction != right.fraction) {
        return left.fraction < right.fraction ? -sign : sign;
    }
    return 0;
}

int CompareCellsNumericAware(const std::wstring& left, const std::wstring& right) {
    const int numericOrder = CompareNumericSortKeys(ParseNumericSortKey(left), ParseNumericSortKey(right));
    if (numericOrder != 0) {
        return numericOrder;
    }
    // Equal numbers and two non-numeric cells both land here, so a column that
    // mixes "0x10 (busy)" with "0x10 (idle)" still has a deterministic order.
    return ::_wcsicmp(left.c_str(), right.c_str());
}

} // namespace Ksword::Ui
