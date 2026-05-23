#ifndef CHARCONV_COMPAT_H
#define CHARCONV_COMPAT_H

#include <charconv>

// Older gcc and clang may have no floating point from_chars
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 10
#define WANT_CHARS_FORMAT
#endif
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 11
#define WANT_FROM_CHARS
#endif
// On Apple Clang, std::from_chars for double may be declared but
// unavailable for the deployment target, causing ambiguity.
// Use fast_float wrapper via a distinct namespace to avoid conflicts.
#if defined(__clang__)
#define WANT_FROM_CHARS_COMPAT
#endif

#if defined(WANT_CHARS_FORMAT) || defined(WANT_FROM_CHARS) || defined(WANT_FROM_CHARS_COMPAT)
#include <fast_float.h>
#endif

#ifdef WANT_CHARS_FORMAT

namespace std
{
    using chars_format = fast_float::chars_format;
}

#endif // WANT_CHARS_FORMAT

#ifdef WANT_FROM_CHARS

namespace std
{
    // NOTE: Don't provide an alias using default
    // parameter since it may create mysterious
    // issues on clang
    inline from_chars_result from_chars(const char* first, const char* last,
        double& value, chars_format fmt) noexcept
    {
        auto ret = fast_float::from_chars(first, last, value, (fast_float::chars_format)fmt);
        return { ret.ptr, ret.ec };
    }
}

#endif // WANT_FROM_CHARS

#ifdef WANT_FROM_CHARS_COMPAT

namespace podofo_compat
{
    inline std::from_chars_result from_chars(const char* first, const char* last,
        double& value, std::chars_format fmt) noexcept
    {
        auto ret = fast_float::from_chars(first, last, value, (fast_float::chars_format)fmt);
        return { ret.ptr, ret.ec };
    }
}

// Override std::from_chars for double with the compat version
#define PODOFO_FROM_CHARS_DOUBLE(first, last, value, fmt) \
    podofo_compat::from_chars(first, last, value, fmt)

#else

#define PODOFO_FROM_CHARS_DOUBLE(first, last, value, fmt) \
    std::from_chars(first, last, value, fmt)

#endif // WANT_FROM_CHARS_COMPAT

#endif // CHARCONV_COMPAT_H
