#ifndef OH_CAPI_H
#define OH_CAPI_H
#pragma once

#include "errors.hpp"

#include <memory>

#define ossl_unique_ptr(name) std::unique_ptr<name, decltype(&name##_free)>

#ifdef NDEBUG
#define ossl_check(ret_code, message) capi::check(ret_code, message)
#else
#define ossl_check(ret_code, message)                                                                                  \
    capi::check(ret_code, std::string("[") + __FILE__ + ":" + __func__ + ":" + std::to_string(__LINE__) + "] " + message)
#endif

/**
 * Util functions for C++ to C interop.
 */
namespace capi
{
template <typename T, typename Deleter> static auto make_unique(T *ptr, Deleter deleter)
{
    return std::unique_ptr<T, Deleter>(ptr, deleter);
}

// TODO add debugging output as macro
template <typename T, typename Deleter>
static auto make_unique_checked(T *ptr, Deleter deleter, const std::string &message)
{
    auto value = make_unique(ptr, deleter);
    if (!value)
    {
        throw_openssl_error(message);
    }
    return value;
}

template <const auto RequiredCode = 1> auto check(const int ret_code, const std::string &message)
{
    if (ret_code != RequiredCode)
    {
        throw_openssl_error(message);
    }
}
} // namespace capi

#endif