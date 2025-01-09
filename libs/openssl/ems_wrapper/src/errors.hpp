#ifndef OH_ERRORS_H
#define OH_ERRORS_H
#pragma once

#include <openssl/err.h>
#include <sstream>
#include <stdexcept>
#include <string>

[[noreturn]] static void throw_openssl_error(const std::string &message)
{
    std::ostringstream oss;
    oss << message;

    bool has_error = false;
    while (const auto err_code = ERR_get_error())
    {
        has_error = true;
        const auto *reason = ERR_error_string(err_code, nullptr);
        oss << "\n[OpenSSL Error] " << message <<  ": " <<  ((reason != nullptr) ? reason : "Unknown OpenSSL error");
    }

    if (!has_error)
    {
        oss << ": No OpenSSL error recorded";
    }

    throw std::runtime_error(oss.str());
}

#endif