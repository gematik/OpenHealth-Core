// Copyright 2025 gematik GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
        oss << "\n[OpenSSL Error] " << message << ": " << ((reason != nullptr) ? reason : "Unknown OpenSSL error");
    }

    if (!has_error)
    {
        oss << ": No OpenSSL error recorded";
    }

    throw std::runtime_error(oss.str());
}

#endif