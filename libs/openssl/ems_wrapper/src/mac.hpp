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

#ifndef OH_MAC_H
#define OH_MAC_H
#pragma once

#include "types.hpp"

#include <memory>
#include <openssl/evp.h>
#include <openssl/types.h>

namespace mac
{
class cmac {
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac;
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx;

    cmac();

public:
    static auto create(const uint8_vector &key, const std::string &algorithm) -> std::unique_ptr<cmac>;

    void update(const uint8_vector &data) const;

    [[nodiscard]] auto final() const -> uint8_vector;
};
}

#endif