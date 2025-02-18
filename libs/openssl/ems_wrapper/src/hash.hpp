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

#ifndef OH_HASH_H
#define OH_HASH_H
#pragma once

#include "types.hpp"

#include <memory>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <optional>

namespace hash
{
class hash_generator
{
    const EVP_MD *md;
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx;

    size_t output_length = 0;

    explicit hash_generator(const std::string &hash_name);

  public:
    hash_generator() = delete;

    static auto create(const std::string &hash_name) -> std::unique_ptr<hash_generator>;

    void update(const uint8_vector &data) const;

    void set_final_output_length(size_t length);

    [[nodiscard]] auto final() const -> uint8_vector;
};
} // namespace hash
#endif