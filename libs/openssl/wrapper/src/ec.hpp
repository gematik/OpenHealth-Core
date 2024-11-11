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

#ifndef OH_EC_H
#define OH_EC_H
#pragma once

#include "capi.hpp"

#include "types.hpp"

#include <openssl/ec.h>
#include <openssl/evp.h>

namespace ec
{
using evp_pkey_ptr = ossl_unique_ptr(EVP_PKEY);
using evp_pkey_ctx_ptr = ossl_unique_ptr(EVP_PKEY_CTX);

auto convert_private_key_to_der(const evp_pkey_ptr &private_key) -> uint8_vector;
auto convert_public_key_to_der(const evp_pkey_ptr &public_key) -> uint8_vector;

auto convert_private_key_from_der(const uint8_vector &private_key) -> evp_pkey_ptr;
auto convert_public_key_from_der(const uint8_vector &public_key) -> evp_pkey_ptr;

class ec_point
{
    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point;
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group;

    explicit ec_point(std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> &&point,
                      std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> &&group);

    static auto create_from_curve(const std::string &curve_name) -> std::unique_ptr<ec_point>;

  public:
    ec_point() = delete;

    static auto create(const std::string &curve_name, const uint8_vector &public_key) -> std::unique_ptr<ec_point>;

    [[nodiscard]] auto clone() const -> std::unique_ptr<ec_point>;

    [[nodiscard]] auto add(const ec_point &other) const -> std::unique_ptr<ec_point>;

    [[nodiscard]] auto times(const uint8_vector &signed_integer) const -> std::unique_ptr<ec_point>;

    [[nodiscard]] auto uncompressed() const -> uint8_vector;
};

class ec_keypair
{
    evp_pkey_ptr pkey;

    explicit ec_keypair(evp_pkey_ptr &&pkey);

  public:
    ec_keypair() = delete;

    [[nodiscard]] auto get_private_key_der() const -> uint8_vector;

    [[nodiscard]] auto get_public_key_der() const -> uint8_vector;

    static auto generate_keypair(const std::string &curve_name) -> std::unique_ptr<ec_keypair>;
};

class ecdh
{
    evp_pkey_ctx_ptr ctx;
    evp_pkey_ptr pkey;

    explicit ecdh(evp_pkey_ctx_ptr &&ctx, evp_pkey_ptr &&pkey);

  public:
    ecdh() = delete;

    static auto create(const uint8_vector &private_key_der) -> std::unique_ptr<ecdh>;

    [[nodiscard]] auto compute_secret(const uint8_vector &public_key_der) const -> uint8_vector;
};
} // namespace ec

#endif