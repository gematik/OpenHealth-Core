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

#ifndef OH_CIPHER_H
#define OH_CIPHER_H
#pragma once

#include "types.hpp"

#include <functional>
#include <memory>
#include <openssl/evp.h>
#include <openssl/types.h>

namespace cipher
{
class aes_cipher
{
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx;
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher;

    explicit aes_cipher(const std::string &algorithm);

    [[nodiscard]] auto is_encrypting() const -> bool;

    static auto init_cipher(const std::string &algorithm, const uint8_vector &key, const uint8_vector &iv,
                            const std::function<int(EVP_CIPHER_CTX *, const EVP_CIPHER *, const unsigned char *,
                                                    const unsigned char *, const OSSL_PARAM *)> &init_fn)
        -> std::unique_ptr<aes_cipher>;

  public:
    aes_cipher() = delete;

    static auto create_encryptor(const std::string &algorithm, const uint8_vector &key, const uint8_vector &iv)
        -> std::unique_ptr<aes_cipher>;

    static auto create_decryptor(const std::string &algorithm, const uint8_vector &key, const uint8_vector &iv)
        -> std::unique_ptr<aes_cipher>;

    void set_auto_padding(bool enabled) const;

    void set_aad(const uint8_vector &aad) const;

    void set_auth_tag(const uint8_vector &auth_tag) const;

    [[nodiscard]] auto get_auth_tag(size_t tag_len) const -> uint8_vector;

    [[nodiscard]] auto update(const uint8_vector &plaintext) const -> uint8_vector;

    [[nodiscard]] auto final() const -> uint8_vector;
};
} // namespace cipher

#endif