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

#include "mac.hpp"

#include "capi.hpp"
#include "errors.hpp"

using namespace mac;

cmac::cmac()
    : mac(EVP_MAC_fetch(nullptr, "CMAC", nullptr), &EVP_MAC_free), ctx(EVP_MAC_CTX_new(mac.get()), &EVP_MAC_CTX_free)
{
    if (!mac)
    {
        throw std::runtime_error("EVP_MAC_fetch failed");
    }
    if (!ctx)
    {
        throw std::runtime_error("EVP_MAC_CTX_new failed");
    }
}

auto cmac::create(const uint8_vector &key, const std::string &algorithm) -> std::unique_ptr<cmac>
{
    auto cmac_instance = std::unique_ptr<cmac>(new cmac());

    const auto params =
        std::array{OSSL_PARAM_construct_utf8_string("cipher",
                                                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
                                                    const_cast<char *>(algorithm.c_str()), 0),
                   OSSL_PARAM_construct_end()};

    ossl_check(EVP_MAC_init(cmac_instance->ctx.get(), key.data(), key.size(), params.data()), "EVP_MAC_init failed");

    return cmac_instance;
}

void cmac::update(const uint8_vector &data) const
{
    ossl_check(EVP_MAC_update(ctx.get(), data.data(), data.size()), "EVP_MAC_update failed");
}

auto cmac::final() const -> uint8_vector
{
    size_t outl = 0;
    ossl_check(EVP_MAC_final(ctx.get(), nullptr, &outl, 0), "EVP_MAC_final failed to get output length");

    uint8_vector data(outl);
    ossl_check(EVP_MAC_final(ctx.get(), data.data(), &outl, outl), "EVP_MAC_final failed to finalize");

    return data;
}