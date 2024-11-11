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

#include "core.hpp"

#include <openssl/crypto.h>
#include <openssl/rand.h>

auto core::crypto_const_time_equals(const uint8_vector &vec_a, const uint8_vector &vec_b) -> bool
{
    if (vec_a.size() != vec_b.size())
    {
        return false;
    }
    return CRYPTO_memcmp(vec_a.data(), vec_b.data(), vec_a.size()) == 0;
}

auto core::crypto_random(const size_t n) -> uint8_vector
{
    auto vector = uint8_vector(n);
    RAND_priv_bytes(vector.data(), static_cast<int>(vector.size()));
    return vector;
}