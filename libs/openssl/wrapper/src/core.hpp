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

#ifndef OH_CORE_HPP
#define OH_CORE_HPP
#include "types.hpp"

namespace core
{

/**
 * Compares two vectors in constant time.
 */
auto crypto_const_time_equals(const uint8_vector &vec_a, const uint8_vector &vec_b) -> bool;

/**
 * Return a random vector of size n.
 */
auto crypto_random(size_t n) -> uint8_vector;
}; // namespace core

#endif
