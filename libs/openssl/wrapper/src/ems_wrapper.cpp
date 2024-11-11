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

#include "capi.hpp"
#include "cipher.hpp"
#include "core.hpp"

#include <iostream>

#include <emscripten/bind.h>

#include <span>

#include "ec.hpp"
#include "errors.hpp"
#include "hash.hpp"
#include "mac.hpp"
#include "mlkem.hpp"

constexpr std::string int8_array_type = "Int8Array";
constexpr std::string uint8_array_type = "Uint8Array";

template <typename T, const std::string &ArrayType> auto from_js_array(const emscripten::val &data) -> std::vector<T>
{
    const auto length = data["length"].as<unsigned int>();
    std::vector<T> result(length);

    if (const auto name = data["constructor"]["name"].as<std::string>(); name != ArrayType)
    {
        throw std::invalid_argument("Invalid array type " + name + ". Expected " + ArrayType);
    }

    for (unsigned int i = 0; i < length; ++i)
    {
        result[i] = data[i].as<T>();
    }

    return result;
}

template <typename T, const std::string &ArrayType> auto to_js_array(const std::vector<T> &data) -> emscripten::val
{
    return emscripten::val::global(ArrayType.c_str()).new_(emscripten::typed_memory_view(data.size(), data.data()));
}

// ReSharper disable CppExpressionWithoutSideEffects
EMSCRIPTEN_BINDINGS(OpenSSL)
{
    using namespace emscripten;

    // utility functions for converting vectors
    function("toInt8Array", &to_js_array<char, int8_array_type>);
    function("toUint8Array", &to_js_array<unsigned char, uint8_array_type>);
    function("fromInt8Array", &from_js_array<char, int8_array_type>);
    function("fromUint8Array", &from_js_array<unsigned char, uint8_array_type>);

    register_vector<char>("Int8Vector");
    register_vector<unsigned char>("Uint8Vector");

    // random
    function("cryptoRandom", &core::crypto_random);

    // constant time equals
    function("cryptoConstantTimeEquals", &core::crypto_const_time_equals);

    // cipher and key generation wrappers
    class_<ec::ec_point>("EcPoint")
        .class_function("create", &ec::ec_point::create, return_value_policy::take_ownership())
        .function("add", &ec::ec_point::add, return_value_policy::take_ownership())
        .function("times", &ec::ec_point::times, return_value_policy::take_ownership())
        .function("uncompressed", &ec::ec_point::uncompressed, return_value_policy::take_ownership());

    class_<mac::cmac>("Cmac")
        .class_function("create", &mac::cmac::create, return_value_policy::take_ownership())
        .function("update", &mac::cmac::update)
        .function("final", &mac::cmac::final);

    class_<ec::ec_keypair>("EcKeyPairGenerator")
        .class_function("generateKeyPair", &ec::ec_keypair::generate_keypair, return_value_policy::take_ownership())
        .function("getPublicKeyDer", &ec::ec_keypair::get_public_key_der)
        .function("getPrivateKeyDer", &ec::ec_keypair::get_private_key_der);

    class_<kem::mlkem_encapsulation_data>("MlKemEncapsulationData")
        .property("wrappedKey", &kem::mlkem_encapsulation_data::wrapped_key)
        .property("sharedSecret", &kem::mlkem_encapsulation_data::shared_secret);

    class_<kem::mlkem_encapsulation>("MlKemEncapsulation")
        .class_function("create", &kem::mlkem_encapsulation::create, return_value_policy::take_ownership())
        .function("encapsulate", &kem::mlkem_encapsulation::encapsulate, return_value_policy::take_ownership());

    class_<kem::mlkem_decapsulation>("MlKemDecapsulation")
        .class_function("create", &kem::mlkem_decapsulation::create, return_value_policy::take_ownership())
        .function("decapsulate", &kem::mlkem_decapsulation::decapsulate)
        .function("getEncapsulationKey", &kem::mlkem_decapsulation::get_encapsulation_key);

    class_<ec::ecdh>("Ecdh")
        .class_function("create", &ec::ecdh::create, return_value_policy::take_ownership())
        .function("computeSecret", &ec::ecdh::compute_secret);

    class_<hash::hash_generator>("HashGenerator")
        .class_function("create", &hash::hash_generator::create)
        .function("update", &hash::hash_generator::update)
        .function("setFinalOutputLength", &hash::hash_generator::set_final_output_length)
        .function("final", &hash::hash_generator::final);

    class_<cipher::aes_cipher>("AesCipher")
        .class_function("createEncryptor", &cipher::aes_cipher::create_encryptor, return_value_policy::take_ownership())
        .class_function("createDecryptor", &cipher::aes_cipher::create_decryptor, return_value_policy::take_ownership())
        .function("setAutoPadding", &cipher::aes_cipher::set_auto_padding)
        .function("setAad", &cipher::aes_cipher::set_aad)
        .function("setAuthTag", &cipher::aes_cipher::set_auth_tag)
        .function("getAuthTag", &cipher::aes_cipher::get_auth_tag)
        .function("update", &cipher::aes_cipher::update)
        .function("final", &cipher::aes_cipher::final);
}
// ReSharper restore CppExpressionWithoutSideEffects
