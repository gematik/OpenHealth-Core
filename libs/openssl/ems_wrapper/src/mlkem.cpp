#include "mlkem.hpp"

#include "capi.hpp"
#include "ec.hpp"

#include <openssl/evp.h>
#include <span>

kem::mlkem_encapsulation::mlkem_encapsulation(evp_pkey_ptr &&pkey) : pkey(std::move(pkey))
{
}

auto kem::mlkem_encapsulation::create(const std::string &algorithm, const uint8_vector &encapsulation_key)
    -> std::unique_ptr<mlkem_encapsulation>
{
    // TODO: check correct key type
    auto pkey =
        capi::make_unique_checked(EVP_PKEY_new_raw_public_key_ex(nullptr, algorithm.c_str(), nullptr,
                                                                 encapsulation_key.data(), encapsulation_key.size()),
                                  &EVP_PKEY_free, "Key initialization from encapsulation key failed");

    return std::unique_ptr<mlkem_encapsulation>(new mlkem_encapsulation(std::move(pkey)));
}

auto kem::mlkem_encapsulation::encapsulate() const -> mlkem_encapsulation_data
{
    const auto ctx = capi::make_unique_checked(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr),
                                               &EVP_PKEY_CTX_free, "Failed to create context from key.");
    ossl_check(EVP_PKEY_encapsulate_init(ctx.get(), nullptr), "Failed to initialize key encapsulation");

    size_t wkeylen = 0;
    size_t gkeylen = 0;
    ossl_check(EVP_PKEY_encapsulate(ctx.get(), nullptr, &wkeylen, nullptr, &gkeylen), "Failed to encapsulate key");

    auto data = mlkem_encapsulation_data{.wrapped_key = uint8_vector(wkeylen), .shared_secret = uint8_vector(gkeylen)};
    ossl_check(EVP_PKEY_encapsulate(ctx.get(), data.wrapped_key.data(), &wkeylen, data.shared_secret.data(), &gkeylen),
               "Failed to encapsulate key");

    return data;
}

kem::mlkem_decapsulation::mlkem_decapsulation(evp_pkey_ptr &&pkey) : pkey(std::move(pkey))
{
}

auto kem::mlkem_decapsulation::create(const std::string &algorithm) -> std::unique_ptr<mlkem_decapsulation>
{
    // TODO: check correct key type
    const auto ctx =
        capi::make_unique(EVP_PKEY_CTX_new_from_name(nullptr, algorithm.c_str(), nullptr), &EVP_PKEY_CTX_free);
    ossl_check(!ctx || EVP_PKEY_keygen_init(ctx.get()), "Failed to initialize key.");

    EVP_PKEY *raw_pkey = nullptr;
    EVP_PKEY_keygen(ctx.get(), &raw_pkey);
    auto pkey = capi::make_unique_checked(raw_pkey, &EVP_PKEY_free, "Key generation failed");

    return std::unique_ptr<mlkem_decapsulation>(new mlkem_decapsulation(std::move(pkey)));
}

auto kem::mlkem_decapsulation::create_from_private_key(const std::string &algorithm, const uint8_vector &private_key)
    -> std::unique_ptr<mlkem_decapsulation>
{
    // TODO: check correct key type
    auto pkey = capi::make_unique_checked(
        EVP_PKEY_new_raw_private_key_ex(nullptr, algorithm.c_str(), nullptr, private_key.data(), private_key.size()),
        &EVP_PKEY_free, "Key initialization from encapsulation key failed");

    return std::unique_ptr<mlkem_decapsulation>(new mlkem_decapsulation(std::move(pkey)));
}

auto kem::mlkem_decapsulation::decapsulate(const uint8_vector &wrapped_key) const -> uint8_vector
{
    const auto ctx = capi::make_unique_checked(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr),
                                               &EVP_PKEY_CTX_free, "Failed to create context from key.");
    EVP_PKEY_decapsulate_init(ctx.get(), nullptr);

    size_t keylen = 0;
    ossl_check(EVP_PKEY_decapsulate(ctx.get(), nullptr, &keylen, wrapped_key.data(), wrapped_key.size()),
               "Failed to decapsulate key");

    auto key = uint8_vector(keylen);
    ossl_check(EVP_PKEY_decapsulate(ctx.get(), key.data(), &keylen, wrapped_key.data(), wrapped_key.size()),
               "Failed to decapsulate key");

    return key;
}

auto kem::mlkem_decapsulation::get_encapsulation_key() const -> uint8_vector
{
    unsigned char *encoded_key = nullptr;
    const auto key_len = EVP_PKEY_get1_encoded_public_key(pkey.get(), &encoded_key);
    auto key_span = std::span(encoded_key, key_len);
    return {key_span.begin(), key_span.end()};
}

auto kem::mlkem_decapsulation::get_private_key() const -> uint8_vector
{
}
