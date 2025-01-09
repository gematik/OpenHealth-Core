#include "cipher.hpp"

#include "errors.hpp"

#include <openssl/core_names.h>

using namespace cipher;

aes_cipher::aes_cipher(const std::string &algorithm)
    : ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free),
      cipher(EVP_CIPHER_fetch(nullptr, algorithm.c_str(), nullptr), &EVP_CIPHER_free)
{
    if (!ctx)
    {
        throw_openssl_error("Failed to create cipher context");
    }
    if (!cipher)
    {
        throw_openssl_error("Failed to fetch cipher");
    }
}

[[nodiscard]] auto aes_cipher::is_encrypting() const -> bool
{
    return EVP_CIPHER_CTX_is_encrypting(ctx.get()) == 1;
}

auto aes_cipher::init_cipher(const std::string &algorithm, const uint8_vector &key,
                             const uint8_vector &initialization_vector,
                             const std::function<int(EVP_CIPHER_CTX *, const EVP_CIPHER *, const unsigned char *,
                                                     const unsigned char *, const OSSL_PARAM *)> &init_fn)
    -> std::unique_ptr<aes_cipher>
{
    std::unique_ptr<aes_cipher> aes(new aes_cipher(algorithm));
    if (!aes)
    {
        throw_openssl_error("Failed to create AESCipher for algorithm: " + algorithm);
    }

    if (init_fn(aes->ctx.get(), aes->cipher.get(), nullptr, nullptr, nullptr) != 1)
    {
        throw_openssl_error("Failed to initialize cipher");
    }

    if (const int cipher_type = EVP_CIPHER_CTX_get_mode(aes->ctx.get());
        cipher_type == EVP_CIPH_GCM_MODE || cipher_type == EVP_CIPH_CCM_MODE)
    {
        auto iv_length = initialization_vector.size();

        const auto params = std::array{OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &iv_length),
                                       OSSL_PARAM_construct_end()};

        if (EVP_CIPHER_CTX_set_params(aes->ctx.get(), params.data()) != 1)
        {
            throw std::runtime_error("Failed to set IV length");
        }
    }
    else
    {
        if (init_fn(aes->ctx.get(), aes->cipher.get(), key.data(), initialization_vector.data(), nullptr) != 1)
        {
            throw_openssl_error("Failed to initialize cipher");
        }
    }

    if (init_fn(aes->ctx.get(), nullptr, key.data(), initialization_vector.data(), nullptr) != 1)
    {
        throw_openssl_error("Failed to initialize cipher");
    }

    return aes;
}

auto aes_cipher::create_encryptor(const std::string &algorithm, const uint8_vector &key,
                                  const uint8_vector &initialization_vector) -> std::unique_ptr<aes_cipher>
{
    return init_cipher(algorithm, key, initialization_vector, &EVP_EncryptInit_ex2);
}

auto aes_cipher::create_decryptor(const std::string &algorithm, const uint8_vector &key,
                                  const uint8_vector &initialization_vector) -> std::unique_ptr<aes_cipher>
{
    return init_cipher(algorithm, key, initialization_vector, &EVP_DecryptInit_ex2);
}

void aes_cipher::set_auto_padding(bool enabled) const
{
    EVP_CIPHER_CTX_set_padding(ctx.get(), enabled ? 1 : 0);
}

void aes_cipher::set_aad(const uint8_vector &aad) const
{
    int len = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
    {
        throw_openssl_error("Failed to set AAD");
    }
}

void aes_cipher::set_auth_tag(const uint8_vector &auth_tag) const
{
    if (auth_tag.empty())
    {
        throw std::invalid_argument("Authentication tag cannot be empty");
    }

    const auto params =
        std::array{OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                     // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
                                                     const_cast<unsigned char *>(auth_tag.data()), auth_tag.size()),
                   OSSL_PARAM_construct_end()};

    if (EVP_CIPHER_CTX_set_params(ctx.get(), params.data()) != 1)
    {
        throw_openssl_error("Failed to set authentication tag");
    }
}

auto aes_cipher::get_auth_tag(const size_t tag_len) const -> uint8_vector
{
    uint8_vector auth_tag(tag_len);

    auto params = std::array{OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, auth_tag.data(), tag_len),
                             OSSL_PARAM_construct_end()};

    if (EVP_CIPHER_CTX_get_params(ctx.get(), params.data()) != 1)
    {
        throw_openssl_error("Failed to get authentication tag");
    }

    return auth_tag;
}

auto aes_cipher::update(const uint8_vector &plaintext) const -> uint8_vector
{
    int len = 0;
    uint8_vector ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx.get()));
    if (is_encrypting())
    {
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1)
        {
            throw_openssl_error("Encryption failed during update");
        }
    }
    else
    {
        if (EVP_DecryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1)
        {
            throw_openssl_error("Decryption failed during update");
        }
    }
    ciphertext.resize(len);
    return ciphertext;
}

auto aes_cipher::final() const -> uint8_vector
{
    int len = 0;
    uint8_vector ciphertext(EVP_CIPHER_CTX_block_size(ctx.get()));
    if (is_encrypting())
    {
        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data(), &len) != 1)
        {
            throw_openssl_error("Encryption failed during finalization");
        }
    }
    else
    {
        if (EVP_DecryptFinal_ex(ctx.get(), ciphertext.data(), &len) != 1)
        {
            throw_openssl_error("Decryption failed during finalization");
        }
    }
    ciphertext.resize(len);
    return ciphertext;
}
