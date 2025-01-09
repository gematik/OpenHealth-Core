#include "hash.hpp"

#include "errors.hpp"

using namespace hash;

hash_generator::hash_generator(const std::string &hash_name)
    : md(EVP_get_digestbyname(hash_name.c_str())), ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free)
{
    if (md == nullptr)
    {
        throw_openssl_error("Invalid hash algorithm: " + hash_name);
    }
    if (!ctx)
    {
        throw_openssl_error("Failed to create EVP_MD_CTX");
    }
}

auto hash_generator::create(const std::string &hash_name) -> std::unique_ptr<hash_generator>
{
    std::unique_ptr<hash_generator> hash(new hash_generator(hash_name));
    if (EVP_DigestInit_ex(hash->ctx.get(), hash->md, nullptr) != 1)
    {
        throw_openssl_error("Failed to initialize digest");
    }
    return hash;
}

void hash_generator::update(const uint8_vector &data) const
{
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
    {
        throw_openssl_error("Failed to update digest");
    }
}

[[nodiscard]] auto hash_generator::final() const -> uint8_vector
{
    uint8_vector hash(EVP_MAX_MD_SIZE);
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &length) != 1)
    {
        throw_openssl_error("Failed to finalize digest");
    }
    hash.resize(length);
    return hash;
}