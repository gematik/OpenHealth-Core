#include "hash.hpp"

#include "capi.hpp"
#include "errors.hpp"

using namespace hash;

hash_generator::hash_generator(const std::string &hash_name)
    : md(EVP_MD_fetch(nullptr, hash_name.c_str(), nullptr)), ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free)
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
    ossl_check(EVP_DigestInit_ex(hash->ctx.get(), hash->md, nullptr), "Failed to initialize digest");
    return hash;
}

void hash_generator::update(const uint8_vector &data) const
{
    ossl_check(EVP_DigestUpdate(ctx.get(), data.data(), data.size()), "Failed to update digest");
}

void hash_generator::set_final_output_length(const size_t length)
{
    if (EVP_MD_flags(md) & EVP_MD_FLAG_XOF)
    {
        if (length <= 0)
        {
            throw std::invalid_argument("Output length must be specified for XOF hashes");
        }
        output_length = length;
    }
    else
    {
        if (length != 0 && length != EVP_MD_size(md))
        {
            throw std::invalid_argument("Fixed-length hash does not support variable output size");
        }
    }
}

[[nodiscard]] auto hash_generator::final() const -> uint8_vector
{
    uint8_vector result;
    if (EVP_MD_flags(md) & EVP_MD_FLAG_XOF)
    {
        result.resize(output_length);
        ossl_check(EVP_DigestFinalXOF(ctx.get(), result.data(), output_length), "Failed to finalize XOF digest");
        return result;
    }
    unsigned int length = EVP_MD_size(md);
    result.resize(length);
    ossl_check(EVP_DigestFinal_ex(ctx.get(), result.data(), &length), "Failed to finalize digest");
    return result;
}