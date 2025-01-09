#ifndef OH_HASH_H
#define OH_HASH_H
#pragma once

#include "types.hpp"

#include <memory>
#include <openssl/evp.h>
#include <openssl/types.h>

namespace hash
{
class hash_generator
{
    const EVP_MD *md;
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx;

    explicit hash_generator(const std::string &hash_name);

  public:
    hash_generator() = delete;

    static auto create(const std::string &hash_name) -> std::unique_ptr<hash_generator>;

    void update(const uint8_vector &data) const;

    [[nodiscard]] auto final() const -> uint8_vector;
};
} // namespace hash
#endif