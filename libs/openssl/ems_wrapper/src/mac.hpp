#ifndef OH_MAC_H
#define OH_MAC_H
#pragma once

#include "types.hpp"

#include <memory>
#include <openssl/evp.h>
#include <openssl/types.h>

namespace mac
{
class cmac {
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac;
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx;

    cmac();

public:
    static auto create(const uint8_vector &key, const std::string &algorithm) -> std::unique_ptr<cmac>;

    void update(const uint8_vector &data) const;

    [[nodiscard]] auto final() const -> uint8_vector;
};
}

#endif