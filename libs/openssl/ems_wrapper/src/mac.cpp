#include "mac.hpp"

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

    if (EVP_MAC_init(cmac_instance->ctx.get(), key.data(), key.size(), params.data()) != 1)
    {
        throw_openssl_error("EVP_MAC_init failed");
    }

    return cmac_instance;
}

void cmac::update(const uint8_vector &data) const
{
    if (EVP_MAC_update(ctx.get(), data.data(), data.size()) != 1)
    {
        throw_openssl_error("EVP_MAC_update failed");
    }
}

auto cmac::final() const -> uint8_vector
{
    size_t outl = 0;
    if (EVP_MAC_final(ctx.get(), nullptr, &outl, 0) != 1)
    {
        throw_openssl_error("EVP_MAC_final failed to get output length");
    }

    uint8_vector data(outl);
    if (EVP_MAC_final(ctx.get(), data.data(), &outl, outl) != 1)
    {
        throw_openssl_error("EVP_MAC_final failed to finalize");
    }

    return data;
}