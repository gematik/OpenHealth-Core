#include "ec.hpp"

#include <span>
#include <vector>

#include "errors.hpp"

#include <openssl/pem.h>

auto bio_to_uint8(BIO *bio) -> uint8_vector
{
    char *data = nullptr;
    const long length = BIO_get_mem_data(bio, &data);
    if (length <= 0 || data == nullptr)
    {
        return {};
    }
    auto span = std::span(data, length);
    return {span.begin(), span.end()};
}

auto ec::convert_private_key_to_der(const evp_pkey_ptr &private_key) -> uint8_vector
{
    const auto bio = capi::make_unique(BIO_new(BIO_s_mem()), &BIO_free);
    if (i2d_PKCS8PrivateKey_bio(bio.get(), private_key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1)
    {
        throw_openssl_error("Failed to convert private key to DER.");
    }
    return bio_to_uint8(bio.get());
}

auto ec::convert_public_key_to_der(const evp_pkey_ptr &public_key) -> uint8_vector
{
    const auto bio = capi::make_unique(BIO_new(BIO_s_mem()), &BIO_free);
    if (i2d_PUBKEY_bio(bio.get(), public_key.get()) != 1)
    {
        throw_openssl_error("Failed to convert public key to DER.");
    }
    return bio_to_uint8(bio.get());
}

auto ec::convert_private_key_from_der(const uint8_vector &private_key) -> evp_pkey_ptr
{
    const auto bio =
        capi::make_unique(BIO_new_mem_buf(private_key.data(), static_cast<int>(private_key.size())), &BIO_free);
    return capi::make_unique_checked(d2i_PrivateKey_bio(bio.get(), nullptr), &EVP_PKEY_free,
                                     "Failed to load private key from DER");
}

auto ec::convert_public_key_from_der(const uint8_vector &public_key) -> evp_pkey_ptr
{
    const auto bio =
        capi::make_unique(BIO_new_mem_buf(public_key.data(), static_cast<int>(public_key.size())), &BIO_free);
    return capi::make_unique_checked(d2i_PUBKEY_bio(bio.get(), nullptr), &EVP_PKEY_free,
                                     "Failed to load public key from DER");
}

using namespace ec;

constexpr auto public_key_buf_size = 128;

ec_point::ec_point(std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> &&point,
                   std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> &&group)
    : point(std::move(point)), group(std::move(group))
{
}

auto ec_point::create_from_curve(const std::string &curve_name) -> std::unique_ptr<ec_point>
{
    const auto nid = OBJ_txt2nid(curve_name.c_str());
    if (nid == NID_undef)
    {
        throw_openssl_error("Failed to get nid from curve name " + curve_name);
    }

    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free);
    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(EC_POINT_new(group.get()), &EC_POINT_free);

    if (!group || !point)
    {
        throw_openssl_error("Failed to create ec point");
    }

    return std::unique_ptr<ec_point>(new ec_point(std::move(point), std::move(group)));
}

auto ec_point::clone() const -> std::unique_ptr<ec_point>
{
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> cloned_group(EC_GROUP_dup(group.get()), &EC_GROUP_free);
    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> cloned_point(EC_POINT_dup(point.get(), group.get()),
                                                                     &EC_POINT_free);
    return std::unique_ptr<ec_point>(new ec_point(std::move(cloned_point), std::move(cloned_group)));
}

auto ec_point::create(const std::string &curve_name, const uint8_vector &public_key) -> std::unique_ptr<ec_point>
{
    auto point = create_from_curve(curve_name);
    if (EC_POINT_oct2point(point->group.get(), point->point.get(), public_key.data(), public_key.size(), nullptr) != 1)
    {
        throw_openssl_error("Failed to create ec point from uncompressed public key");
    }
    return point;
}

auto ec_point::add(const ec_point &other) const -> std::unique_ptr<ec_point>
{
    auto result = clone();
    if (EC_POINT_add(group.get(), result->point.get(), point.get(), other.point.get(), nullptr) != 1)
    {
        throw_openssl_error("EC_POINT_add failed");
    }
    return result;
}

auto ec_point::times(const uint8_vector &signed_integer) const -> std::unique_ptr<ec_point>
{
    const std::unique_ptr<BIGNUM, decltype(&BN_free)> times(
        BN_signed_bin2bn(signed_integer.data(), static_cast<int>(signed_integer.size()), nullptr), &BN_free);
    auto result = clone();
    if (EC_POINT_mul(group.get(), result->point.get(), nullptr, point.get(), times.get(), nullptr) != 1)
    {
        throw_openssl_error("EC_POINT_mul failed");
    }
    return result;
}

auto ec_point::uncompressed() const -> uint8_vector
{
    uint8_vector public_key(public_key_buf_size);
    const auto length = EC_POINT_point2oct(group.get(), point.get(), POINT_CONVERSION_UNCOMPRESSED, public_key.data(),
                                           public_key.size(), nullptr);
    if (length == 0)
    {
        throw_openssl_error("Error during ec point conversion");
    }
    public_key.resize(length);
    return public_key;
}

ec_keypair::ec_keypair(evp_pkey_ptr &&pkey) : pkey(std::move(pkey))
{
}

auto ec_keypair::get_private_key_der() const -> uint8_vector
{
    return convert_private_key_to_der(pkey);
}

auto ec_keypair::get_public_key_der() const -> uint8_vector
{
    return convert_public_key_to_der(pkey);
}

auto ec_keypair::generate_keypair(const std::string &curve_name) -> std::unique_ptr<ec_keypair>
{
    // TODO: check correct key type
    const auto ctx = capi::make_unique(EVP_PKEY_CTX_new_from_name(nullptr, curve_name.c_str(), nullptr), &EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1)
    {
        throw_openssl_error("Failed to initialize key generation.");
    }
    //
    // const auto nid = OBJ_sn2nid(curve_name.c_str());
    // if (nid == NID_undef)
    // {
    //     throw_openssl_error("Invalid curve name: " + curve_name);
    // }
    //
    // if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), nid) != 1)
    // {
    //     throw_openssl_error("Failed to set EC curve.");
    // }

    EVP_PKEY *raw_pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw_pkey) != 1)
    {
        throw_openssl_error("Key generation failed.");
    }
    auto pkey = capi::make_unique(raw_pkey, &EVP_PKEY_free);

    return std::unique_ptr<ec_keypair>(new ec_keypair(std::move(pkey)));
}

ecdh::ecdh(evp_pkey_ctx_ptr &&ctx, evp_pkey_ptr &&pkey) : ctx(std::move(ctx)), pkey(std::move(pkey))
{
}

auto ecdh::create(const uint8_vector &private_key_der) -> std::unique_ptr<ecdh>
{
    auto pkey = convert_private_key_from_der(private_key_der);

    auto ctx = capi::make_unique(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!ctx)
    {
        throw_openssl_error("Failed to create ECDH context");
    }
    if (EVP_PKEY_derive_init(ctx.get()) != 1)
    {
        throw_openssl_error("Failed to initialize ECDH context");
    }

    return std::unique_ptr<ecdh>(new ecdh(std::move(ctx), std::move(pkey)));
}

auto ecdh::compute_secret(const uint8_vector &public_key_der) const -> uint8_vector
{
    const auto pkey = convert_public_key_from_der(public_key_der);
    EVP_PKEY_derive_set_peer(ctx.get(), pkey.get());
    auto shared_secret = uint8_vector();
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) != 1)
    {
        throw_openssl_error("Failed to compute secret");
    }
    shared_secret.resize(secret_len);
    EVP_PKEY_derive(ctx.get(), shared_secret.data(), &secret_len);
    return shared_secret;
}
