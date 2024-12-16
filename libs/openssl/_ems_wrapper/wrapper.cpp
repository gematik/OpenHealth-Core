#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>

#include <emscripten/bind.h>

// BIGNUM

using ems_BIGNUM = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

// OSSL
//
// using ems_OSSL_LIB_CTX = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
//
// // CMAC
//
// using ems_EVP_MAC = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
//
// void ems_EVP_MAC_fetch(OSSL_LIB_CTX *libctx, const std::string &algorithm,
//                        const std::string &properties) {
//     EVP_MAC_fetch()
//
// }

// EVP_CIPHER

using ems_EVP_CIPHER_CTX = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

ems_EVP_CIPHER_CTX ems_EVP_CIPHER_CTX_new() {
    return {EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
}

// EC_GROUP

using ems_EC_GROUP = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;

ems_EC_GROUP ems_EC_GROUP_new_by_curve_name(const int nid) {
    return {EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free};
}

// EC_POINT

using ems_EC_POINT = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

ems_EC_POINT ems_EC_POINT_new(const ems_EC_GROUP &group) {
    return {EC_POINT_new(group.get()), &EC_POINT_free};
}

using ems_EC_POINT = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

int ems_EC_POINT_mul(const ems_EC_GROUP &group, const ems_EC_POINT &r,
                     const ems_BIGNUM *n,
                     const ems_EC_POINT &q, const ems_BIGNUM &m) {
    return EC_POINT_mul(group.get(), r.get(), n ? n->get() : nullptr, q.get(), m.get(),
                        nullptr);
}

EMSCRIPTEN_BINDINGS(OpenSSL) {
    using namespace emscripten;

    class_<ems_BIGNUM>("ems_BIGNUM_ptr");
    class_<std::reference_wrapper<ems_BIGNUM> >("ems_BIGNUM_ref");
    register_optional<std::reference_wrapper<ems_BIGNUM> >();

    class_<ems_EVP_CIPHER_CTX>("ems_EVP_CIPHER_CTX_ptr");
    function("ems_EVP_CIPHER_CTX_new", &ems_EVP_CIPHER_CTX_new, return_value_policy::take_ownership());

    class_<ems_EC_GROUP>("ems_EC_GROUP_ptr");
    function("ems_EC_GROUP_new_by_curve_name", &ems_EC_GROUP_new_by_curve_name, return_value_policy::take_ownership());

    class_<ems_EC_POINT>("ems_EC_POINT_ptr");
    function("ems_EC_POINT_new", &ems_EC_POINT_new, return_value_policy::take_ownership());

    function("ems_EC_POINT_mul", &ems_EC_POINT_mul);
}
