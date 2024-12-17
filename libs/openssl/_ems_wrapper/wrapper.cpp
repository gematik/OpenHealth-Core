#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>


#include <emscripten/bind.h>


// BIGNUM

using ems_BIGNUM = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

// OSSL

using ems_OSSL_LIB_CTX = std::unique_ptr<OSSL_LIB_CTX, decltype(&OSSL_LIB_CTX_free)>;

using ems_OSSL_PARAM = OSSL_PARAM;

ems_OSSL_PARAM ems_OSSL_PARAM_construct_utf8_string(const std::string &key, const std::string &buf) {
    return OSSL_PARAM_construct_utf8_string(key.data(), const_cast<char *>(buf.c_str()), 0);
}

ems_OSSL_PARAM ems_OSSL_PARAM_construct_end() {
    return OSSL_PARAM_construct_end();
}

// CMAC

using ems_EVP_MAC = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;

ems_EVP_MAC ems_EVP_MAC_fetch(const ems_OSSL_LIB_CTX *libctx, const std::string &algorithm,
                              const std::string &properties) {
    return {EVP_MAC_fetch(libctx ? libctx->get() : nullptr, algorithm.c_str(), nullptr), &EVP_MAC_free};
}

using ems_EVP_MAC_CTX = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

ems_EVP_MAC_CTX ems_EVP_MAC_CTX_new(const ems_EVP_MAC &mac) {
    return {EVP_MAC_CTX_new(mac.get()), &EVP_MAC_CTX_free};
}

int ems_EVP_MAC_init(const ems_EVP_MAC_CTX &ctx, const std::string &key, const std::vector<OSSL_PARAM> &params) {
    return EVP_MAC_init(ctx.get(), reinterpret_cast<const unsigned char *>(key.data()), key.size(), params.data());
}

int ems_EVP_MAC_update(const ems_EVP_MAC_CTX &ctx, const std::string &data) {
    return EVP_MAC_update(ctx.get(), reinterpret_cast<const unsigned char *>(data.data()), data.size());
}

std::optional<std::string> ems_EVP_MAC_final(const ems_EVP_MAC_CTX &ctx) {
    size_t outl;
    if (EVP_MAC_final(ctx.get(), nullptr, &outl, 0) == 0) {
        return std::nullopt;
    }

    std::vector<unsigned char> data(outl);
    if (EVP_MAC_final(ctx.get(), data.data(), nullptr, outl)) {
        return std::nullopt;
    }

    return std::string(data.begin(), data.end());
}

// EVP_CIPHER

using ems_EVP_CIPHER_CTX = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

ems_EVP_CIPHER_CTX ems_EVP_CIPHER_CTX_new() {
    return {EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
}

// EC

using ems_EC_GROUP = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;

ems_EC_GROUP ems_EC_GROUP_new_by_curve_name(const int nid) {
    return {EC_GROUP_new_by_curve_name(nid), &EC_GROUP_free};
}

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

void throwOpenSSLError(const std::string& context) {
    unsigned long errCode = ERR_get_error(); // Get the latest OpenSSL error
    if (errCode != 0) {
        const char* reason = ERR_error_string(errCode, nullptr);
        std::string errorMsg = context + ": " + (reason ? reason : "Unknown OpenSSL error");
        throw std::runtime_error(errorMsg);
    } else {
        throw std::runtime_error(context + ": No OpenSSL error recorded");
    }
}

class Cmac {
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac;
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx;

public:
    Cmac(): mac({nullptr, &EVP_MAC_free}), ctx({nullptr, &EVP_MAC_CTX_free}) {
    }

    void initialize(const std::vector<unsigned char> &key, const std::string &cipher) {
        mac.reset(EVP_MAC_fetch(nullptr, "CMAC", nullptr));
        if (!mac) {
            throw std::runtime_error("EVP_MAC_fetch failed");
        }

        ctx.reset(EVP_MAC_CTX_new(mac.get()));
        if (!ctx) {
            throw std::runtime_error("EVP_MAC_CTX_new failed");
        }

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("cipher", const_cast<char *>(cipher.c_str()), 0);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1) {
            throwOpenSSLError("EVP_MAC_init failed");
        }
    }

    void update(const std::vector<unsigned char> &data) const {
        if (EVP_MAC_update(ctx.get(), data.data(), data.size()) != 1) {
            throw std::runtime_error("EVP_MAC_update failed");
        }
    }
    std::vector<unsigned char> finalize() const {
        size_t outl;
        if (EVP_MAC_final(ctx.get(), nullptr, &outl, 0) != 1) {
            throw std::runtime_error("EVP_MAC_final failed to get output length");
        }

        std::vector<unsigned char> data(outl);
        if (EVP_MAC_final(ctx.get(), data.data(), &outl, outl) != 1) {
            throw std::runtime_error("EVP_MAC_final failed to finalize");
        }

        return data;
    }
};

// std::vector<unsigned char> fromTypedArray(const emscripten::val& data) {
//     return std::vector(data.begin(), data.end());
// }

std::vector<unsigned char> fromTypedArray(const emscripten::val& data) {
    auto length = data["length"].as<unsigned int>();
    std::vector<unsigned char> result(length);
    emscripten::val memoryView = emscripten::val::global("Uint8Array").new_(emscripten::typed_memory_view(length, result.data()));
    memoryView.call<void>("set", data);
    return result;
}

emscripten::val toTypedArray(const std::vector<unsigned char> &data) {
    return emscripten::val(emscripten::typed_memory_view(data.size(), data.data()));
}

//
// int sadfasd() {
//     unsigned char key[] = "0123456789abcdef"; // Example key
//     unsigned char data[] = "This is a test message."; // Example data
//     unsigned char cmac_value[EVP_MAX_BLOCK_LENGTH];
//     size_t cmac_len;
//
//     EVP_MAC *mac = NULL;
//     EVP_MAC_CTX *ctx = NULL;
//     OSSL_PARAM params[2];
//
//     // Create MAC context for CMAC
//     mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
//     if (!mac) {
//         fprintf(stderr, "Error fetching CMAC implementation.\n");
//         return 1;
//     }
//
//     ctx = EVP_MAC_CTX_new(mac);
//     if (!ctx) {
//         fprintf(stderr, "Error creating MAC context.\n");
//         EVP_MAC_free(mac);
//         return 1;
//     }
//
//     // Set key and cipher as parameters
//     params[0] = OSSL_PARAM_construct_utf8_string("cipher", "AES-128-CBC", 0);
//     params[1] = OSSL_PARAM_construct_end();
//
//     if (EVP_MAC_init(ctx, key, sizeof(key) - 1, params) != 1) {
//         fprintf(stderr, "Error initializing MAC context.\n");
//         EVP_MAC_CTX_free(ctx);
//         EVP_MAC_free(mac);
//         return 1;
//     }
//
//     // Update MAC with data
//     if (EVP_MAC_update(ctx, data, strlen((char *)data)) != 1) {
//         fprintf(stderr, "Error updating MAC.\n");
//         EVP_MAC_CTX_free(ctx);
//         EVP_MAC_free(mac);
//         return 1;
//     }
//
//     // Finalize and get the MAC value
//     if (EVP_MAC_final(ctx, cmac_value, &cmac_len, sizeof(cmac_value)) != 1) {
//         fprintf(stderr, "Error finalizing MAC.\n");
//         EVP_MAC_CTX_free(ctx);
//         EVP_MAC_free(mac);
//         return 1;
//     }
//
//     // Print CMAC value
//     printf("CMAC: ");
//     for (size_t i = 0; i < cmac_len; i++) {
//         printf("%02x", cmac_value[i]);
//     }
//     printf("\n");
//
//     // Cleanup
//     EVP_MAC_CTX_free(ctx);
//     EVP_MAC_free(mac);
//
//     return 0;
// }

EMSCRIPTEN_BINDINGS(OpenSSL) {
    using namespace emscripten;

    // register_optional<std::string>();

    // Cmac

    function("toTypedArray", &toTypedArray);
    function("fromTypedArray", &fromTypedArray);

    register_vector<unsigned char>("UChar_vector");

    class_<Cmac>("Cmac")
            .constructor()
            .function("initialize", &Cmac::initialize)
            .function("update", &Cmac::update)
            .function("finalize", &Cmac::finalize);

    // // BIGNUM
    //
    // class_<ems_BIGNUM>("BIGNUM");
    //
    // // OSSL
    //
    // register_vector<OSSL_PARAM>("OSSL_PARAM_vector");
    // class_<ems_OSSL_LIB_CTX>("OSSL_LIB_CTX");
    //
    // class_<ems_OSSL_PARAM>("OSSL_PARAM");
    // function("OSSL_PARAM_construct_utf8_string", &ems_OSSL_PARAM_construct_utf8_string);
    // function("OSSL_PARAM_construct_end", &ems_OSSL_PARAM_construct_end);
    //
    // // CMAC
    //
    // class_<ems_EVP_MAC>("EVP_MAC");
    // class_<ems_EVP_MAC_CTX>("EVP_MAC_CTX");
    //
    // function("EVP_MAC_fetch", &ems_EVP_MAC_fetch, allow_raw_pointer<std::string>(),
    //          return_value_policy::take_ownership());
    // function("EVP_MAC_CTX_new", &ems_EVP_MAC_CTX_new, return_value_policy::take_ownership());
    // function("EVP_MAC_init", &ems_EVP_MAC_init);
    // function("EVP_MAC_update", &ems_EVP_MAC_update);
    // function("EVP_MAC_final", &ems_EVP_MAC_final);
    //
    // // EVP_CIPHER
    //
    // class_<ems_EVP_CIPHER_CTX>("EVP_CIPHER_CTX");
    // function("EVP_CIPHER_CTX_new", &ems_EVP_CIPHER_CTX_new, return_value_policy::take_ownership());
    //
    // // EC
    //
    // class_<ems_EC_GROUP>("EC_GROUP");
    // function("EC_GROUP_new_by_curve_name", &ems_EC_GROUP_new_by_curve_name, return_value_policy::take_ownership());
    //
    // class_<ems_EC_POINT>("EC_POINT");
    // function("EC_POINT_new", &ems_EC_POINT_new, return_value_policy::take_ownership());
    //
    // function("EC_POINT_mul", &ems_EC_POINT_mul, allow_raw_pointer<ems_BIGNUM>());
}
