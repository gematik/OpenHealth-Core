#include "../../src/capi.hpp"

#include <array>
#include <catch2/catch_test_macros.hpp>
#include <climits>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <emscripten/bind.h>
#include <emscripten/em_macros.h>
#include <iostream>
#include <mutex>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <print>
#include <random>
#include <span>
#include <string_view>
#include <thread>

// constexpr auto random_provider_name = "custom_rand";
//
// // Constants for magic numbers
// constexpr unsigned char kByteMask = 0xFF;
// constexpr int kDefaultStrength = 256;
//
// class custom_provider_ctx
// {
//     std::recursive_mutex mutex;
//     std::unordered_map<std::shared_ptr<EVP_RAND_CTX>, std::function<uint64_t()>> callbacks;
//
// public:
//     custom_provider_ctx() = default;
//     custom_provider_ctx(const custom_provider_ctx&) = delete;
//     auto operator=(const custom_provider_ctx&) -> custom_provider_ctx& = delete;
//     custom_provider_ctx(custom_provider_ctx&&) = delete;
//     auto operator=(custom_provider_ctx&&) -> custom_provider_ctx& = delete;
//
//     ~custom_provider_ctx() = default;
//
//     auto register_callback(const std::shared_ptr<EVP_RAND_CTX> &ctx, std::function<uint64_t()> &&callback) -> void
//     {
//         auto lock = std::lock_guard{mutex};
//         if (callbacks.contains(ctx))
//         {
//             throw std::runtime_error("EVP_RAND_CTX can only contain one callback at a time");
//         }
//         callbacks[ctx] = std::move(callback);
//     }
//
//     auto call(const std::shared_ptr<EVP_RAND_CTX> &ctx) -> uint64_t
//     {
//
//     }
//
//     auto unregister_callback(const std::shared_ptr<EVP_RAND_CTX> &ctx) -> void
//     {
//         auto lock = std::lock_guard{mutex};
//         callbacks.erase(ctx);
//     }
// };
//
// struct callback_guard
// {
//     custom_provider_ctx *prov_ctx;
//     const std::shared_ptr<EVP_RAND_CTX> rand_ctx;
//
//     callback_guard(custom_provider_ctx *ctx, const std::shared_ptr<EVP_RAND_CTX>& rand)
//         : prov_ctx(ctx), rand_ctx(rand) {}
//
//     ~callback_guard()
//     {
//         prov_ctx->unregister_callback(rand_ctx);
//     }
//
//     callback_guard(const callback_guard &) = delete;
//     auto operator=(const callback_guard &) -> callback_guard & = delete;
//     callback_guard(callback_guard &&) noexcept = delete;
//     auto operator=(callback_guard &&) noexcept -> callback_guard & = delete;
// };
//
// extern "C"
// {
//     EMSCRIPTEN_KEEPALIVE
//     void crypto_random_buf(unsigned char *buf, const size_t num)
//     {
//         const auto crypto = emscripten::val::global("crypto");
//         const auto buffer = crypto.call<emscripten::val>("randomBytes", num);
//         std::span<unsigned char> buf_view{buf, num};
//         for (size_t i = 0; i < num; ++i)
//         {
//             buf_view[i] = buffer[i].as<unsigned>();
//         }
//     }
// }
//
// struct random_callback_context
// {
//     int state = 0;
//     custom_provider_ctx *prov_ctx;
//     std::mutex mutex;
//
//     explicit random_callback_context(custom_provider_ctx *ctx) : prov_ctx(ctx) {}
// };
//
// static auto custom_rand_generate(void *vctx, unsigned char *out, size_t outlen, unsigned int strength,
//                                  int prediction_resistance, const unsigned char *adin, size_t adinlen) -> int
// {
//
//     std::println("call to custom_rand_generate");
//     auto *ctx = static_cast<random_callback_context *>(vctx);
//
//     for (std::span out_span{out, outlen}; auto &byte : out_span)
//     {
//         byte = static_cast<unsigned char>((ctx->prov_ctx->()) & kByteMask);
//     }
//     return 1;
// }
//
// // Free the custom context
// static auto custom_rand_free(void *vctx) -> void
// {
//     std::println("call to custom_rand_free");
//     delete static_cast<random_callback_context *>(vctx);
// }
//
// // Create a new custom context, using trailing return type
// static auto custom_rand_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_dispatch) -> void *
// {
//     std::println("call to custom_rand_newctx");
//     (void)parent;
//     (void)parent_dispatch;
//     std::println("Creating custom_rand_context");
//     auto *ctx = new random_callback_context{static_cast<custom_provider_ctx*>(provctx)};
//     // ctx->gen.default_seed
//     return ctx;
// }
//
// static auto custom_rand_instantiate(void *vrng,  unsigned int strength,
//                                      int prediction_resistance,  const unsigned char *pstr,
//                                     size_t pstr_len,  const OSSL_PARAM params[]) -> int
// {
//     std::println("call to custom_rand_instantiate");
//     (void)vrng;
//     (void)strength;
//     (void)prediction_resistance;
//     (void)pstr;
//     (void)pstr_len;
//     (void)params;
//     return 1;
// }
//
// static auto fake_rand_uninstantiate(void *vrng) -> int
// {
//     std::println("call to fake_rand_uninstantiate");
//     (void)vrng;
//     return 1;
// }
//
// static auto fake_rand_get_ctx_params(ossl_unused void *vrng, OSSL_PARAM params[]) -> int
// {
//     std::println("call to fake_rand_get_ctx_params");
//     auto *frng = reinterpret_cast<random_callback_context *>(vrng);
//     OSSL_PARAM *param = nullptr;
//
//     param = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
//     if (param != nullptr)
//     {
//         if (!OSSL_PARAM_set_int(param, frng->state))
//         {
//             return 0;
//         }
//     }
//
//     param = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
//     if (param != nullptr)
//     {
//         if (OSSL_PARAM_set_size_t(param, INT_MAX) == 0)
//         {
//             return 0;
//         }
//     }
//     return 1;
// }
//
// static auto fake_rand_set_ctx_params(ossl_unused void *vrng, OSSL_PARAM params[]) -> int
// {
//     std::println("call to fake_rand_set_ctx_params");
//     auto *frng = reinterpret_cast<random_callback_context *>(vrng);
//     OSSL_PARAM *param = nullptr;
//
//     param = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
//     if (param != nullptr)
//     {
//         if (!OSSL_PARAM_set_int(param, frng->state))
//         {
//             return 0;
//         }
//     }
//
//     param = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
//     if (param != nullptr)
//     {
//         if (OSSL_PARAM_set_size_t(param, INT_MAX) == 0)
//         {
//             return 0;
//         }
//     }
//     return 1;
// }
//
// static auto fake_rand_gettable_ctx_params(ossl_unused void *vrng, ossl_unused void *provctx) -> const OSSL_PARAM *
// {
//     std::println("call to fake_rand_gettable_ctx_params");
//     static const std::array<OSSL_PARAM, 4> known_gettable_ctx_params{
//         {OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, nullptr), OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, nullptr),
//          OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, nullptr), OSSL_PARAM_END}};
//     return known_gettable_ctx_params.data();
// }
//
// static auto cb_rand_enable_locking(void *vctx) -> int
// {
//     return 1;
// }
//
// static auto cb_rand_lock(void *vctx) -> void
// {
//     auto *ctx = static_cast<random_callback_context *>(vctx);
//     ctx->mutex.lock();
// }
//
// static auto cb_rand_unlock(void *vctx) -> void
// {
//     auto *ctx = static_cast<random_callback_context *>(vctx);
//     ctx->mutex.unlock();
// }
//
// static const std::array<OSSL_DISPATCH, 11> custom_rand_functions{{
//     /* NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast) */
//     {.function_id = OSSL_FUNC_RAND_NEWCTX, .function = reinterpret_cast<void (*)()>(custom_rand_newctx)},
//     {.function_id = OSSL_FUNC_RAND_INSTANTIATE, .function = reinterpret_cast<void (*)()>(custom_rand_instantiate)},
//     {.function_id = OSSL_FUNC_RAND_UNINSTANTIATE, .function = reinterpret_cast<void (*)()>(fake_rand_uninstantiate)},
//     {.function_id = OSSL_FUNC_RAND_GENERATE, .function = reinterpret_cast<void (*)()>(custom_rand_generate)},
//     {.function_id = OSSL_FUNC_RAND_FREECTX, .function = reinterpret_cast<void (*)()>(custom_rand_free)},
//     {.function_id = OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
//      .function = reinterpret_cast<void (*)()>(fake_rand_gettable_ctx_params)},
//     {.function_id = OSSL_FUNC_RAND_GET_CTX_PARAMS, .function = reinterpret_cast<void (*)()>(fake_rand_get_ctx_params)},
//     {.function_id = OSSL_FUNC_RAND_ENABLE_LOCKING, .function = reinterpret_cast<void (*)()>(cb_rand_enable_locking)},
//     {.function_id = OSSL_FUNC_RAND_LOCK, .function = reinterpret_cast<void (*)()>(cb_rand_lock)},
//     {.function_id = OSSL_FUNC_RAND_UNLOCK, .function = reinterpret_cast<void (*)()>(cb_rand_unlock)},
//     OSSL_DISPATCH_END
//     /* NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast) */
// }};
//
// static const std::array<OSSL_ALGORITHM, 2> rand_algorithms{
//     {{.algorithm_names = "RAND",
//       .property_definition = "provider=custom",
//       .implementation = custom_rand_functions.data()},
//      {.algorithm_names = nullptr, .property_definition = nullptr, .implementation = nullptr}}};
//
// static auto custom_provider_query(void *provctx, int operation_id, const int *no_cache) -> const OSSL_ALGORITHM *
// {
//     if (operation_id == OSSL_OP_RAND)
//     {
//         return rand_algorithms.data();
//     }
//     return nullptr;
// }
//
// static const std::array<OSSL_DISPATCH, 2> provider_dispatch{
//     {{.function_id=OSSL_FUNC_PROVIDER_QUERY_OPERATION, .function=reinterpret_cast<void (*)()>(custom_provider_query)}, OSSL_DISPATCH_END}};
//
// static auto custom_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
//                                  void **provctx) -> int
// {
//     (void)in;
//     *out = provider_dispatch.data();
//     *provctx = new custom_provider_ctx();
//     return 1;
// }

void print_openssl_errors() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        fprintf(stderr, "OpenSSL Error: %s\n", ERR_error_string(err, NULL));
    }
}

TEST_CASE("Random provider returns from seed pool", "[random]")
{
    // if (OSSL_PROVIDER_add_builtin(nullptr, "fake", custom_provider_init) == 0)
    // {
    //     std::cerr << "Failed to register custom provider!" << std::endl;
    // }
    //
    //
    // OSSL_PROVIDER *prov = OSSL_PROVIDER_try_load(nullptr, "fake", 1);
    // if (!prov)
    // {
    //     std::cerr << "Failed to load custom provider!" << std::endl;
    //     return;
    // }
    //
    // auto *provctx = static_cast<custom_provider_ctx*>(OSSL_PROVIDER_get0_provider_ctx(prov));
    //
    //
    // if (!OSSL_PROVIDER_available(nullptr, "fake"))
    // {
    //     std::cerr << "Provider unavailable!" << std::endl;
    //     return;
    // }


    // EVP_RAND *rand = EVP_RAND_fetch(nullptr, "RAND", nullptr);
    // EVP_RAND *rand = EVP_RAND_fetch(nullptr, "CTR-DRBG", "provider=default");
    // if (!rand)
    // {
    //     std::cerr << "Failed to fetch RAND!" << std::endl;
    //     return;
    // }
    // auto *rand_ctx =EVP_RAND_CTX_new(rand, nullptr);
    // if (!rand_ctx)
    // {
    //     std::cerr << "Failed to create RAND context!" << std::endl;
    //     return;
    // }
    // // auto cb_guard = callback_guard{provctx, rand_ctx};
    // // provctx->register_callback(rand_ctx, [] -> uint64_t { return 123; });
    // // Set the DRBG instance as the primary random source
    // if (EVP_RAND_instantiate(rand_ctx, 0, 0, nullptr, 0, nullptr) <= 0) {
    //     std::cerr << "Failed to instantiate custom RNG!" << std::endl;
    //     return;
    // }

    std::array<unsigned char, 16> buffer{};

    if (RAND_bytes(buffer.data(), buffer.size()))
    {
        std::cout << "Custom Random Bytes: ";
        for (unsigned char byte : buffer)
        {
            std::printf("%02X ", byte);
        }
        std::cout << std::endl;
    } else
    {
        print_openssl_errors();
    }



    // EVP_RAND_CTX *rand_ctx2 = EVP_RAND_CTX_new(rand, nullptr);

    // std::println("GG: {}", RAND_set0_public(nullptr, rand_ctx2)); // Use for non-cryptographic purposes
    // std::println("GG: {}", RAND_set0_private(nullptr, rand_ctx2)); // Use for cryptographic keygen

    // assert(RAND_get0_private(nullptr) == rand_ctx2);

    // Initialize EC key generation
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0) {
        std::cerr << "Failed to initialize EC keygen!" << std::endl;
        return;
    }

    const auto params =
        std::array{OSSL_PARAM_construct_utf8_string("group",
                                                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
                                                   "P-256", 0),
                   OSSL_PARAM_construct_end()};

    // Set curve
    if (EVP_PKEY_CTX_set_params(pctx, params.data()) <= 0) {
        std::cerr << "Failed to set curve!" << std::endl;
        return;
    }

    // Generate key
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        std::cerr << "Key generation failed!" << std::endl;
        print_openssl_errors();
        return;
    }

    std::cout << "EC Key generated using custom provider's RNG!" << std::endl;

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio && PEM_write_bio_PUBKEY(bio, pkey))
    {
        char *key_data;
        long key_len = BIO_get_mem_data(bio, &key_data);
        std::cout << "Public Key:\n" << std::string(key_data, key_len) << std::endl;
    }

    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    // EVP_RAND_CTX_free(rand_ctx);
    // EVP_RAND_free(rand);
    // OSSL_PROVIDER_unload(prov);
}