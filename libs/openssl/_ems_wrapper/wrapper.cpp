#include <emscripten/bind.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

extern "C" {
EMSCRIPTEN_KEEPALIVE
inline BIGNUM *BN_new_hex(const char *str) {
    BIGNUM *bn = BN_new();
    BN_hex2bn(&bn, str);
    return bn;
}
}
