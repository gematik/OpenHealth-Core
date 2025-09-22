#include "rust_wrapper.h"
#include "openssl/crypto.h"

void OPENSSL_free_fn(void *ptr) {
    if (ptr != NULL) {
        OPENSSL_free(ptr);
    }
}