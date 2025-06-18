#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/err.h"

void OPENSSL_free_fn(void *ptr) {
    if (ptr != NULL) {
        OPENSSL_free(ptr);
    }
}