#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/types.h"
#include "openssl/core_names.h"

void OPENSSL_free_fn(void *ptr) {
    if (ptr != NULL) {
        OPENSSL_free(ptr);
    }
}