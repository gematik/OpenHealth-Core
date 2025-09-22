#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/types.h"
#include "openssl/core_names.h"
#include "openssl/provider.h"
#include "openssl/crypto.h"

void OPENSSL_free_fn(void *ptr);
