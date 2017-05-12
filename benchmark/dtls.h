
#ifndef _BENCHMARK_DTLS_H_
#define _BENCHMARK_DTLS_H_


#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    unsigned char local_fingerprint[160];
} DTLSParams;

int
dtls_InitContextFromKeystore(DTLSParams* params, const char* keyname);

#ifdef __cplusplus
}
#endif

#endif //_BENCHMARK_DTLS_H_

