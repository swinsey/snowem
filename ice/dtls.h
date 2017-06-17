#ifndef _ICE_DTLS_H
#define _ICE_DTLS_H

#include <inttypes.h>
#include <srtp/srtp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ice.h"

/* DTLS stuff */
#define DTLS_CIPHERS "ALL:NULL:eNULL:aNULL"

/* SRTP stuff (http://tools.ietf.org/html/rfc3711) */
#define SRTP_MASTER_KEY_LENGTH   16
#define SRTP_MASTER_SALT_LENGTH  14
#define SRTP_MASTER_LENGTH (SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH)

#define SRTP_ERR_STR ERR_reason_error_string(ERR_get_error())

#define DTLS_BUFFER_SIZE 1500
#define DTLS_MTU_SIZE 1472

/* dtls type */
enum  {
   DTLS_TYPE_ACTPASS = 0,
   DTLS_TYPE_SERVER,
   DTLS_TYPE_CLIENT,
};

enum {
   DTLS_STATE_CONNECTING = 0,
   DTLS_STATE_CONNECTED,
   DTLS_STATE_ERROR,
};

struct dtls_ctx {
   snw_ice_context_t *ctx;
   void              *component;             

   int    type;
   int    state;

   /* handshake stuff */
   SSL *ssl;
   BIO *in_bio;
   BIO *out_bio;
   BIO *dtls_bio;

   /* srtp contect */
   srtp_t srtp_in;
   srtp_t srtp_out;
   srtp_policy_t remote_policy;
   srtp_policy_t local_policy;
};

int
srtp_setup(snw_ice_context_t *ctx, char *server_pem, char *server_key);

dtls_ctx_t*
srtp_context_new(snw_ice_context_t *ice_ctx, void *component, int role);

void
srtp_destroy(dtls_ctx_t *dtls);

void srtp_do_handshake(dtls_ctx_t *dtls);
int srtp_process_incoming_msg(dtls_ctx_t *dtls, char *buf, uint16_t len);
void srtp_context_free(dtls_ctx_t *dtls);
void srtp_callback(const SSL *ssl, int where, int ret);
int srtp_verify_cb(int preverify_ok, X509_STORE_CTX *ctx);
int srtp_send_data(dtls_ctx_t *dtls);

#endif

