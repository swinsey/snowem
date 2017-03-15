#ifndef _ICE_DTLS_H
#define _ICE_DTLS_H

#include <inttypes.h>
#include <srtp/srtp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/* DTLS stuff */
#define DTLS_CIPHERS "ALL:NULL:eNULL:aNULL"

/* SRTP stuff (http://tools.ietf.org/html/rfc3711) */
#define SRTP_MASTER_KEY_LENGTH   16
#define SRTP_MASTER_SALT_LENGTH  14
#define SRTP_MASTER_LENGTH (SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH)

#define SRTP_ERR_STR ERR_reason_error_string(ERR_get_error())

/* DTLS role */
enum  {
   DTLS_ROLE_ACTPASS = 0,
   DTLS_ROLE_SERVER,
   DTLS_ROLE_CLIENT,
};

/* DTLS state */
enum {
   DTLS_STATE_FAILED = 0,
   DTLS_STATE_CREATED,
   DTLS_STATE_TRYING,
   DTLS_STATE_CONNECTED,
};

/* Helper struct to keep the filter state */
#define ICE_DTLS_PKT_NUM 10
typedef struct dtls_bio_filter {
   int pkts[ICE_DTLS_PKT_NUM+1];
   int num;
} dtls_bio_filter;


typedef struct dtls_ctx dtls_ctx_t;
struct dtls_ctx {
   void *component;             
   SSL *ssl;
   BIO *read_bio;               /* incoming DTLS data */
   BIO *write_bio;              /* outgoing DTLS data */
   BIO *filter_bio;             /* to fix MTU fragmentation on outgoing DTLS data */
   srtp_t srtp_in;              /* libsrtp context for incoming SRTP packets */
   srtp_t srtp_out;             /* libsrtp context for outgoing SRTP packets */
   srtp_policy_t remote_policy; /* libsrtp policy for incoming SRTP packets */
   srtp_policy_t local_policy;  /* libsrtp policy for outgoing SRTP packets */

   int role;                    /* DTLS role */
   int state;                   /* DTLS state */
   int srtp_valid;              
   int ready;                   
   int64_t dtls_connected;      /* Monotonic time of when the DTLS state has switched to connected */
   dtls_bio_filter bio_pending_state;
};

int srtp_setup(char *server_pem, char *server_key);
SSL_CTX *srtp_get_ssl_ctx(void);
char *srtp_get_local_fingerprint(void);

dtls_ctx_t *srtp_context_new(void *component, int role);
void srtp_do_handshake(dtls_ctx_t *dtls);
int srtp_process_incoming_msg(dtls_ctx_t *dtls, char *buf, uint16_t len);
void srtp_context_free(dtls_ctx_t *dtls);
void srtp_callback(const SSL *ssl, int where, int ret);
int srtp_verify_cb(int preverify_ok, X509_STORE_CTX *ctx);
int srtp_send_data(dtls_ctx_t *dtls);


/* Handle dtls fragmentation */
BIO_METHOD *BIO_ice_dtls_filter(void);
void srtp_bio_filter_set_mtu(int start_mtu);


#endif

