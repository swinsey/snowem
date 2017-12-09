
#ifndef _BENCHMARK_DTLS_H_
#define _BENCHMARK_DTLS_H_

//#ifdef __cplusplus
//extern "C" {
//#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <srtp/srtp.h>

#include "cicero/list.h"

//packet type
#define UNKNOWN_PT 0
#define RTP_PT     1
#define RTCP_PT    2
#define DTLS_PT    3
      
/* RTP packet */
#define RTP_HEADER_SIZE 12
typedef struct rtp_packet rtp_packet_t;
struct rtp_packet { 
   char *data;
   int length;

   uint8_t type:1;      //0 - audio, 1 - video
   uint8_t control:1;   //0 - rtp, 1 - rtcp
   uint8_t keyframe:1;  //0 - non-key frame, 1 - key frame
   uint8_t encrypted:1;
   uint8_t reserve:4;
   
   uint64_t last_retransmit;
   
   struct list_head list;
}; 

typedef struct rtp_header
{
#if __BYTE_ORDER == __BIG_ENDIAN
   uint16_t version:2;
   uint16_t padding:1;
   uint16_t extension:1;
   uint16_t csrccount:4;
   uint16_t markerbit:1;
   uint16_t type:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
   uint16_t csrccount:4;
   uint16_t extension:1;
   uint16_t padding:1;
   uint16_t version:2;
   uint16_t type:7;
   uint16_t markerbit:1;
#endif
   uint16_t seq_number;
   uint32_t timestamp;
   uint32_t ssrc;
   uint32_t csrc[16];
} rtp_header;


int ice_get_packet_type(char* buf, int len);

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
   void *wsclient;
   void *component;             
   void *agent;
   uint32_t component_id;
   uint32_t stream_id;
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

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    unsigned char local_fingerprint[160];
    unsigned char remote_fingerprint[160];
    dtls_ctx_t *dtls_ctx;
} DTLSParams;

int
init_dtls_srtp_ctx(DTLSParams* params, const char* keyname);

int srtp_setup(char *server_pem, char *server_key);
SSL_CTX *srtp_get_ssl_ctx(void);
char *srtp_get_local_fingerprint(void);

dtls_ctx_t*
srtp_context_new(DTLSParams *params, void *component, int role);

void
srtp_destroy(dtls_ctx_t *dtls);

void srtp_do_handshake(dtls_ctx_t *dtls);
int srtp_process_incoming_msg(dtls_ctx_t *dtls, char *buf, uint16_t len);
void srtp_context_free(dtls_ctx_t *dtls);
void srtp_callback(const SSL *ssl, int where, int ret);
int srtp_verify_cb(int preverify_ok, X509_STORE_CTX *ctx);
int srtp_send_data(dtls_ctx_t *dtls);

/* Handle dtls fragmentation */
BIO_METHOD *BIO_ice_dtls_filter(void);
void srtp_bio_filter_set_mtu(int start_mtu);

int
srtp_dtls_setup(dtls_ctx_t *dtls);

//#ifdef __cplusplus
//}
//#endif

#endif //_BENCHMARK_DTLS_H_

