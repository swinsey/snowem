#ifndef _BENCHMARK_WSCLIENT_H_
#define _BENCHMARK_WSCLIENT_H_

#include <unistd.h>
#include <string.h>
#include <fstream>

#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/event.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>

#include "json/json.h"
#include "wslay/wslay.h"
#include "cicero/agent.h"
#include "util.h"
#include "dtls.h"

#define MAX_HTTP_HEADER_SIZE 8192

#define ERR_FAILURE 1
#define ERR_READ    2
#define ERR_WRITE   3

class WsClient;

enum evws_data_type {
  EVWS_DATA_TEXT = 0,
  EVWS_DATA_BINARY = 1,
};

typedef struct bm_config_ bm_config;
struct bm_config_ {
   int total_client_num;
   int started_client_num;
   int stopped_client_num;
   struct event *ev;
   int n_calls;
   int channel_id;

   struct event_base *base;
   struct evdns_base *dns_base;
   SSL_CTX *ssl_ctx;
   SSL_CTX *dtls_ssl_ctx;
   DTLSParams *dtls_params;
};
extern bm_config g_config;


/* Built-in module (msg) type */
enum {
   SNW_MSGTYPE_MIN = 1,
   SNW_ICE = SNW_MSGTYPE_MIN,
   SNW_CORE = 2,
   SNW_EVENT = 3,

   /* reserve range */
   SNW_MSGTYPE_MAX = 255,
};

/* ICE api code */
enum {
   SNW_ICE_MIN = 1,
   SNW_ICE_CREATE = SNW_ICE_MIN,
   SNW_ICE_CONNECT = 2,
   SNW_ICE_STOP = 3,
   SNW_ICE_SDP = 4,
   SNW_ICE_CANDIDATE = 5,
   SNW_ICE_PUBLISH = 6,
   SNW_ICE_PLAY = 7,
   SNW_ICE_FIR = 8,

   /* reserved range */
   SNW_ICE_MAX = 255,
};

/* CORE api code */
enum {
   SNW_CORE_MIN = 1,
   SNW_CORE_RTP = SNW_CORE_MIN,
   SNW_CORE_RTCP = 2,

   /* reserved range */
   SNW_CORE_MAX = 255,
};

/* EVENT api code */
enum {
   SNW_EVENT_MIN = 1,
   SNW_EVENT_ICE_CONNECTED = SNW_EVENT_MIN,

   /* reserved range */
   SNW_EVENT_MAX = 255,
};

class WsClient {
public:
   int init(struct event_base *base, struct evdns_base *dns_base, SSL_CTX *ssl_ctx);

   /* ws methods */
   int do_http_handshake(char *host, char* service, char *path);
   void get_random(uint8_t *buf, size_t len);
   int send_message(enum evws_data_type data_type, const char* data, size_t len);
   void message_cb(WsClient *conn, enum evws_data_type, const char* data, int len, void *user_data);
   void close_cb(WsClient *conn, void *user_data);
   void error_cb(WsClient *conn, void *user_data, int code);
   
   /* ice methods */
   int ice_create_req();
   int ice_create_resp(Json::Value &root);
   int ice_connect_req();
   int ice_connect_resp(Json::Value &root);
   int ice_stop_req();
   int ice_stop_resp(Json::Value &root);
   int ice_sdp_req();
   int ice_sdp_resp(Json::Value &root);
   int ice_candidate_req();
   int ice_candidate_resp(Json::Value &root);
   int ice_publish_req();
   int ice_publish_resp(Json::Value &root);
   //int ice__req();
   //int ice__resp(Json::Value &root);
   
   int start_ice_process();
   int send_answer(Json::Value &root);
   int send_candidates();
   int play();

public:
   SSL_CTX *ssl_ctx;
   struct event_base *base; 
   struct evdns_base *dns_base;
   wslay_event_context_ptr wslay_ctx;
   std::fstream dev_urand_;

   int fd;
   SSL *ssl;
   struct bufferevent *bev;

   agent_t *agent;
   candidate_t *cands;

   uint8_t alive : 1;
   uint8_t is_offerred : 1;
   uint8_t ice_started : 1;
   uint8_t ice_gathering_done : 1;
   uint8_t has_remote_credentials : 1;
   uint8_t sent_candidates : 1;
   uint8_t reserved : 3;

   uint32_t id;
   uint32_t channelid;


   const char* subprotocol;
   void      *user_data;
   uint32_t   ip;
   uint32_t   port;
   uint32_t   flowid;

   // ice agent
   uint32_t  stream_id;
   char     *remote_user;
   char     *remote_pwd;

   // dtls stuff
   //dtls_ctx_t  *dtls_context;
};


#endif // _BENCHMARK_WSCLIENT_H_
