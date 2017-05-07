#include <unistd.h>
#include <string>
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

#define MAX_HTTP_HEADER_SIZE 8192

#define ERR_FAILURE 1
#define ERR_READ    2
#define ERR_WRITE   3

class WsClient;

#define DEBUG(fmt,...)\
    { log_write(__FUNCTION__, __LINE__,fmt, ##__VA_ARGS__); }
    //{ log_write(__FILE__, __LINE__,fmt, ##__VA_ARGS__); }

enum evws_data_type {
  EVWS_DATA_TEXT = 0,
  EVWS_DATA_BINARY = 1,
};

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

public:
   SSL_CTX *ssl_ctx;
   struct event_base *base; 
   struct evdns_base *dns_base;
   wslay_event_context_ptr wslay_ctx;
   std::fstream dev_urand_;

   int fd;
   SSL *ssl;
   agent_t *agent;
   struct bufferevent *bev;

   unsigned char alive : 1;

   uint32_t id;
   uint32_t channelid;


   const char* subprotocol;
   void      *user_data;
   uint32_t   ip;
   uint32_t   port;
   uint32_t   flowid;

   // ice agent
   uint32_t stream_id;
};


