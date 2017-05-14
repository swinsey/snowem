#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <stdlib.h>

#include <nettle/base64.h>
#include <nettle/sha.h>
#include <sofia-sip/sdp.h>

#include "json/json.h"
#include "sdp.h"
#include "util.h"
#include "wsclient.h"

bm_config g_config;

void ssl_readcb(struct bufferevent *bev, void *ptr)
{
    char buf[1024];
    int n;
    struct evbuffer *input = bufferevent_get_input(bev);
    while ((n = evbuffer_remove(input, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, n, stdout);
    }
}

void ssl_eventcb(struct bufferevent *bev, short events, void *ptr)
{
    SSL *ssl = bufferevent_openssl_get_ssl(bev);
    X509 *peer;
    if (events & BEV_EVENT_CONNECTED) {
        printf("Connect okay\n");
        if ((peer = SSL_get_peer_certificate(ssl)))
        {
            if (SSL_get_verify_result(ssl) == X509_V_OK)
            {
                /* The client sent a certificate which verified OK */
                printf("ok\n");
            }
        }
    } else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
        struct event_base *base = (struct event_base *)ptr;
        if (events & BEV_EVENT_ERROR) {
            int err = bufferevent_socket_get_dns_error(bev);
            if (err)
                printf("DNS error: %s\n", evutil_gai_strerror(err));
        }

        bufferevent_free(bev);
        event_base_loopexit(base, NULL);
    }
}

int WsClient::init(struct event_base *base, struct evdns_base *dns_base, SSL_CTX *ssl_ctx)
{
   this->base = base;
   this->dns_base = dns_base;
   this->ssl_ctx = ssl_ctx;
   this->bev = 0;
   this->ssl = 0;
   this->dev_urand_.open("/dev/urandom", std::ios::out | std::ios::in );
   this->alive = 0;
   this->is_offerred = 0;
   this->ice_started = 0;
   this->cands = 0;

   this->ssl = SSL_new(ssl_ctx);
   if (!ssl) {
      fprintf(stderr, "Null pointer.\n");
      return -2;
   }

   this->fd = socket(AF_INET, SOCK_STREAM, 0);
   if (this->fd < 0) {
      perror("socket");
      return 1;
   }

   this->bev = bufferevent_openssl_socket_new(base, this->fd, this->ssl, 
                 BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
   if (!this->bev) {
      fprintf(stderr, "Null pointer.\n");
      return -2;
   }

   this->fd = bufferevent_getfd(bev);
   fprintf(stderr, "this->fd=%d\n",this->fd);

   bufferevent_setcb(this->bev, ssl_readcb, NULL, ssl_eventcb, base);
   bufferevent_enable(this->bev, EV_READ|EV_WRITE);

   //evbuffer_add_printf(bufferevent_get_output(this->bev), "GET /\r\n");
   bufferevent_socket_connect_hostname(this->bev, dns_base, AF_UNSPEC, "media.peercall.vn", 443);

   return 0;
}

std::string base64(const std::string& src)
{
  base64_encode_ctx ctx;
  base64_encode_init(&ctx);
  int dstlen = BASE64_ENCODE_RAW_LENGTH(src.size());
  uint8_t *dst = new uint8_t[dstlen];
  base64_encode_raw(dst, src.size(),
                    reinterpret_cast<const uint8_t*>(src.c_str()));
  std::string res(&dst[0], &dst[dstlen]);
  delete [] dst;
  return res;
}

std::string get_random16()
{
  char buf[16];
  std::fstream f("/dev/urandom");
  f.read(buf, 16);
  return std::string(buf, buf+16);
}

#define STRNCASEEQL(data, lstring, len) \
  ((len) == sizeof((lstring)) - 1 && !strncasecmp((data), (lstring), (len)))

static void evwsconn_closing_cb(struct bufferevent *bev, void *conn_ptr) {
  WsClient *conn = (WsClient *)conn_ptr;
  conn->alive = 0;
  //if (conn->close_cb)
    conn->close_cb(conn, conn->user_data);
}
static void ws_error(WsClient *conn, int code) {
  conn->alive = 0;
  //if (conn->error_cb)
    conn->error_cb(conn, conn->user_data, code);
}

static void evwsconn_event_cb(struct bufferevent *bev, short events,
    void *conn_ptr) {
  WsClient *conn = (WsClient *)conn_ptr;
  if (events & BEV_EVENT_EOF) {
    //if (conn->close_cb)
      conn->close_cb(conn, conn->user_data);
  } else {
    ws_error(conn, ERR_FAILURE);
  }
}

static void evwsconn_do_write(WsClient *conn) {
  if (wslay_event_want_write(conn->wslay_ctx)) {
    if (wslay_event_send(conn->wslay_ctx) < 0) {
      ws_error(conn, ERR_WRITE);
      return;
    }
  }
  if (wslay_event_get_close_sent(conn->wslay_ctx)) {
    bufferevent_setcb(conn->bev, NULL, evwsconn_closing_cb, evwsconn_event_cb, conn);
  }
}

static void evwsconn_read_cb(struct bufferevent *bev, void *conn_ptr) {
  WsClient *conn = (WsClient *)conn_ptr;
  int ret;

  if ((ret = wslay_event_recv(conn->wslay_ctx)) < 0) {
    ws_error(conn, ERR_READ);
    return;
  }
  evwsconn_do_write(conn);
}

static ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data,
    size_t len, int flags, void *conn_ptr) {
  WsClient *conn = (WsClient *)conn_ptr;
  struct evbuffer* output = bufferevent_get_output(conn->bev);
  int ret;
  ret = evbuffer_add(output, data, len);
  if (ret < 0) {
    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    return -1;
  }
  return len;
}

static ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *buf,
    size_t len, int flags, void *conn_ptr) {
  WsClient *conn = (WsClient *)conn_ptr;
  struct evbuffer* input = bufferevent_get_input(conn->bev);
  int ret = evbuffer_remove(input, buf, len);
  if (ret < 0) {
    printf("error recv callback, ret=%d",ret);
    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    return -1;
  }
  //printf("wss recv msg, len=%lu, ret=%d, msg=%s\n", len, ret, buf);
  return ret;
}

int genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len,
                     void *user_data)
{
  WsClient *ws = (WsClient*)user_data;
  ws->get_random(buf, len);
  return 0;
}

static void on_msg_recv_callback(wslay_event_context_ptr ctx,
    const struct wslay_event_on_msg_recv_arg *arg, void *conn_ptr) {
  WsClient *conn = (WsClient *)conn_ptr;
  if(!wslay_is_ctrl_frame(arg->opcode)) {
    //if (conn->message_cb) {
      enum evws_data_type data_type;
      switch(arg->opcode) {
      case WSLAY_TEXT_FRAME: data_type = EVWS_DATA_TEXT; break;
      case WSLAY_BINARY_FRAME: data_type = EVWS_DATA_BINARY; break;
      default:
        fprintf(stderr, "Internal error, unexpected type: %d", arg->opcode);
        exit(-1);
        break;
      }
      conn->message_cb(conn, data_type, (const char*)arg->msg, arg->msg_length, conn->user_data);
    //}
  }
}

void evwsconn_send_message(WsClient *conn, enum evws_data_type data_type,
    const unsigned char* data, size_t len) {
  if (!conn->alive) {
    return;
  }
  struct wslay_event_msg msg = { 
      data_type == EVWS_DATA_TEXT ? WSLAY_TEXT_FRAME : WSLAY_BINARY_FRAME,
      data, len};
  if (wslay_event_queue_msg(conn->wslay_ctx, &msg) < 0) {
    ws_error(conn, ERR_FAILURE);
    return;
  }
  printf("send msg, msg=%s\n",data);
  evwsconn_do_write(conn);
}



static void pending_read(struct bufferevent *bev, void *ptr) {
   WsClient *client = (WsClient *)ptr;
   struct evbuffer* input = bufferevent_get_input(client->bev);
   struct evbuffer_ptr end = evbuffer_search(input, "\r\n\r\n", 4, NULL);
   size_t len = evbuffer_get_length(input);

   //WSS_DEBUG("pending read, len=%u,pos=%d",len,end.pos);
   char buf[4096] = {0};
   int ret = evbuffer_copyout(input,buf,len);
   //int ret = evbuffer_remove(input, buf, len);
   printf("recv msg, len=%lu, ret=%u, msg=%s\n", len, ret, buf);
   //hexdump(buf,len,"frame");

   if (end.pos == -1) {
      if (len > MAX_HTTP_HEADER_SIZE) {
         //remove_pending(pending);
         //free_pending(pending);
      }   
      return; // full request not yet found
   }
   evbuffer_drain(input, len);

   /*unsigned char* data = evbuffer_pullup(input, len);
   char accept_key[29];
   const char* subprotocol = NULL;
   const char* supported_subprotocols[] = {"default"};
   if (evaluate_websocket_handshake((char*)data, len,
         supported_subprotocols, accept_key, &subprotocol)) {
      printf("failed to handshake\n");
      //remove_pending(pending);
      //free_pending(pending);
      return;
   }*/

   printf("websocket connected!\n");
   client->alive = 1;
   struct wslay_event_callbacks callbacks = 
       {recv_callback, send_callback, genmask_callback, NULL, NULL, NULL, on_msg_recv_callback};
   wslay_event_context_client_init(&client->wslay_ctx, &callbacks, client);
   bufferevent_setcb(client->bev, evwsconn_read_cb, NULL, evwsconn_event_cb, client); 


   client->ice_create_req();   
   return;
}

int WsClient::do_http_handshake(char *host, char* service, char *path) {
   std::string client_key = base64(get_random16());

   bufferevent_setcb(this->bev, pending_read, NULL, NULL, this);
   struct evbuffer* output = bufferevent_get_output(this->bev);
   evbuffer_add_printf(output,
           "GET %s HTTP/1.1\r\n"
           "Host: %s:%s\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "\r\n",
           path, host, service, client_key.c_str());

   return 0;
}

int WsClient::send_message(enum evws_data_type data_type, const char* data, size_t len) {
  if (!this->alive) {
    return -1;
  }
  struct wslay_event_msg msg = { 
      data_type == EVWS_DATA_TEXT ? WSLAY_TEXT_FRAME : WSLAY_BINARY_FRAME,
      (const uint8_t*)data, len};
  if (wslay_event_queue_msg(this->wslay_ctx, &msg) < 0) {
    ws_error(this, ERR_FAILURE);
    return -1;
  }
  DEBUG("send msg, msg=%s",data);
  evwsconn_do_write(this);

  return 0;
}

int WsClient::ice_create_req() {
   Json::Value root;
   Json::FastWriter writer;
   std::string msg;

   root["msgtype"] = SNW_ICE;
   root["api"] = SNW_ICE_CREATE;
   root["uuid"] = "b27aec53-8815-42fa-bfb3-1299d90c269a";

   msg = writer.write(root);
   this->send_message(EVWS_DATA_TEXT,msg.c_str(),msg.size());
   return 0;
}

int WsClient::ice_create_resp(Json::Value &root) {

   try {
      this->id = root["id"].asUInt();
      this->channelid = root["channelid"].asUInt();
   } catch(...) {
   }
   ice_connect_req();
   return 0;
}

int WsClient::ice_connect_req() {
   Json::Value root;
   Json::FastWriter writer;
   std::string msg;

   DEBUG("ice connect, id=%u, channelid=%u", this->id, this->channelid);
   root["msgtype"] = SNW_ICE;
   root["api"] = SNW_ICE_CONNECT;
   root["id"] = this->id;
   root["channelid"] = this->channelid;
   root["name"] = "demo";
   root["callid"] = "xxxyyyzzz";

   msg = writer.write(root);
   this->send_message(EVWS_DATA_TEXT,msg.c_str(),msg.size());

   start_ice_process(); 
   return 0;
}

int WsClient::ice_connect_resp(Json::Value &root) {

   return 0;
}

int WsClient::ice_stop_req() {
   return 0;
}

int WsClient::ice_stop_resp(Json::Value &root) {
   return 0;
}

int WsClient::ice_candidate_req() {
   return 0;
}
candidate_t*
ice_remote_candidate_new(char *type, char *transport) {
   candidate_t* c = NULL;
         
   if(strcasecmp(transport, "udp")) {
      printf("skipping unsupported transport, s=%s", transport);
      return NULL;
   }     
            
   if(!strcasecmp(type, "host")) {
      c = candidate_new(ICE_CANDIDATE_TYPE_HOST);
   } else if (!strcasecmp(type, "srflx")) {
      c = candidate_new(ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
   } else if(!strcasecmp(type, "prflx")) {
      c = candidate_new(ICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
   } else if(!strcasecmp(type, "relay")) { 
      //c = candidate_new(ICE_CANDIDATE_TYPE_RELAYED);
      printf("relay candidate not supported, type:%s", type);
   } else {
      printf("Unknown remote candidate, type:%s", type);
   }     

   return c;
}

int WsClient::ice_candidate_resp(Json::Value &root) {
   const char *candidate;
   Json::FastWriter writer;
   std::string output;
   char foundation[16], transport[4], type[6]; 
   char ip[32], relip[32];
   uint32_t component_id, priority, port, relport;
   int ret = 0;

   try {
      candidate = root["candidate"]["candidate"].asString().c_str();
      DEBUG("ice remote candidate, s=%s", candidate);
      //output = writer.write(root);
      //DEBUG("ice remote candidate, s=%s",output.c_str());
   } catch(...) {
      DEBUG("json error");
   }

   if (strstr(candidate, "candidate:") == candidate) {
      candidate += strlen("candidate:");
   }

   ret = sscanf(candidate, "%15s %30u %3s %30u %31s %30u typ %5s %*s %31s %*s %30u",
                           foundation, &component_id, transport, &priority,
                           ip, &port, type, relip, &relport);

   DEBUG("parsing result, ret=%u, cid:%d sid:%d, type:%s, transport=%s, refaddr=%s:%d, addr=%s:%d",
          ret, component_id, 1/*stream->stream_id*/, type, transport, relip, relport, ip, port);

   if (ret < 7) {
      DEBUG("bad candidate");
      return -2;
   }
 
   candidate_t head; 
   candidate_t *c = 0;

   INIT_LIST_HEAD(&head.list); 
   c = ice_remote_candidate_new(type,transport);
   if (c != NULL) {
      c->component_id = 1;
      c->stream_id = 1;
      if (!strcasecmp(transport, "udp")) {
         c->transport = ICE_CANDIDATE_TRANSPORT_UDP;
      } else {
         DEBUG("wrong transport, s=%s",transport);
         candidate_free(c);
         return -1;
      }

      strncpy(c->foundation, foundation, ICE_CANDIDATE_MAX_FOUNDATION);
      c->priority = priority;
      address_set_from_string(&c->addr, ip); 
      address_set_port(&c->addr, port);
      DEBUG("setting up remote credentials, user=%s, pwd=%s", 
            this->remote_user, this->remote_pwd);
      c->username = strdup(this->remote_user);
      c->password = strdup(this->remote_pwd);
      address_set_from_string(&c->base_addr, relip);
      address_set_port(&c->base_addr, relport);

      if (this->has_remote_credentials == 0) {
         ice_agent_set_remote_credentials(this->agent,1,this->remote_user,this->remote_pwd);
         this->has_remote_credentials = 1;
      }

      list_add(&c->list, &head.list);
      ice_agent_set_remote_candidates(this->agent,1,1,&head);
   }

   return 0;
}

int WsClient::ice_publish_req() {
   return 0;
}

int WsClient::ice_publish_resp(Json::Value &root) {
   return 0;
}

void log_callback(int severity, const char* msg, void* data) {
   DEBUG("%s",msg);
   return;
}

void
print_candidates(candidate_t *cands)
{
  static const char *candidate_type_name[] = {"host", "srflx", "prflx", "relay"};
  struct list_head *pos;
  char ipaddr[INET6_ADDRSTRLEN];

  DEBUG("candidate info: ");
  list_for_each(pos,&cands->list) {
     candidate_t *c = list_entry(pos,candidate_t,list);
     address_to_string(&c->addr, ipaddr);
     DEBUG(" --- foundation=%s, priority=%u, ipaddr=%s, port=%u, type=%s",
        c->foundation,
        c->priority,
        ipaddr,
        address_get_port(&c->addr),
        candidate_type_name[c->type]);
  }

  return;     
}

int WsClient::ice_sdp_req() {
   return 0;
}

#define OPUS_PT   111
#define VP8_PT    100
static char*
generate_sdp_answer(int sendonly) {
   static const char *sdp_template = 
         "v=0\r\n" "o=- %lu %lu IN IP4 127.0.0.1\r\n"
         "s=%s\r\n"
         "t=0 0\r\n"
         "a=group:BUNDLE audio video\r\n"
         "a=msid-semantic:PeerCall Semantic\r\n"
         "%s%s";
   static  const char *audio_mline_template = 
         "m=audio 9 RTP/SAVPF %d\r\n"
         "c=IN IP4 0.0.0.0\r\n"
         "a=rtcp:9 IN IP4 0.0.0.0\r\n"
         "a=ice-ufrag:VJq2\r\n"
         "a=ice-pwd:qpmMq1l7h4Y8N/lLpISXguX7\r\n"
         "a=fingerprint:sha-256 %s\r\n"
         "a=setup:active\r\n"
         "a=mid:audio\r\n"
         "a=%s\r\n"
         "a=rtcp-mux\r\n"
         "a=rtpmap:%d opus/48000/2\r\n"
         "a=ssrc:%u cname:peercallagentaudio\r\n"
         "a=ssrc:%u msid:peercallagent peercallagenta0\r\n"
         "a=ssrc:%u mslabel:peercallagent\r\n"
         "a=ssrc:%u label:peercallagenta0\r\n";

   static  const char *video_mline_template = 
         "m=video 9 RTP/SAVPF %d\r\n"
         "c=IN IP4 0.0.0.0\r\n"
         "a=rtcp:9 IN IP4 0.0.0.0\r\n"
         "a=ice-ufrag:VJq2\r\n"
         "a=ice-pwd:qpmMq1l7h4Y8N/lLpISXguX7\r\n"
         "a=fingerprint:sha-256 %s\r\n"
         "a=setup:active\r\n"
         "a=mid:video\r\n"
         "a=%s\r\n"
         "a=rtcp-mux\r\n"
         "a=rtpmap:%d VP8/90000\r\n"
         "a=rtcp-fb:%d ccm fir\r\n"
         "a=rtcp-fb:%d nack\r\n"
         "a=rtcp-fb:%d nack pli\r\n"
         "a=rtcp-fb:%d goog-remb\r\n"
         "a=ssrc:%u cname:peercallagentvideo\r\n"
         "a=ssrc:%u msid:peercallagent peercallagentv0\r\n"
         "a=ssrc:%u mslabel:peercallagent\r\n"
         "a=ssrc:%u label:peercallagentv0\r\n";
         

   static char sdp[2*1024], audio_mline[512], video_mline[1024];
   int random_ssrc_a = random();
   int random_ssrc_v = random();
   int ret = 0;

   DEBUG("sendonly=%u",sendonly);

   memset(audio_mline,0,512);
   snprintf(audio_mline, 512, audio_mline_template,
            OPUS_PT, 
            g_config.dtls_params->local_fingerprint,
            sendonly ? "sendonly" : "sendrecv", 
            OPUS_PT, 
            random_ssrc_a,
            random_ssrc_a,
            random_ssrc_a,
            random_ssrc_a);

   memset(video_mline,0,1024);
   snprintf(video_mline, 1024, video_mline_template,
            VP8_PT, 
            g_config.dtls_params->local_fingerprint,
            sendonly ? "sendonly" : "sendrecv",
            VP8_PT, 
            VP8_PT, 
            VP8_PT, 
            VP8_PT, 
            VP8_PT,
            random_ssrc_v,
            random_ssrc_v,
            random_ssrc_v,
            random_ssrc_v);

   memset(sdp,0,2*1024);
   snprintf(sdp, 2*1024, sdp_template,
            /*v=0*/get_real_time(), get_real_time(),
            /*s=*/"PeerCall Agent", 
            audio_mline, 
            video_mline);

   //DEBUG("sdp anser, s=%s",sdp);
   //session->sdp = strdup(sdp);
   //ret = snw_ice_session_setup(ice_ctx, session, 0, (char *)sdp);
   //if (ret < 0) {
   //   DEBUG("Error setting ICE locally, ret=%d",ret);
   //   return -4;
   //}

   return strdup(sdp);
}

int WsClient::send_candidates() {
   Json::Value root,cand;
   Json::FastWriter writer;
   std::string output;
   char buffer[100];
   static const char *candidate_type_name[] = {"host", "srflx", "prflx", "relay"};
   struct list_head *pos;
   char ipaddr[INET6_ADDRSTRLEN];

   DEBUG("send candidate");
   list_for_each(pos,&cands->list) {
     candidate_t *c = list_entry(pos,candidate_t,list);
     //char address[ICE_ADDRESS_STRING_LEN];
     //address_to_string(&(c->addr), (char *)&address);
     address_to_string(&c->addr, ipaddr);
     DEBUG(" --- foundation=%s, priority=%u, ipaddr=%s, port=%u, type=%s",
        c->foundation,
        c->priority,
        ipaddr,
        address_get_port(&c->addr),
        candidate_type_name[c->type]);
     if (!strcasecmp(c->foundation,"1")) {
        memset(buffer,0,100);
        snprintf(buffer, 100, "candidate:%s %d %s %d %s %d typ host generation 0",
              c->foundation,
              1,
              "udp",
              c->priority, 
              ipaddr, 
              address_get_port(&c->addr));
        root["msgtype"] = SNW_ICE;
        root["api"] = SNW_ICE_CANDIDATE;
        root["roomid"] = 0;
        root["callid"] = "callid";
        cand["candidate"] = buffer;
        cand["label"] = 0;
        cand["type"] = "candidate";
        cand["id"] = "audio";
        root["candidate"] = cand;
        output = writer.write(root);
        DEBUG("audio candidate info, s=%s",output.c_str());
        this->send_message(EVWS_DATA_TEXT,output.c_str(),output.size());
     }

     if (!strcasecmp(c->foundation,"2")) {
        memset(buffer,0,100);
        snprintf(buffer, 100, "candidate:%s %d %s %d %s %d typ host generation 0",
              c->foundation,
              1,
              "udp",
              c->priority, 
              ipaddr, 
              address_get_port(&c->addr));
        root["msgtype"] = SNW_ICE;
        root["api"] = SNW_ICE_CANDIDATE;
        root["roomid"] = 0;
        root["callid"] = "callid";
        cand["candidate"] = buffer;
        cand["label"] = 1;
        cand["type"] = "candidate";
        cand["id"] = "video";
        root["candidate"] = cand;
        output = writer.write(root);
        DEBUG("video candidate info (not send), s=%s",output.c_str());
        //this->send_message(EVWS_DATA_TEXT,output.c_str(),output.size());
     }

   }


   //print_candidates(this->cands);


   return 0;
}

int WsClient::send_answer(Json::Value &root) {
   Json::Value type, jsep, sdp;
   Json::FastWriter writer;
   sdp_parser_t *parser = 0;
   const char *jsep_type, *jsep_sdp;
   std::string output;


   try {
      jsep = root["sdp"];
      if (!jsep.isNull()) {
         type = jsep["type"];
         jsep_type = type.asString().c_str();
         DEBUG("get sdp type, type=%s",jsep_type);
      } else {
         output = writer.write(root);
         DEBUG("failed to get sdp type, root=%s",output.c_str());
         goto jsondone;
      }

      if (!strcasecmp(jsep_type, "answer")) {
         // only handle answer
         DEBUG( "not handling answer, type=%s", jsep_type);
         goto jsondone;
      } else if(!strcasecmp(jsep_type, "offer")) {
         DEBUG("got sdp offer, offer=%s",jsep_type);
      } else {
         DEBUG("unknown message type, type=%s", jsep_type);
         goto jsondone;
      }
      sdp = jsep["sdp"];
      if (sdp.isNull() || !sdp.isString() ) {
         DEBUG("sdp not found");
         goto jsondone;
      }

      jsep_sdp = strdup(sdp.asString().c_str()); //FIXME: don't use strdup
      //DEBUG("Remote SDP, s=%s", jsep_sdp);

      parser = sdp_get_parser(jsep_sdp);     
      if (!parser) {
         DEBUG("parser is null");
         return 0;
      }

      //get_remote_credentials(parser);
      sdp_session_t *parsed_sdp = sdp_session(parser);
      sdp_media_t *m = parsed_sdp->sdp_media;
      while(m) {
         sdp_attribute_t *a = m->m_attributes;
         while(a) {
            if (!strcasecmp(a->a_name,"ice-ufrag")) {
               DEBUG("get remote user: name=%s, value=%s", a->a_name, a->a_value);
               if (this->remote_user) free(this->remote_user);
               this->remote_user = strdup(a->a_value);
            }
            if (!strcasecmp(a->a_name,"ice-pwd")) {
               DEBUG("get remote pwd: name=%s, value=%s", a->a_name, a->a_value);
               if (this->remote_pwd) free(this->remote_pwd);
               this->remote_pwd = strdup(a->a_value);
            }
            a = a->a_next;
         }
         m = m->m_next;
      }

      char* sdp_answer = generate_sdp_answer(0);
      //DEBUG("generate and send answer, s=%s",sdp_answer);//snw_ice_generate_sdp

      Json::Value answer, json_sdp;
      answer["msgtype"] = SNW_ICE;
      answer["api"] = SNW_ICE_SDP;
      answer["roomid"] = 1443712566;
      json_sdp["sdp"] = sdp_answer;
      json_sdp["type"] = "answer";
      answer["sdp"] = json_sdp;
      output = writer.write(answer);
      DEBUG("generate and send answer, s=%s",output.c_str());//snw_ice_generate_sdp
      this->send_message(EVWS_DATA_TEXT,output.c_str(),output.size());


   } catch(...) {
      DEBUG("error: generate and send offer");
   }

   this->send_candidates();

jsondone:
   return 0;
}

int WsClient::ice_sdp_resp(Json::Value &root) {
   //FIXME: check wether sdp is offer.
   this->is_offerred = 1;
   if (!this->ice_started) {
      DEBUG("ice process starting ...");
      start_ice_process();
   } else {
      send_answer(root);
   }
   return 0;
}

static void
cb_candidate_gathering_done(agent_t *agent, uint32_t _stream_id, void* data) {
   WsClient *client = (WsClient *)data; 
   candidate_t *cands = NULL;
   char *local_ufrag = NULL;
   char *local_password = NULL;
   uint32_t component_id = 1;

   DEBUG("candidate gathering done, sid=%u",_stream_id);
   if (ice_agent_get_local_credentials(agent, _stream_id,
       &local_ufrag, &local_password) != ICE_OK)
     goto end;

   DEBUG("candidate info, ufrag=%s, pass=%s", local_ufrag, local_password);
   cands = ice_agent_get_local_candidates(agent, _stream_id, component_id);
   if (cands == NULL)
      goto end;
   
   client->cands = cands;
   print_candidates(cands);
   /*list_for_each(pos,&cands->list) {
      candidate_t *c = list_entry(pos,candidate_t,list);
      address_to_string(&c->addr, ipaddr);
      DEBUG(" --- foundation=%s, priority=%u, ipaddr=%s, port=%u, type=%s",
        c->foundation,
        c->priority,
        ipaddr,
        address_get_port(&c->addr),
        candidate_type_name[c->type]);
   }*/
   
   if (client->is_offerred) {
      DEBUG("FIXME: sending candidate");
   }
   client->ice_gathering_done = 1;   
   return;

end:
   if (local_ufrag)
      free(local_ufrag);
   if (local_password)
      free(local_password);
   if (cands)
      candidate_free(cands);
      
   return;


  /*struct bufferevent *bev;
  bev = bufferevent_socket_new(agent->base, 0, BEV_OPT_CLOSE_ON_FREE);
  bufferevent_setcb(bev, read_data_cb, NULL, event_cb, agent);
  bufferevent_enable(bev, EV_READ|EV_WRITE);
  //printf("event base dispatch\n"); 
  event_base_dispatch(agent->base);*/

  fflush (stdout);
}

static void
cb_new_selected_pair(agent_t *agent, uint32_t _stream_id,
    uint32_t component_id, char *lfoundation,
    char *rfoundation, void *data) {
  DEBUG("SIGNAL: selected pair %s %s", lfoundation, rfoundation);
}

static void
cb_component_state_changed(agent_t *agent, uint32_t _stream_id,
    uint32_t component_id, uint32_t state,
    void *data) {

  static const char *state_name[] = {"disconnected", "gathering", "connecting",
                                    "connected", "ready", "failed"};
  DEBUG("SIGNAL: state changed %d %d %s[%d]n",
      _stream_id, component_id, state_name[state], state);

  if (state == ICE_COMPONENT_STATE_READY) {
    candidate_t *local, *remote;

    // Get current selected candidate pair and print IP address used
    if (ice_agent_get_selected_pair(agent, _stream_id, component_id,
                &local, &remote) == ICE_OK) {
      char ipaddr[INET6_ADDRSTRLEN];

      address_to_string(&local->addr, ipaddr);
      DEBUG("Negotiation complete: ([%s]:%d,",
          ipaddr, address_get_port(&local->addr));
      address_to_string(&remote->addr, ipaddr);
      DEBUG(" ---> [%s]:%d)", ipaddr, address_get_port(&remote->addr));
    }

    // Listen to stdin and send data written to it
    DEBUG("FIXME: Send lines to remote (Ctrl-D to quit):\n");
    //g_io_add_watch(io_stdin, G_IO_IN, stdin_send_data_cb, agent);
  } else if (state == ICE_COMPONENT_STATE_FAILED) {
     DEBUG("FIXME: component state failed");
  }

  return;
}

static void
cb_nice_recv(agent_t *agent, uint32_t _stream_id, uint32_t component_id,
    char *buf, uint32_t len, void *data)
{
  DEBUG("cb_nice_recv: %.*s", len, buf);
  return;
}


int WsClient::start_ice_process() {
   //int8_t controlling = 1;
   ice_set_log_callback(log_callback,0);
   this->agent = ice_agent_new(this->base, ICE_COMPATIBILITY_RFC5245, 0);

   if (agent == NULL) {
      DEBUG("Failed to create agent");
      exit(-1);
   }

   DEBUG("set up ice agent");
   ice_set_candidate_gathering_done_cb(this->agent, cb_candidate_gathering_done, this);
   ice_set_new_selected_pair_cb(this->agent, cb_new_selected_pair, this);
   ice_set_component_state_changed_cb(this->agent, cb_component_state_changed, this);

   this->stream_id = ice_agent_add_stream(agent, 1);
   if (stream_id <= 0) {
      DEBUG("Failed to add stream, stream_id=%u",this->stream_id);
      return -1;
   }
   ice_agent_attach_recv(this->agent, stream_id, 1, cb_nice_recv, NULL);

   this->ice_started = 1;
   if (ice_agent_gather_candidates(agent, stream_id) != ICE_OK) {
      DEBUG("Failed to start candidate gathering");
      return -1;
   }

   //FIXME: set remote credentials 
   this->has_remote_credentials = 0;
   return 0;
}

void WsClient::message_cb(WsClient *conn, enum evws_data_type, 
      const char* data, int len, void *user_data) {
   Json::Value root;
   Json::Reader reader;
   uint32_t msgtype = 0;
   uint32_t api = 0;
   int ret = -1;

   DEBUG("message cb, data=%s\n", data);

   try {
      ret = reader.parse(data,data+len,root,0);
      if (!ret) {
         DEBUG("failed to parse json, ret=%d", ret);
         return;
      }
      msgtype = root["msgtype"].asUInt();
      api = root["api"].asUInt();
      if (msgtype != SNW_ICE) {
         DEBUG("wrong msgtype, msgtype=%u",msgtype);
         return;
      }

      switch(api) {
         case SNW_ICE_CREATE:
            ice_create_resp(root);
            break;
         case SNW_ICE_CONNECT:
            ice_connect_resp(root);
            break;
         case SNW_ICE_SDP:
            ice_sdp_resp(root);
            break;
         case SNW_ICE_CANDIDATE:
            ice_candidate_resp(root);
            break;
         default:
            DEBUG("unknow api, api=%u", api);
            break;
      }
   } catch (...) {
      DEBUG("error json, data=%s",data);
   }

   return;
}

void WsClient::close_cb(WsClient *conn, void *user_data) {
   printf("close cb\n");
   return;
}

void WsClient::error_cb(WsClient *conn, void *user_data, int code) {
   printf("error cb, code=%d\n",code);
   return;
}

void WsClient::get_random(uint8_t *buf, size_t len) {
  dev_urand_.read((char*)buf, len);
}



