#include <assert.h>

#include "core.h"
#include "snw_event.h"
#include "evws.h"
#include "types.h"
#include "websocket.h"
#include "wslistener.h"

static const char* subprotocols[] = {"default"};

void
close_handler(struct evwsconn* conn, void* user_data) {
  snw_event_t event;
  time_t cur_time;
  snw_websocket_context_t *ctx = (snw_websocket_context_t *)user_data;
  snw_context_t *g_ctx = (snw_context_t*)ctx->ctx;

  DEBUG(ctx->log,"close connection, flowid=%u",conn->flowid);

  cur_time = time(NULL);
  memset(&event,0,sizeof(event));
  event.magic_num = SNW_EVENT_MAGIC_NUM;
  event.event_type = snw_ev_disconnect;
  event.ipaddr = conn->ip;
  event.port = conn->port;
  event.flow = conn->flowid;
  event.other = bufferevent_getfd(conn->bev);

  snw_shmmq_enqueue(g_ctx->snw_net2core_mq,
      cur_time,&event,sizeof(event),conn->flowid);
  //g_mq_ccd_2_mcd->enqueue(cur_time, &event_header, CCD_EVENT_HEADER_LEN, conn->flowid);

  snw_flowset_freeid(ctx->flowset,conn->flowid);
  evwsconn_free(conn);
}


void
error_handler(struct evwsconn* conn, void* user_data) {
  snw_event_t event;
  time_t cur_time;
  snw_websocket_context_t *ctx = (snw_websocket_context_t *)user_data;
  snw_context_t *g_ctx = (snw_context_t*)ctx->ctx;
  
  DEBUG(ctx->log,"error connection, flowid=%u",conn->flowid);

  cur_time = time(NULL);
  memset(&event,0,sizeof(event));
  event.magic_num = SNW_EVENT_MAGIC_NUM;
  event.event_type = snw_ev_disconnect;
  event.ipaddr = conn->ip;
  event.port = conn->port;
  event.flow = conn->flowid;
  event.other = bufferevent_getfd(conn->bev);

  snw_shmmq_enqueue(g_ctx->snw_net2core_mq,
      cur_time,&event,sizeof(event),conn->flowid);
  //g_mq_ccd_2_mcd->enqueue(cur_time, &event_header, CCD_EVENT_HEADER_LEN, conn->flowid);

  snw_flowset_freeid(ctx->flowset,conn->flowid);
  evwsconn_free(conn);
} 

void message_handler(struct evwsconn* conn, enum evws_data_type data_type,
     const unsigned char* data, int len, void* user_data) {
  static char buf[MAX_BUFFER_SIZE];
  snw_event_t event;
  time_t cur_time;
  snw_websocket_context_t *ctx = (snw_websocket_context_t *)user_data;
  snw_context_t *g_ctx = (snw_context_t*)ctx->ctx;

  DEBUG(ctx->log, "message handler, flowid=%u, len=%u", conn->flowid, len);

  cur_time = time(NULL);
  memset(&event,0,sizeof(event));
  event.magic_num = SNW_EVENT_MAGIC_NUM;
  event.event_type = snw_ev_data;
  event.ipaddr = conn->ip;
  event.port = conn->port;
  event.flow = conn->flowid;
  event.other = bufferevent_getfd(conn->bev);

  memcpy(buf, &event, sizeof(event));
  memcpy(buf+sizeof(event),data,len);
   
  snw_shmmq_enqueue(g_ctx->snw_net2core_mq,
      cur_time,buf,len+sizeof(event),conn->flowid);
  //g_mq_ccd_2_mcd->enqueue(cur_time,buf,len+sizeof(header),conn->flowid);

  return;
}

void 
new_wsconnection(struct evwsconnlistener *wslistener, struct evwsconn *conn, 
                 struct sockaddr *address, int socklen, void* user_data) {
  uint32_t flowid = 0;
  snw_websocket_context_t *ctx = (snw_websocket_context_t *)user_data;


  flowid = snw_flowset_getid(ctx->flowset);
  if (flowid ==0) {
     ERROR(ctx->log, "connection limit reached");
     return;
  }

  DEBUG(ctx->log, "new connection, flowid=%u", flowid);
  conn->flowid = flowid;
  conn->ip = ((struct sockaddr_in*) address)->sin_addr.s_addr;
  conn->port = ((struct sockaddr_in*) address)->sin_port;
  snw_flowset_setobj(ctx->flowset,flowid,conn);

  evwsconn_set_cbs(conn, message_handler, close_handler, error_handler, ctx);

  return;
}

void ws_listener_error(struct evwsconnlistener *wslistener, void* user_data) {
  snw_context_t *ctx = (snw_context_t *)user_data;
  ERROR(ctx->log, "Error on Web Socket listener: %s", strerror(errno));
  exit(-1);
}


void
snw_websocket_init(snw_context_t *ctx) {
   struct sockaddr_in sin;
   struct evwsconnlistener* levws = 0;
   snw_websocket_context_t *ws_ctx = 0;
   snw_flowset_t *flowset = 0;

   ws_ctx = (snw_websocket_context_t*)malloc(sizeof(*ws_ctx));
   if (ws_ctx == 0) {
      ERROR(ctx->log, "can not create ws context");
      assert(0);
   }
   memset(ws_ctx,0,sizeof(*ws_ctx));
   ws_ctx->ctx = ctx;
   ws_ctx->ssl_ctx = ctx->ssl_ctx;
   ws_ctx->log = ctx->log;

   flowset = snw_flowset_init(10*1024);
   if (flowset == 0) {
      free(ws_ctx);
      assert(0);
   }
   ws_ctx->flowset = flowset;

   memset(&sin, 0, sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_addr.s_addr = inet_addr(ctx->wss_ip);
   sin.sin_port = htons(ctx->wss_port);

   DEBUG(ctx->log,"wss_ip: %s, wss_port: %d", ctx->wss_ip, ctx->wss_port);

   levws = evwsconnlistener_new_bind(ctx->ev_base, 
      new_wsconnection, ws_ctx,
      LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, 
      subprotocols, ctx->ssl_ctx,
      (struct sockaddr*)&sin, sizeof(sin));
   if (!levws) {
      ERROR(ctx->log, "Error creating Web Socket listener: %s", strerror(errno));
      exit(-1);
   }
   evwsconnlistener_set_error_cb(levws, ws_listener_error);
   event_base_dispatch(ctx->ev_base);

   return;
}



