#include <stdio.h>

#include "core.h"
#include "ice.h"
#include "ice_channel.h"
#include "ice_session.h"
#include "ice_stream.h"
#include "json/json.h"
#include "log.h"
#include "sdp.h"
#include "process.h"

void
snw_ice_api_handler(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = 0;
   struct list_head *p = 0, *n = 0;
   Json::Value root;
   Json::Reader reader;
   Json::FastWriter writer;
   std::string output;
   uint32_t msgtype = 0, api = 0;
   int ret;

   if (!ice_ctx) return;
   log = ice_ctx->log;

   ret = reader.parse(data,data+len,root,0);
   if (!ret) {
      ERROR(log,"error json format, s=%s",data);
      return;
   }

   DEBUG(log, "get ice msg, data=%s", data);
   try {
      msgtype = root["msgtype"].asUInt();
      if (msgtype != SNW_ICE) {
         ERROR(log, "wrong msg, msgtype=%u data=%s", msgtype, data);
         return;
      }
      api = root["api"].asUInt();
   } catch (...) {
      ERROR(log, "json format error, data=%s", data);
   }

   list_for_each(p,&ice_ctx->api_handlers.list) {
      snw_ice_api_t *a = list_entry(p,snw_ice_api_t,list);
      if (a->api == api) {
         DEBUG(log, "got api, api=%u", api);
         list_for_each(n,&a->handlers.list) {
            snw_ice_handlers_t *h = list_entry(n,snw_ice_handlers_t,list);
            h->handler(ice_ctx,data,len,flowid);
         }
      }
   }

   /*DEBUG(log, "num of apis, num=%u", api_num);
   for (int i=0; i<api_num; i++) {
      if (apis[i].api == api ) {
         apis[i].handler(ice_ctx,(char*)&root,0,flowid);
      }
   }*/

   return;
}

void
snw_ice_dispatch_msg(int fd, short int event,void* data) {
   static char buf[MAX_BUFFER_SIZE];
   snw_ice_context_t *ice_ctx = (snw_ice_context_t*)data;
   snw_context_t *ctx = (snw_context_t*)ice_ctx->ctx;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;
   int ret = 0; 
   //time_t cur_time = time(0);
   
   while (true) {
      len = 0;
      flowid = 0;
      cnt++;
      if (cnt >= 100) break;

      ret = snw_shmmq_dequeue(ctx->snw_core2ice_mq, buf, MAX_BUFFER_SIZE, &len, &flowid);
      //DEBUG(ice_ctx->log,"core2ice fd=%d, ret=%d, len=%u, flowid=%u",
      //              ctx->snw_core2ice_mq->_fd, ret, len, flowid);
      if ((len == 0 && ret == 0) || (ret < 0))
         return;
      
      buf[len] = 0; // null-terminated string
      snw_ice_process_msg(ice_ctx,buf,len,flowid);
      snw_ice_api_handler(ice_ctx,buf,len,flowid);
   }

   return;
}

//FIXME: uncomment remove this code
static char *server_pem = NULL;
static char *server_key = NULL;
SSL_CTX *
ice_srtp_init(snw_context_t *ctx, const char* pem, const char *key) {
   snw_log_t *log = 0;
   SSL_CTX  *server_ctx = 0;

   if (!ctx) return 0;
   log = ctx->log;

   DEBUG(log, "Using certificates: pem=%s, key%s", pem, key);

   server_pem = strdup(pem);
   server_key = strdup(key);
   SSL_library_init();
   SSL_load_error_strings();
   OpenSSL_add_all_algorithms();

   if (srtp_setup(server_pem, server_key) < 0) { 
      ERROR(log, "Failed to init dtls");
      exit(1);
   }
   server_ctx= srtp_get_ssl_ctx();

   return server_ctx;
}

void  
test_api1(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = 0;
   
   if (!ice_ctx) return;
   log = ice_ctx->log;
   
   DEBUG(log, "got api 1"); 

   return;
}

void  
test_api2(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = 0;
   
   if (!ice_ctx) return;
   log = ice_ctx->log;
   
   DEBUG(log, "got api 2"); 

   return;
}

void  
test_api3(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = 0;
   
   if (!ice_ctx) return;
   log = ice_ctx->log;
   
   DEBUG(log, "got api 3"); 

   return;
}


void 
snw_ice_init(snw_context_t *ctx) {
   static snw_ice_api_t apis[] = {
      {.list = {0,0}, .api = SNW_ICE_CREATE},
      {.list = {0,0}, .api = SNW_ICE_CONNECT},
      {.list = {0,0}, .api = SNW_ICE_STOP}
   };
   static snw_ice_handlers_t handlers[] = {
      {.list = {0,0}, .api = SNW_ICE_CREATE, .handler = test_api1},
      {.list = {0,0}, .api = SNW_ICE_CONNECT, .handler = test_api2},
      {.list = {0,0}, .api = SNW_ICE_STOP, .handler = test_api3}
   };
   struct list_head *p = 0;
   snw_ice_context_t *ice_ctx;
   snw_log_t *log = 0;
   struct event *q_event;
   int api_num = sizeof(apis)/sizeof(snw_ice_api_t);
   int handler_num = sizeof(handlers)/sizeof(snw_ice_handlers_t);
   
   if (!ctx) return;
   log = ctx->log;

   ice_ctx = (snw_ice_context_t *)malloc(sizeof(snw_ice_context_t));
   if (ice_ctx == 0) return;
   memset(ice_ctx,0,sizeof(snw_ice_context_t));
   ice_ctx->ctx = ctx;
   ice_ctx->log = ctx->log;

   snw_ice_sdp_init(ice_ctx);
   snw_ice_session_init(ice_ctx);
   snw_ice_channel_init(ice_ctx);
   snw_stream_mempool_init(ice_ctx);
   snw_component_mempool_init(ice_ctx);

   ice_ctx->rtcpmux_enabled = 0; 
   ice_ctx->ice_lite_enabled = 1; 
   ice_ctx->ipv6_enabled = 0; 
   ice_ctx->ice_tcp_enabled = 0;

   ice_srtp_init(ctx, ctx->wss_cert_file, ctx->wss_key_file);

   //DEBUG(ctx->log,"core2ice fd=%d",ctx->snw_core2ice_mq->_fd);
   q_event = event_new(ctx->ev_base, ctx->snw_core2ice_mq->_fd, 
         EV_TIMEOUT|EV_READ|EV_PERSIST, snw_ice_dispatch_msg, ice_ctx);
   event_add(q_event, NULL);   

   for (int j=0; j<handler_num; j++) {
      INIT_LIST_HEAD(&handlers[j].list);
   }

   INIT_LIST_HEAD(&ice_ctx->api_handlers.list);
   for (int i=0; i<api_num; i++) {
      //DEBUG(log, "api info, api=%u",apis[i].api);
      INIT_LIST_HEAD(&apis[i].list);
      INIT_LIST_HEAD(&apis[i].handlers.list);
      list_add_tail(&apis[i].list, &ice_ctx->api_handlers.list);
   }

   list_for_each(p, &ice_ctx->api_handlers.list) {
      snw_ice_api_t *h = list_entry(p,snw_ice_api_t,list);
      DEBUG(log, "api info, api=%u",h->api);
      for (int j=0; j<handler_num; j++) {
         if (h->api == handlers[j].api)
            list_add_tail(&handlers[j].list, &h->handlers.list);
      }
   }

   event_base_dispatch(ctx->ev_base);
   return;
}

void
ice_rtp_established(snw_ice_session_t *session) {
   snw_context_t *ctx = 0;
   snw_ice_context_t *ice_ctx = 0;
   snw_log_t *log = 0;
   Json::Value root,notify;
   Json::FastWriter writer;
   std::string output;

   if (!session) return;
   ice_ctx = session->ice_ctx;
   log = ice_ctx->log;
   ctx = (snw_context_t*)ice_ctx->ctx;


   DEBUG(log, "ice_rtp_established, flowid=%u", session->flowid);

   if ( IS_FLAG(session,ICE_SUBSCRIBER) ) {
      DEBUG(log, "send fir req");
      root["cmd"] = SNW_ICE;
      root["subcmd"] = SNW_ICE_FIR;
      root["flowid"] = session->flowid;

      output = writer.write(root);
      //enqueue_msg_to_mcd(output.c_str(),output.size(),session->flowid);
      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),session->flowid);
   } else if IS_FLAG(session,ICE_PUBLISHER) {
      // start recording a stream.
      /*char filename[256];
      time_t nowtime = time(NULL);
      DEBUG(log, "FIXME: start recording a stream");
      sprintf(filename, "%d_%ld_audio", session->roomid, nowtime);
      session->a_recorder = recorder_create("/home/tuyettt/record_video", 0, filename);
      sprintf(filename, "%d_%ld_video", session->roomid, nowtime);
      session->v_recorder = recorder_create("/home/tuyettt/record_video", 1, filename);*/
   } else if IS_FLAG(session,ICE_REPLAY) {
      // start replaying a stream.
      /*DEBUG("FIXME: start replaying a stream");
      record_start(session);*/
   }

   notify["msgtype"] = SNW_EVENT;
   notify["api"] = SNW_EVENT_ICE_CONNECTED;
   notify["flowid"] = session->flowid;
   notify["channelid"] = session->channelid;
   output = writer.write(notify);
   snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),session->flowid);


   return;
}




