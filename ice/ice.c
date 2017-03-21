#include <stdio.h>

#include <sofia-sip/sdp.h>

#include "core.h"
#include "ice.h"
#include "json/json.h"
#include "log.h"
#include "module.h"
#include "session.h"

static su_home_t *g_home = NULL;

int ice_sdp_init(snw_ice_context_t *ctx) {

   DEBUG(ctx->log,"sdp initialization");
   g_home = (su_home_t*)su_home_new(sizeof(su_home_t));
   if(su_home_init(g_home) < 0) {
      ERROR(ctx->log,"Ops, error setting up sofia-sdp?");
      return -1; 
   }   
   return 0;
}

void ice_sdp_deinit(void) {
   su_home_deinit(g_home);
   su_home_unref(g_home);
   g_home = NULL;
}

sdp_parser_t *ice_sdp_get_parser(snw_ice_context_t *ctx, const char *sdp) {
   sdp_parser_t *parser = NULL;

   if (!sdp) {
      ERROR(ctx->log,"sdp is null, sdp=%p",sdp);
      return NULL;
   }   

   parser = sdp_parse(g_home, sdp, strlen(sdp), 0); 
   return parser;
}

void
snw_ice_create(snw_ice_context_t *ice_ctx, Json::Value root, uint32_t flowid) {
   snw_context_t *ctx = (snw_context_t*)ice_ctx->ctx;
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;

   try {
      root["id"] = flowid;
      root["sessionid"] = flowid;
      root["rc"] = 0;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->snw_ice2core_mq,0,output.c_str(),output.size(),flowid);

      DEBUG(log,"ice create, mq=%p, flowid=%u, len=%u, res=%s", 
                ctx->snw_ice2core_mq, flowid, output.size(), output.c_str());

   } catch (...) {
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   return;
}

void
snw_ice_process_msg(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   Json::Value root;
   Json::Reader reader;
   Json::FastWriter writer;
   std::string output;
   uint32_t msgtype = 0, api = 0;
   int ret;

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

   switch(api) {
      case SNW_ICE_CREATE:
         snw_ice_create(ice_ctx,root,flowid);
         break;

      default:
         ERROR(log, "unknow api, api=%u", api);
         break;
   }




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
   
   DEBUG(ctx->log,"ice dispatch msg");
   while(true){
     len = 0;
     flowid = 0;
     cnt++;
     //if ( cnt % 10000 == 0 ) break;
     if ( cnt >= 100) {
         //DEBUG("dequeue_from_ccd: breaking the loop, cnt=%d", cnt);
         break;
     }

     ret = snw_shmmq_dequeue(ctx->snw_core2ice_mq, buf, MAX_BUFFER_SIZE, &len, &flowid);
     DEBUG(ice_ctx->log,"core2ice fd=%d, ret=%d, len=%u, flowid=%u",
                    ctx->snw_core2ice_mq->_fd, ret, len, flowid);
     if ( (len == 0 && ret == 0) || (ret < 0) )
        return;

     snw_ice_process_msg(ice_ctx,buf,len,flowid);
   }

   return;
}


void 
snw_ice_init(snw_context_t *ctx) {
   snw_ice_context_t *ice_ctx;
   struct event *q_event;
   
   if (ctx == NULL)
      return;

   ice_ctx = (snw_ice_context_t *)malloc(sizeof(snw_ice_context_t));
   if (ice_ctx == 0)
      return;
   ice_ctx->ctx = ctx;
   ice_ctx->log = ctx->log;

   ice_sdp_init(ice_ctx);

   ice_session_init(ice_ctx);
   /*cache_handle_init(0x91001,10,100,1);

   stream_mempool_init();
   component_mempool_init();
   memset(&g_ice_context,0,sizeof(g_ice_context));
   g_ice_context.rtcpmux_enabled = 0; 
   g_ice_context.ice_lite_enabled = 1; 
   g_ice_context.ipv6_enabled = 0; 
   g_ice_context.ice_tcp_enabled = 0; */

   DEBUG(ctx->log,"core2ice fd=%d",ctx->snw_core2ice_mq->_fd);
   q_event = event_new(ctx->ev_base, ctx->snw_core2ice_mq->_fd, 
         EV_TIMEOUT|EV_READ|EV_PERSIST, snw_ice_dispatch_msg, ice_ctx);
   event_add(q_event, NULL);   

   event_base_dispatch(ctx->ev_base);
   return;
}

void
snw_ice_start(snw_context_t *ctx, snw_connection_t *conn, Json::Value *root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;

   try {
      (*root)["id"] = conn->flowid;
      (*root)["sessionid"] = conn->flowid;
      (*root)["rc"] = 0;
      output = writer.write(*root);
      //snw_shmmq_enqueue(ctx->snw_core2net_mq,0,output.c_str(),output.size(),conn->flowid);

      DEBUG(log,"ice create, mq=%p, flowid=%u, len=%u, res=%s", 
                ctx->snw_core2net_mq, conn->flowid, output.size(), output.c_str());

   } catch (...) {
      ERROR(log, "json format error, data=%s", output.c_str());
      return;
   }

   return;
}


void
ice_srtp_handshake_done(ice_session_t *session, ice_component_t *component) {

   if (!session || !component)
      return;

   ICE_DEBUG2("srtp handshake is completed, cid=%u, sid=%u",
         component->component_id, component->stream_id);

   struct list_head *n,*p;
   list_for_each(n,&session->streams.list) {
      ice_stream_t *s = list_entry(n,ice_stream_t,list);
      if (s->disabled)
         continue;
      list_for_each(p,&s->components.list) {
         ice_component_t *c = list_entry(p,ice_component_t,list);
         ICE_DEBUG2("checking component, sid=%u, cid=%u",s->stream_id, c->component_id);
         if (!c->dtls || !c->dtls->srtp_valid) {
            ICE_DEBUG2("component not ready, sid=%u, cid=%u",s->stream_id, c->component_id);
            return;
         }    
      }    
   }

   SET_FLAG(session, WEBRTC_READY);
   //ice_rtp_established(session); //FIXME: uncomment
   return;
}

