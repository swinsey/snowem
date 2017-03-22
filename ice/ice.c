#include <stdio.h>

#include "core.h"
#include "ice.h"
#include "ice_session.h"
#include "ice_stream.h"
#include "log.h"
#include "sdp.h"
#include "process.h"

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
   while (true) {
      len = 0;
      flowid = 0;
      cnt++;
      if (cnt >= 100) break;

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

   snw_ice_sdp_init(ice_ctx);
   ice_session_init(ice_ctx);
   snw_stream_mempool_init(ice_ctx);
   snw_component_mempool_init(ice_ctx);
   ice_ctx->rtcpmux_enabled = 0; 
   ice_ctx->ice_lite_enabled = 1; 
   ice_ctx->ipv6_enabled = 0; 
   ice_ctx->ice_tcp_enabled = 0;

   DEBUG(ctx->log,"core2ice fd=%d",ctx->snw_core2ice_mq->_fd);
   q_event = event_new(ctx->ev_base, ctx->snw_core2ice_mq->_fd, 
         EV_TIMEOUT|EV_READ|EV_PERSIST, snw_ice_dispatch_msg, ice_ctx);
   event_add(q_event, NULL);   

   event_base_dispatch(ctx->ev_base);
   return;
}

/*
void
ice_srtp_handshake_done(snw_ice_session_t *session, ice_component_t *component) {

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
*/



