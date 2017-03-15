#include <stdio.h>
#include <sofia-sip/sdp.h>

#include "core.h"
#include "ice.h"
#include "log.h"
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
snw_ice_init(snw_context_t *ctx) {
   
   DEBUG(ctx->log,"ice init test");

   if (ctx == NULL)
      return;

   ctx->ice_ctx = (snw_ice_context_t *)malloc(sizeof(snw_ice_context_t));
   if (ctx->ice_ctx == 0)
      return;
   ctx->ice_ctx->log = ctx->log;

   ice_sdp_init(ctx->ice_ctx);

   ice_session_init(ctx->ice_ctx);
   /*cache_handle_init(0x91001,10,100,1);

   stream_mempool_init();
   component_mempool_init();
   memset(&g_ice_context,0,sizeof(g_ice_context));
   g_ice_context.rtcpmux_enabled = 0; 
   g_ice_context.ice_lite_enabled = 1; 
   g_ice_context.ipv6_enabled = 0; 
   g_ice_context.ice_tcp_enabled = 0; */

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

