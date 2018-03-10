
#include "core/log.h"
#include "ice/ice_session.h"
#include "rtp/rtp.h"
#include "rtp/rtp_audio.h"
#include "rtp/rtp_rtcp.h"
#include "rtp/rtp_video.h"
#include "rtp/rtp_utils.h"

#define USE_MODULE_COMMON
snw_rtp_module_t *g_rtp_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef USE_MODULE_COMMON

int
snw_rtp_init(snw_ice_context_t *ctx) {
   snw_log_t *log;
   int i = 0;

   if (!ctx) return -1;
   log = ctx->log;
    
   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_modules[i];
      if (!m) break;

      DEBUG(log,"init module, name=%s",m->name);
      m->init(ctx);
   }
   return 0;
}

void
print_rtp_header(snw_log_t *log, char *buf, int buflen, const char *msg) {
   rtp_hdr_t *hdr;
   char *p;
   uint16_t id = 0;
   int hdrlen = 0;
   int extlen = 0;

   //parsing rtp header
   hdr = (rtp_hdr_t*)buf;
   hdrlen = snw_rtp_get_hdrlen(hdr);
   DEBUG(log, "rtp %s info, seq=%u, id=%u, hdrlen=%u, "
              "extlen=%u, v=%u, x=%u, cc=%u, pt=%u, m=%u", 
         msg, htons(hdr->seq), id, hdrlen, extlen, hdr->v, 
         hdr->x, hdr->cc, hdr->pt, hdr->m);

   return;
 
}

/* rfc 5764 section 5: multiplex dtls, rtp, and stun
   rfc 5761: multiplex rtp and rtcp */
int
snw_rtp_get_pkt_type(char* buf, int len) {
   rtp_hdr_t *header = 0;
   uint8_t c;
   
   if (!buf || len <= 0) {
      return UNKNOWN_PT;
   }

   c = (uint8_t)*buf;
   if ((c >= 20) && (c < 64)) {
      return DTLS_PT;
   }

   if (len < RTP_HEADER_SIZE) {
      return UNKNOWN_PT;
   }

   header = (rtp_hdr_t *)buf;
   if ((header->pt < 64) || (header->pt >= 96)) {
      return RTP_PT;
   } else if ((header->pt >= 64) && (header->pt < 96)) {
      return RTCP_PT;
   }

   return UNKNOWN_PT;
}


int
snw_rtp_handle_pkg_in(snw_rtp_ctx_t *ctx, char *buffer, int len) {
   snw_log_t *log;
   int i = 0;

   if (!ctx) return -1;
   log = ctx->log;

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_modules[i];
      if (!m) break;

      //DEBUG(log,"rtp handling, name=%s, m_pkt_type=%u, pkt_type=%u", 
      //         m->name, m->pkt_type, ctx->pkt_type);
      if (ctx->pkt_type & m->pkt_type)
         m->handle_pkg_in(ctx,buffer,len);
   }

   return 0;
}

int
snw_rtp_handle_pkg_out(snw_rtp_ctx_t *ctx, char *buffer, int len) {
   snw_log_t *log;
   int i = 0;

   if (!ctx) return -1;
   log = ctx->log;

   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_modules[i];
      if (!m) break;

      //DEBUG(log,"rtp handling, name=%s, m_pkt_type=%u, pkt_type=%u", 
      //         m->name, m->pkt_type, ctx->pkt_type);
      if (ctx->pkt_type & m->pkt_type)
         m->handle_pkg_out(ctx,buffer,len);
   }

   return 0;
}


int
snw_rtp_ctx_init(snw_rtp_ctx_t *ctx) {
   if (!ctx) return 0;
   
   memset(ctx,0,sizeof(*ctx));
   INIT_LIST_HEAD(&ctx->sender_stats.list);
   INIT_LIST_HEAD(&ctx->receiver_stats.list);

   return 0;
}




