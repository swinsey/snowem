#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "core/log.h"
#include "rtp/rtp_nack.h"
#include "rtp/rtp_rtcp.h"

#define USE_MODULE_RTCP
#define DECLARE_MODULE(name) &(g_rtp_##name##_module),
snw_rtp_module_t *g_rtp_rtcp_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef DECLARE_MODULE
#undef USE_MODULE_RTCP

int
snw_rtp_rtcp_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   snw_rtp_module_t *prev = &g_rtp_rtcp_module;
   int i = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   DEBUG(log,"init rtp rtcp");
   //FIXME init rtmp module
    
   for (i=0; ; i++) {
      snw_rtp_module_t *m = g_rtp_rtcp_modules[i];
      if (!m) break;

      DEBUG(log,"init module, name=%s",m->name);
      m->init(ctx);
      prev->next = m;
      prev = m;
   }

   return 0;
}


int
snw_rtp_rtcp_handle_pkg(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_log_t *log;
   rtp_hdr_t *hdr;
   char *p;
   int hdrlen = 0;
   int extlen = 0;
   int ret = 0;
   int dts = 0;
   int pts = 0;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;
   
   //parsing rtp header
   hdr = (rtp_hdr_t*)buf;
   hdrlen = MIN_RTP_HEADER_SIZE + 4*hdr->cc;
   if (hdr->x) {
      uint16_t id, len;
      p = buf + hdrlen; 
      id = ntohs(*((uint16_t*)p));
      len = ntohs(*((uint16_t*)(p+2)));
      extlen = 4 + 4*len;
      hdrlen += extlen;
   }


   DEBUG(log, "rtp rtcp info, seq=%u, start_ts=%llu, cur_ts=%llu, hdrlen=%u, extlen=%u, v=%u, x=%u, cc=%u, pt=%u, m=%u", 
         htons(hdr->seq), ctx->first_video_ts, ctx->current_ts, hdrlen, extlen, hdr->v, hdr->x, hdr->cc, hdr->pt, hdr->m);
   
   //HEXDUMP(log,(char*)buf,buflen,"rtp");
   return 0;
}

int
snw_rtp_rtcp_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_rtcp_module = { 
   "rtcp",
   0,/*ctx*/
   RTP_RTCP,
   snw_rtp_rtcp_init, 
   snw_rtp_rtcp_handle_pkg, 
   snw_rtp_rtcp_fini,
   0 /*next*/
};


