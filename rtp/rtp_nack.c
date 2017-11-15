#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "core/log.h"
#include "rtp/rtp_nack.h"

int
snw_rtp_nack_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   DEBUG(log,"init rtp nack");
   //FIXME init nack module

   return 0;
}


int
snw_rtp_nack_handle_pkg(void *data, char *buf, int buflen) {
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

   DEBUG(log, "rtp nack info, seq=%u, start_ts=%llu, cur_ts=%llu, hdrlen=%u, extlen=%u, v=%u, x=%u, cc=%u, pt=%u, m=%u", 
         htons(hdr->seq), ctx->first_video_ts, ctx->current_ts, hdrlen, extlen, hdr->v, hdr->x, hdr->cc, hdr->pt, hdr->m);
   
   //HEXDUMP(log,(char*)buf,buflen,"rtp");
   return 0;
}

int
snw_rtp_nack_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_nack_module = { 
   "nack",
   0,/*ctx*/
   RTP_RTCP,
   snw_rtp_nack_init, 
   snw_rtp_nack_handle_pkg, 
   snw_rtp_nack_fini,
   0 /*next*/
};


