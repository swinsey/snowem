#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "core/log.h"
#include "rtp/rtcp.h"
#include "rtp/rtp_nack.h"
#include "rtp/rtp_rtcp.h"

#define USE_MODULE_RTCP
snw_rtp_module_t *g_rtp_rtcp_modules[] = {
   #include "rtp_module_dec.h"
   0
};
#undef USE_MODULE_RTCP

int
snw_rtp_rtcp_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
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
   }

   return 0;
}

int
snw_rtp_rtcp_fb_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log;
  
   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   DEBUG(log,"rtcp transport layer feedback msg");
   if (rtcp->hdr.rc == RTCP_RTPFB_GENERIC_FMT) {
      snw_rtcp_nack_handle_pkg(ctx,rtcp);
   } else {
      WARN(log, "unknown rtcp-fb format, fmt=%u", rtcp->hdr.rc);
   }

   return 0;
}

int
snw_rtp_rtcp_psfb_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   DEBUG(log,"rtcp payload-specific layer feedback msg");

   switch (rtcp->hdr.rc) {
      case RTCP_PSFB_PLI_FMT:
         // rfc 4585 6.3.1
         //store the last key frame, and send it
         break;
      case RTCP_PSFB_SLI_FMT:
         // rfc 4585 6.3.2
         break;
      case RTCP_PSFB_RPSI_FMT:
         // rfc 4585 6.3.3
         break;

      case RTCP_PSFB_FIR_FMT:
         // rfc 5104 4.3.1
         break;
      case RTCP_PSFB_TSTR_FMT:
         // rfc 5104 4.3.2
         break;
      case RTCP_PSFB_TSTN_FMT:
         // rfc 5104 4.3.3
         break;
      case RTCP_PSFB_VBCM_FMT:
         // rfc 5104 4.3.4
         break;

      case RTCP_PSFB_REMB_FMT:
         break;

      default:
         break;
   }

   return 0;
}

int
snw_rtp_rtcp_fir_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   DEBUG(log,"rtcp fir msg");

   return 0;
}

int
snw_rtp_rtcp_sr_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;
   snw_rtcp_sr_t *sr = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   sr = &rtcp->pkt.sr;
   DEBUG(log,"rtcp sr, ssrc=%u , ntp_secs=%u, ntp_frac=%u, rtp_ts=%u, packet_cnt=%u, octet_cnt=%u", 
         sr->ssrc, sr->ntp_secs, sr->ntp_frac, sr->rtp_ts, ntohl(sr->packet_cnt), ntohl(sr->octet_cnt));

   //.1 collect ntp and rtp, RtcpAggregator
   
   //.2 sender bandwidth estimation, SenderBandwidthEstimationHandler
   
   return 0;
}

int
snw_rtp_rtcp_rr_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;
   snw_rtcp_rr_t *rr = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   rr = &rtcp->pkt.rr;
   DEBUG(log,"rtcp rr, ssrc=%u", rr->ssrc);

   return 0;
}

int
snw_rtp_rtcp_sdes_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   DEBUG(log,"rtcp sdes msg");

   return 0;
}

int
snw_rtp_rtcp_bye_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   DEBUG(log,"rtcp byte msg");

   return 0;
}

int
snw_rtp_rtcp_app_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   DEBUG(log,"rtcp app msg");

   return 0;
}

int
snw_rtp_rtcp_handle_pkg(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_log_t *log;
   rtcp_pkt_t *rtcp = 0;
   int total = buflen;
   int length;
   
   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }
   log = ctx->log;
   
   print_rtcp_header(log,buf,buflen,"rtcp");

   HEXDUMP(log,(char*)buf,buflen,"rtcp");

	rtcp = (rtcp_pkt_t *)buf;

	if (rtcp->hdr.v != RTCP_VERSION) return -2;

	while (rtcp) {
      switch (rtcp->hdr.pt) {
         case RTCP_RTPFB:
            snw_rtp_rtcp_fb_msg(ctx,rtcp);
            break;
         case RTCP_PSFB:
            snw_rtp_rtcp_psfb_msg(ctx,rtcp);
            break;
         case RTCP_FIR:
            snw_rtp_rtcp_fir_msg(ctx,rtcp);
            break;
         case RTCP_SR:
            snw_rtp_rtcp_sr_msg(ctx,rtcp);
            break;
         case RTCP_RR:
            snw_rtp_rtcp_rr_msg(ctx,rtcp);
            break;
         case RTCP_SDES:
            snw_rtp_rtcp_sdes_msg(ctx,rtcp);
            break;
         case RTCP_BYE:
            snw_rtp_rtcp_bye_msg(ctx,rtcp);
            break;
         case RTCP_APP:
            snw_rtp_rtcp_app_msg(ctx,rtcp);
            break;
         default:
            WARN(log,"unknown rtcp packet type, type=%u",rtcp->hdr.pt);
            break;
      }
		length = ntohs(rtcp->hdr.len);
		if (length == 0)
			break;
		total -= length*4+4;
		if (total <= 0)
			break;
		rtcp = (rtcp_pkt_t *)((uint32_t*)rtcp + length + 1);
	}

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
   0,
   snw_rtp_rtcp_init, 
   snw_rtp_rtcp_handle_pkg, 
   snw_rtp_rtcp_fini,
   0 /*next*/
};


