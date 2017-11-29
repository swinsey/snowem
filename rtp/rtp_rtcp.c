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
   snw_rtcp_stats_t *stats = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   sr = &rtcp->pkt.sr;
   //HEXDUMP(log,(char*)sr,sizeof(*sr),"sr");
   //HEXDUMP(log,(char*)&sr->ntp_ts,sizeof(sr->ntp_ts),"ntp");
   DEBUG(log,"rtcp sr, ssrc=%u , ntp_ts=%llu, rtp_ts=%u, "
         "packet_cnt=%u, octet_cnt=%u", ntohl(sr->ssrc), be64toh(sr->ntp_ts), 
         ntohl(sr->rtp_ts), ntohl(sr->pkt_cnt), ntohl(sr->byte_cnt));

   stats = snw_rtcp_stats_find(ctx,&ctx->receiver_stats, ntohl(sr->ssrc));
   if (!stats) {
      ERROR(log, "no rtcp stats found, ssrc=%u", ntohl(sr->ssrc));
      return -1;
   }

   //.1 collect ntp and rtp
   stats->last_sr_ntp = ntohl((rtcp->pkt.sr.ntp_ts << 16) >> 32);
   stats->last_sr_rtp_ts = ntohl(rtcp->pkt.sr.rtp_ts);
   stats->last_sr_recv_ts = ctx->epoch_curtime;

   DEBUG(log,"rtcp sr stats lsr, ssrc=%u, pkt_cnt=%u, byte_cnt=%u, last_sr_ntp=%u(%llu)", 
          stats->ssrc, stats->pkt_cnt, stats->byte_cnt, stats->last_sr_ntp,be64toh(rtcp->pkt.sr.ntp_ts));
   
   //.2 sender bandwidth estimation, SenderBandwidthEstimationHandler
   
   return 0;
}

void
snw_rtp_rtcp_print_rb(snw_log_t *log, snw_report_block_t *rb) {

   if (!log || !rb) return;

   DEBUG(log,"rtcp rr rb, cum_lost=%u, frac_lost=%u, hi_seqno=%u, jitter=%u, lsr=%u, dlsr=%u", 
         rb->cum_lost,
         rb->frac_lost,
         ntohl(rb->hi_seqno),
         ntohl(rb->lsr),
         ntohl(rb->dlsr));
   return;
}

int
snw_rtp_rtcp_rr_msg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log = 0;
   snw_rtcp_rr_t *rr = 0;
   snw_rtcp_stats_t *stats = 0;
   int i = 0;

   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   rr = &rtcp->pkt.rr;
   DEBUG(log,"rtcp rr, rc=%u, ssrc=%u", rtcp->hdr.rc, ntohl(rr->ssrc));
   
   for (i=0; i<rtcp->hdr.rc; i++) {
      snw_report_block_t *rb = &rr->rb[i];
      DEBUG(log, "rtcp rr rb, ssrc=%u", ntohl(rb->ssrc));
      snw_rtp_rtcp_print_rb(log,rb);
      stats = snw_rtcp_stats_find(ctx,&ctx->sender_stats,ntohl(rb->ssrc));
      if (!stats) {
         stats = snw_rtcp_stats_new(ctx,&ctx->sender_stats,ntohl(rb->ssrc));
         if (!stats) continue;
      }
      DEBUG(log, "rtcp rr update stats, ssrc=%u", ntohl(rb->ssrc));
      stats->last_rr_recv_ts = ctx->epoch_curtime;

      stats->last_rr_cum_lost = rb->cum_lost;
	   stats->last_rr_frac_lost = ntohl(rb->frac_lost);
   	stats->last_rr_hi_seqno = ntohl(rb->hi_seqno);
   	stats->last_rr_jitter = ntohl(rb->jitter);
   	stats->last_rr_lsr = ntohl(rb->lsr);
   	stats->last_rr_dlsr = ntohl(rb->dlsr);

   }

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
snw_rtp_rtcp_handle_pkg_in(void *data, char *buf, int buflen) {
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
snw_rtp_rtcp_handle_pkg_out(void *data, char *buf, int buflen) {

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
   snw_rtp_rtcp_handle_pkg_in, 
   snw_rtp_rtcp_handle_pkg_out, 
   snw_rtp_rtcp_fini,
   0 /*next*/
};


