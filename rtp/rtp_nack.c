#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "core/log.h"
#include "ice/ice_component.h"
#include "ice/ice_session.h"
#include "ice/ice_stream.h"
#include "ice/process.h"
#include "rtp/rtp_nack.h"
#include "rtp/rtp_utils.h"

int
snw_rtcp_resend_pkt(snw_rtp_ctx_t *ctx, int video, int seqno) {
   snw_log_t *log = ctx->log;
   snw_ice_session_t *session;
   int64_t now = 0;

   if (!ctx) return -1;
   log = ctx->log;
   session = (snw_ice_session_t*)ctx->session;

   DEBUG(log, "resend seq, flowid=%u, seqno=%u, ts=%llu",
         session->flowid, seqno, now);
   //FIXME: impl
   
   return 0;
}


int
snw_rtcp_nack_handle_pkg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp) {
   snw_log_t *log;
   snw_rtcp_nack_t *nack;
   char *end;
   uint16_t pid = 0;
   uint16_t blp = 0;
   int i, cnt = 0;
   int video = 0;
   
   if (!ctx || !rtcp) return -1;
   log = ctx->log;

   if (rtcp->hdr.pt != RTCP_RTPFB || 
       rtcp->hdr.rc != RTCP_RTPFB_GENERIC_FMT) {
      ERROR(log,"wrong fb msg, pt=%u, rc=%u", rtcp->hdr.pt, rtcp->hdr.rc);
      return -1;
   }

   nack = rtcp->pkt.fb.fci.nack;
   end = (char*)rtcp + 4*(ntohs(rtcp->hdr.len) + 1);

   DEBUG(log,"nacks info, buf=%p, end=%p,nack=%p(%p)", 
         rtcp,end,nack,rtcp->pkt.fb.fci.nack);

   cnt = 0;
   video = ctx->pkt_type && RTP_VIDEO;
   do {
      pid = ntohs(nack->pid);
      blp = ntohs(nack->blp);
      snw_rtcp_resend_pkt(ctx,video,pid);
      for (i=0; i<16; i++) {
         if ((blp & (1 << i)) >> i) {
            snw_rtcp_resend_pkt(ctx,video,pid+i+1);
         }
      }
      cnt++;
      nack++;
      // make sure no loop
      if (cnt > RTCP_PKT_NUM_MAX) break;

   } while ((char*)nack < end);

   //DEBUG(log, "total lost packets, flowid=%u, num=%d", s->flowid, cnt);

   return 0;
}


int
snw_rtp_nack_init(void *c) {
   snw_ice_context_t *ctx = (snw_ice_context_t*)c;
   snw_log_t *log = 0;
   
   if (!ctx) return -1;
   log = ctx->log;
   
   if (MODULE_IS_FLAG(g_rtp_nack_module,M_FLAGS_INIT)) {
      WARN(log,"rtp nack aready init");
      return -1;
   }

   DEBUG(log,"init rtp nack");

   //FIXME init nack module

   MODULE_SET_FLAG(g_rtp_nack_module,M_FLAGS_INIT);

   return 0;
}

int
snw_rtp_nack_handle_pkg(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   rtp_hdr_t *hdr = 0;
   snw_rtcp_stats_t *stats = 0;
   snw_log_t *log;
   uint32_t nack = 0;
   uint16_t seqno;
   int clockrate = 0;
   int64_t transit = 0;
   int delta = 0;
   int video = 0;
   int ret = 0;

   if (!ctx || !buf || buflen <= MIN_RTP_HEADER_SIZE) {
      return -1;
   }
   log = ctx->log;

   //print_rtp_header(log,buf,buflen,"nack");
   video = (ctx->pkt_type & RTP_VIDEO) != 0;
   hdr = (rtp_hdr_t*)buf;
   seqno = ntohs(hdr->seq); 
   DEBUG(log, "nack get seq, seq=%u, ssrc=%u, video=%u", 
         seqno, ntohl(hdr->ssrc), video);

   // collect and update stats
   stats = snw_rtcp_stats_find(ctx,ntohl(hdr->ssrc));
   if (!stats) {
      stats = snw_rtcp_stats_new(ctx,ntohl(hdr->ssrc));
      if (!stats) {
         WARN(log,"no stats on stream");
         return -2;
      }
      // init new slide window
      snw_rtp_slidewin_reset(ctx,&stats->seq_win,seqno-1);
   }

   stats->pkt_cnt++; 
   stats->byte_cnt += buflen - snw_rtp_get_hdrlen(hdr);
   stats->received++;

   //FIXME: handle retransmitted packet
   if (!snw_rtp_slidewin_is_retransmit(ctx, &stats->seq_win, seqno)) {
      clockrate = video ? 90 : 48;
      transit = ctx->epoch_curtime * clockrate - ntohl(hdr->ts);
      if (stats->transit != 0) {
         delta = abs(stats->transit - transit);
         stats->jitter += (1.0/16.0)*(delta - stats->jitter);
      }
      ERROR(log,"jitter info, ssrc=%u, seq=%u, ts=%u, epoch_ts=%llu, delta=%u, jitter=%f, clock=%u", 
             stats->ssrc, ntohs(hdr->seq), ntohl(hdr->ts), ctx->epoch_curtime, delta, stats->jitter, clockrate);
      stats->transit = transit;
   }

   //HEXDUMP(log,(char*)buf,buflen,"rtp");
   //FIXME: save rtp packet in component, not here
   
   //handle lost packets and generate NACK rtpfb message.
   nack = snw_rtp_slidewin_put(ctx, &stats->seq_win, seqno);
   if (nack != 0) {
      char rtcpbuf[RTCP_RTPFB_MSG_LEN];
      snw_ice_session_t *session = 0;
      snw_ice_stream_t *stream = 0;
      snw_ice_component_t *component = 0;

      session = (snw_ice_session_t*)ctx->session;
      stream = (snw_ice_stream_t*)ctx->stream;
      component = (snw_ice_component_t*)ctx->component;
      DEBUG(log,"sending rtpfb nack, flowid=%u, local_ssrc=%x,"
                " remote_ssrc=%x, payload=%x", session->flowid,
                stream->local_video_ssrc, stream->remote_video_ssrc, 
                nack);
                            
         ret = snw_rtcp_gen_nack(rtcpbuf, RTCP_RTPFB_MSG_LEN, 
                           stream->local_video_ssrc, 
                           stream->remote_video_ssrc, 
                           nack);
         if (ret < 0) return -1;
         send_rtp_pkt(session,1,video,rtcpbuf,RTCP_RTPFB_MSG_LEN);
   }

   //generate receiver report
   if (ctx->epoch_curtime - stats->lastsr_time > stats->rtcp_interval) {
      snw_report_block_t rb;
      uint32_t ext_seq = 0;
      uint32_t expected = 0;
      uint32_t lost = 0;
      uint32_t expected_interval = 0;
      uint32_t received_interval = 0;
      uint32_t lost_interval = 0;
      uint8_t  fraction;

      DEBUG(log, "generate receiver rb info, ssrc=%u, cycles=%u, max_seq=%u lastsr_time=%llu, curtime=%llu", 
            stats->ssrc, stats->seq_win.cycles, stats->seq_win.max_seq, stats->lastsr_time, ctx->epoch_curtime);
      
      // generate report block
      memset(&rb,0,sizeof(rb)); 
      rb.ssrc = htonl(stats->ssrc);

      ext_seq = (stats->seq_win.cycles << 16) + stats->seq_win.max_seq;
      expected = ext_seq - stats->seq_win.base_seq + 1;
      if (expected < stats->received || stats->expected_prior == 0)
         lost = 0;
      else 
         lost = expected - stats->received;

      DEBUG(log, "lost rb info, expected=%u, received=%u, lost=%u", 
            expected, stats->received, lost); 

      expected_interval = expected - stats->expected_prior;
      stats->expected_prior = expected;
      received_interval = stats->received - stats->received_prior;
      lost_interval = expected_interval - received_interval;
      if (expected_interval != 0) {
         fraction = ((lost_interval) << 8) / expected_interval;
      }
      stats->received_prior = stats->received;

      rb.frac_lost = fraction;
      rb.cum_lost = htonl(lost) >> 8;
      rb.hi_seqno = htonl((stats->seq_win.cycles << 16) + stats->seq_win.max_seq);
      rb.jitter = 0;
      rb.lsr = ntohl(stats->last_sr_ntp);
      rb.dlsr = htonl((uint32_t)((ctx->epoch_curtime - stats->lastsr_time) * 65536 / 1000));

      DEBUG(log, "rb info, ssrc=%u, frac_lost=%u, cum_lost=%u, hi_seqno=%u, "
            "jitter=%u, lsr=%u, dlsr=%u",
            ntohl(rb.ssrc), rb.frac_lost, ntohl(rb.cum_lost)>>8, 
            ntohl(rb.hi_seqno), ntohl(rb.jitter), ntohl(rb.lsr), ntohl(rb.dlsr));

      // generate rtcp pkt

      stats->lastsr_time = ctx->epoch_curtime;
   }

   return 0;
}

int
snw_rtp_nack_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_nack_module = { 
   "nack",
   0,/*ctx*/
   RTP_AUDIO|RTP_VIDEO,
   0,
   snw_rtp_nack_init, 
   snw_rtp_nack_handle_pkg, 
   snw_rtp_nack_fini,
   0 /*next*/
};


