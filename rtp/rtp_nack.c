#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "core/log.h"
#include "ice/ice_component.h"
#include "ice/ice_session.h"
#include "ice/ice_stream.h"
#include "ice/process.h"
#include "rtp/rtp_nack.h"

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

void
snw_rtp_slidewin_reset(snw_ice_session_t *session, rtp_slidewin_t *win, uint16_t seq) {
   snw_log_t *log = 0;
   int idx = 0;

   if (!session || !win) 
      return;
   log = session->ice_ctx->log;

   memset(win,0,sizeof(*win)); //reset all
   idx = seq % RTP_SLIDEWIN_SIZE; 
   win->head = idx;
   win->last_seq = seq;
   win->last_ts  = session->curtime;
   win->seqlist[idx].status = RTP_RECV;

   DEBUG(log, "slidewin reset, flowid=%u, seq=%u", session->flowid, seq);

   return;
}

void
snw_rtp_slidewin_update(rtp_slidewin_t *win, nack_payload_t *nack, 
      int begin, int end, uint16_t seq) {

   for (int i = begin; i < end; i++) {
      //case of missing seq: update nack payload
      if (win->seqlist[i].seq != 0 && win->seqlist[i].status == RTP_MISS) {
         if (nack->data.pl.seq == 0) {
            nack->data.pl.seq = win->seqlist[i].seq;
         } else {
            uint16_t blp = ntohs(nack->data.pl.blp);
            blp |= 1 << (win->seqlist[i].seq - nack->data.pl.seq - 1);
            nack->data.pl.blp = htons(blp);
         }
      } 
      
      //update seq list 
      win->seqlist[i].seq = seq + i - begin;
      win->seqlist[i].status = RTP_MISS;
   }
   return;
}

uint32_t
snw_rtp_slidewin_put(snw_ice_session_t *session, rtp_slidewin_t *win, uint16_t seq) {
   snw_log_t *log = 0;
   nack_payload_t nack;
   int nseq = RTP_SEQ_NUM_MAX + seq;
   int nlast_seq = RTP_SEQ_NUM_MAX + win->last_seq;
   int idx = 0;
   
  
   if (!session || !win) 
      return 0;
   log = session->ice_ctx->log;
   nack.data.num = 0;

   DEBUG(log, "slidewin put, flowid=%u, seq=%u, last_seq=%u, head=%u",
        session->flowid, seq, win->last_seq, win->head);
   if (session->curtime - win->last_ts > RTP_SYNC_TIME_MAX) {
      WARN(log, "slidewin stream out of sync, flowid=%u, seq=%u", 
           session->flowid, seq);
      snw_rtp_slidewin_reset(session, win, seq);
      return 0;
   }

   //FIXME: modular arithmetics
   if (seq - win->last_seq > RTP_SLIDEWIN_SIZE /*|| nseq - win->last_seq > RTP_SLIDEWIN_SIZE*/) {
      WARN(log, "slidewin stream out of sync, flowid=%u, seq=%u, last_seq=%u", 
              session->flowid, seq, win->last_seq);
      snw_rtp_slidewin_reset(session, win, seq);
      return 0;
   }

   //FIXME: modular arithmetics
   if (win->last_seq - seq > RTP_SLIDEWIN_SIZE /*|| nlast_seq - seq > RTP_SLIDEWIN_SIZE*/) {
      WARN(log, "slidewin packet out of sync, flowid=%u, seq=%u", session->flowid, seq);
      return 0;
   }

   win->last_ts = session->curtime;
   idx = seq % RTP_SLIDEWIN_SIZE;
   if (seq < win->last_seq) {
      win->seqlist[idx].seq = seq;
      win->seqlist[idx].status = RTP_RECV;
   } else if (seq > win->last_seq) {
      if (idx > win->head) {
         // [head -- idx]: overlap area, generate report and init 
         snw_rtp_slidewin_update(win, &nack, win->head, idx, win->seqlist[win->head].seq);
      } else if (idx < win->head) {
         // [head -- end] and [begin -- idx]: overlap area
         snw_rtp_slidewin_update(win, &nack, win->head, RTP_SLIDEWIN_SIZE, win->seqlist[win->head].seq);
         snw_rtp_slidewin_update(win, &nack, 0, idx, win->seqlist[win->head].seq);
      } else {
         WARN(log,"slidewin duplicate packet, flowid=%u, seq=%u", session->flowid, seq);
      }
      win->head = idx;
      win->last_seq = seq;
      win->seqlist[idx].seq = seq;
      win->seqlist[idx].status = RTP_RECV;

   } else {
      WARN(log,"slidewin duplicate packet, flowid=%u, seq=%u", session->flowid, seq);
   }

   return nack.data.num;
}

void 
snw_rtp_handle_lost_packets(snw_ice_session_t *session, snw_ice_stream_t *stream,
      snw_ice_component_t *component, uint16_t seqno, int video) {
   snw_log_t *log = 0;
   uint32_t nack = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   /* Save current seq number and generate list of lost seqs */
   //FIXME: handle both audio and video
   if (!video) {
      //ignore loss handler for audio
      return;
   }
    
   nack = snw_rtp_slidewin_put(session, &component->v_slidewin, seqno);
   /* Generate NACK rtpfb message */
   if (nack != 0) {
      char rtcpbuf[RTCP_RTPFB_MSG_LEN];
      DEBUG(log,"sending rtpfb nack, flowid=%u, local_ssrc=%x, remote_ssrc=%x, payload=%x",
                              session->flowid,
                              stream->local_video_ssrc, 
                              stream->remote_video_ssrc, 
                              nack);
                            
         snw_rtcp_gen_nack(rtcpbuf, RTCP_RTPFB_MSG_LEN, 
                           stream->local_video_ssrc, 
                           stream->remote_video_ssrc, 
                           nack);
         send_rtp_pkt(session,1,video,rtcpbuf,RTCP_RTPFB_MSG_LEN);
   }

   return;
}


int
snw_rtp_nack_handle_pkg(void *data, char *buf, int buflen) {
   snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
   snw_ice_session_t *session = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;
   rtp_hdr_t *hdr = 0;
   snw_log_t *log;
   int video = 0;

   if (!ctx || !buf || buflen <= MIN_RTP_HEADER_SIZE) {
      return -1;
   }
   log = ctx->log;
   session = (snw_ice_session_t*)ctx->session;
   stream = (snw_ice_stream_t*)ctx->stream;
   component = (snw_ice_component_t*)ctx->component;
   
   print_rtp_header(log,buf,buflen,"nack");
   video = (ctx->pkt_type & RTP_VIDEO) != 0;
   hdr = (rtp_hdr_t*)buf;
   DEBUG(log, "nack get seq, seq=%u, ssrc=%u, video=%u", ntohs(hdr->seq), ntohl(hdr->ssrc), video);

   //HEXDUMP(log,(char*)buf,buflen,"rtp");
   //FIXME: save rtp packet
   
   //handle lost packets 
   snw_rtp_handle_lost_packets(session,stream,
          component,ntohs(hdr->seq),video);

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


