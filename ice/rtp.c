
#include "log.h"
#include "ice.h"
#include "ice_session.h"
#include "json/json.h"
#include "process.h"
#include "rtp.h"
#include "utils.h"

/* seq_info_t list functions */
void 
snw_ice_seq_append(seq_info_t **head, seq_info_t *new_seq) {
   if(*head == NULL) {
      new_seq->prev = new_seq;
      new_seq->next = new_seq;
      *head = new_seq;
   } else {
      seq_info_t *last_seq = (*head)->prev;
      new_seq->prev = last_seq;
      new_seq->next = *head;
      (*head)->prev = new_seq;
      last_seq->next = new_seq;
   }   
}

seq_info_t *
snw_ice_seq_pop_head(seq_info_t **head) {
   seq_info_t *pop_seq = *head;
   if(pop_seq) {
      seq_info_t *new_head = pop_seq->next;
      if (pop_seq == new_head) {
         *head = NULL;
      } else {
         *head = new_head;
         new_head->prev = pop_seq->prev;
         new_head->prev->next = new_head;
      }   
   }   
   return pop_seq;
}

void
snw_ice_seq_list_free(seq_info_t **head) {
   if (!*head) return;
   seq_info_t *cur = *head;
   do {
      seq_info_t *next = cur->next;
      free(cur);
      cur = next;
   } while(cur != *head);
   *head = NULL;
}

int
snw_ice_seq_in_range(uint16_t seqn, uint16_t start, uint16_t len) {
   /* Supports wrapping sequence (easier with int range) */
   int n = seqn;
   int nh = (1<<16) + n;
   int s = start;
   int e = s + len;
   return (s <= n && n < e) || (s <= nh && nh < e);
}


void
snw_ice_broadcast_rtp_pkg(snw_ice_session_t *session, int control, int video, char *buf, int len) {
   snw_ice_context_t *ice_ctx = 0;
   snw_log_t *log = 0;
   snw_ice_session_t *s = 0;
   uint32_t flowid = 0;

   if (!session) return;
   ice_ctx = session->ice_ctx;
   log = ice_ctx->log;

   DEBUG(log, "broadcast session, flowid=%u, players=%u %u %u %u %u", 
         session->flowid,
         session->channel->players[0],
         session->channel->players[1],
         session->channel->players[2],
         session->channel->players[3],
         session->channel->players[4]);

   for (int i=0; i<SNW_ICE_CHANNEL_USER_NUM_MAX; i++) {
     
      if (session->channel->players[i] != 0) {
         rtp_hdr_t *header = (rtp_hdr_t *)buf;
         uint16_t seq = ntohs(header->seq);

         flowid = session->channel->players[i];
         DEBUG(log, "relay rtp pkt, flowid: %u, media_type: %u, pkg_type: %u(%u), seq: %u, length=%u", 
            session->flowid, video, header->pt, VP8_PT, seq,len);
         s = (snw_ice_session_t*)snw_ice_session_search(ice_ctx,flowid);
         if (s) {
            DEBUG(log, "forward, is_rtcp=%u, flowid=%u -> forwardid=%u", 
                  control, session->flowid, flowid);
            send_rtp_pkt(s, control, video, buf, len);
         } else {
            // failed
            ERROR(log, "session not found, flowid=%u",flowid);
         }
      }
   }

   return;
}

void 
snw_ice_handle_incoming_rtp(snw_ice_session_t *session, int control, int video, char *buf, int len) {

   if (!session) return;

   if (IS_FLAG(session,ICE_PUBLISHER)) {
      snw_ice_broadcast_rtp_pkg(session,control,video,buf,len);
   } else if (IS_FLAG(session,ICE_SUBSCRIBER)) {
      if (control == 1) {
         //DEBUG("forward receiver rtcp pkt, flowid=%u", session->flowid);
      }
   } else {
     //DEBUG("unknown rtp type of agent, flowid=%u", session->flowid);
   }

   return;
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

void
snw_rtp_slidewin_put(snw_ice_session_t *session, rtp_slidewin_t *win, uint16_t seq) {
   snw_log_t *log = 0;
   nack_payload_t nack;
   int nseq = RTP_SEQ_NUM_MAX + seq;
   int nlast_seq = RTP_SEQ_NUM_MAX + win->last_seq;
   int idx = 0;
   

   if (!session || !win) 
      return;
   log = session->ice_ctx->log;

   DEBUG(log, "slidewin put, flowid=%u, seq=%u",session->flowid, seq);
   if (session->curtime - win->last_ts > RTP_SYNC_TIME_MAX) {
      WARN(log, "slidewin stream out of sync, flowid=%u, seq=%u", session->flowid, seq);
      snw_rtp_slidewin_reset(session, win, seq);
      return;
   }

   if (seq - win->last_seq > RTP_SLIDEWIN_SIZE || nseq - win->last_seq > RTP_SLIDEWIN_SIZE) {
      WARN(log, "slidewin stream out of sync, flowid=%u, seq=%u", session->flowid, seq);
      snw_rtp_slidewin_reset(session, win, seq);
      return;
   }

   if (win->last_seq - seq > RTP_SLIDEWIN_SIZE || nlast_seq - seq > RTP_SLIDEWIN_SIZE) {
      WARN(log, "slidewin packet out of sync, flowid=%u, seq=%u", session->flowid, seq);
      return;
   }

   win->last_ts = session->curtime;
   idx = seq % RTP_SLIDEWIN_SIZE;
   if (seq < win->last_seq) {
      win->seqlist[idx].seq = seq;
      win->seqlist[idx].status = RTP_RECV;
   } else if (seq > win->last_seq) {
      if (idx > win->head) {
         // [head -- idx]: overlap area, generate report and init 
         nack.data.num = 0;
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

   return;
}




