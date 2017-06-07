
#include "log.h"
#include "ice.h"
#include "ice_session.h"
#include "json/json.h"
#include "process.h"
#include "rtp.h"
#include "utils.h"

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

