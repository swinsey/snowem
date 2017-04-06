
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
snw_ice_handle_incoming_rtp(snw_ice_session_t *session, int type, int video, char *buf, int len) {
   snw_ice_context_t *ice_ctx = 0;
   snw_log_t *log = 0;

   if (!session) return;
   ice_ctx = session->ice_ctx;
   log = ice_ctx->log;

   if (IS_FLAG(session,ICE_PUBLISHER)) {
	   /*Json::Value root;
   	Json::FastWriter writer;
   	std::string output;
   	std::string sData;
   	//sData.append(decrypted_frame, frame_len);
      sData.append(buf, len);
   	root["msgtype"] = SNW_CORE;
   	root["api"] = SNW_CORE_RTP;
   	if (video)
   		root["media_type"] = "v";
   	else
   		root["media_type"] = "a";

      root["pkg_type"] = type;
   	root["data"] = sData;
   	output = writer.write(root);*/

      /*snw_ice_session_t *s = 0;
      rtp_header *header = (rtp_header *)buf;
      uint16_t seq = ntohs(header->seq_number);
      DEBUG(log, "relay rtp pkt, flowid: %u, media_type: %u, pkg_type: %u(%u), seq: %u, length=%u", 
         session->flowid, video, header->type, VP8_PT, seq,len);
      rtp_packet_t *pkt = (rtp_packet_t *)malloc(sizeof(rtp_packet_t));
      pkt->data = (char*)malloc(len);
      memcpy(pkt->data, buf, len);
      pkt->length = len;
      pkt->type = video ? RTP_PACKET_VIDEO : RTP_PACKET_AUDIO;
      pkt->control = (type == 0) ? 0: 1; //rtcp or rtp
      pkt->encrypted = 0;

      DEBUG(log, "flowid=%u -> forwardid=%u", session->flowid, session->forwardid);
      s = (snw_ice_session_t*)snw_ice_session_search(ice_ctx,session->forwardid);
      if (s) {
         DEBUG(log, "forward, flowid=%u -> forwardid=%u", session->flowid, session->forwardid);
         send_rtp_pkt(s,pkt);
      } else {
         //FIXME: free pkt
         if (pkt && pkt->data ) free(pkt->data);
         pkt->data = NULL;
         if (pkt) free(pkt);
         pkt = NULL;
      }*/

      /*FIXME: uncomment the below line*/
   	//enqueue_msg_to_mcd(output.c_str(),output.size(), session->flowid);

   } else if (IS_FLAG(session,ICE_SUBSCRIBER)) {
      if ( type == 1 ) {
         //DEBUG("forward receiver rtcp pkt, flowid=%u", session->flowid);
      }
   } else {
     //DEBUG("unknown rtp type of agent, flowid=%u", session->flowid);
   }

   return;
}

