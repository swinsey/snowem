
#include "core/log.h"
#include "core/types.h"
#include "vp8.h"
#include "rtp.h"
#include "packet.h"


int g_max_rtp_queue = 3001;
void ice_rtp_is_vp8(rtp_packet_t *head, int type, char* buf, int len) {
   rtp_packet_t *rtp = NULL;
   rtp_hdr_t   *rtp_hdr = NULL;
   vp8_desc_t   *vp8 = NULL;
   int rtp_bytes = 0;
   int vp8_desc_bytes = 0;
   int is_key_frame = 0;

   //DEBUG("check vp8 header, len=%u",len);
   if ( len < RTP_HEADER_SIZE )
      return;
   if (!type)
   {   
   rtp_hdr = (rtp_hdr_t*)buf;
   rtp_bytes = RTP_HEADER_SIZE + rtp_hdr->cc*4;
   vp8 = (vp8_desc_t*)(buf + rtp_bytes);

   //HEXDUMP(buf,rtp_bytes,"rtp");
   //HEXDUMP(buf+rtp_bytes,8,"vp8");
   //DEBUG("rtp info, rtp_bytes=%u, ssrc=%u, seq=%u, ts=%u, version=%u, padding=%u, extension=%u, csrccount=%u, markerbit=%u, type=%u",
   //      rtp_bytes, rtp_hdr->ssrc, ntohs(rtp_hdr->seq_number), ntohl(rtp_hdr->timestamp), rtp_hdr->version,rtp_hdr->padding,rtp_hdr->extension,
   //      rtp_hdr->csrccount,rtp_hdr->markerbit,rtp_hdr->type);
   //DEBUG("vp8 desc info, markerbit=%u,vp8_desc_t=%u, X=%u, R1=%u, N=%u, S=%u, R2=%u, PID=%u",
   //      rtp_hdr->markerbit, *(unsigned char*)vp8, vp8->X, vp8->R1, vp8->N, vp8->S, vp8->R2, vp8->PID);

   vp8_desc_bytes = 1;
   if ( vp8->X ) {
      vp8_xext_t *x = (vp8_xext_t*)vp8->ext;
      vp8_desc_bytes += 1;
      //DEBUG("vp8 desc x extension, I=%u, K=%u, L=%u, RSV=%u",x->I, x->K, x->L, x->RSV);
      if ( x->I ) {
         vp8_desc_bytes += 1;
         if ( vp8->ext[1] & 0x80 ) {
            //unsigned char c= vp8->ext[1];
            //DEBUG("vp8 desc with M bit, I=%u",c);
            vp8_desc_bytes += 1;
         }
      }
      if ( x->L ) vp8_desc_bytes += 1;
      if ( x->T || x->K ) vp8_desc_bytes += 1;
   }

   if ( vp8->S == 1 && vp8->PID == 0 ) {
      unsigned char c = *(buf + rtp_bytes + vp8_desc_bytes);
      //int got_keyframe = !(c&0x01);
      is_key_frame= !(c&0x01);
      //DEBUG("vp8 payload header, got_keyframe=%u, rtp_bytes=%u, vp8_desc_bytes=%u, vp8_payload_hdr=%u", 
      //      is_key_frame, rtp_bytes, vp8_desc_bytes, c);
      //HEXDUMP(buf,rtp_bytes+vp8_desc_bytes+1,"vp8");
   }
 
   //DEBUG("skip vp8 desc, vp8_desc_bytes=%u",vp8_desc_bytes);
   }
   /* Save the packet for retransmissions that may be needed later */
   rtp = SNW_MALLOC(rtp_packet_t);
   if ( rtp == NULL )
      return;
   SNW_MEMZERO(rtp,rtp_packet_t);
   rtp->data = (char*)malloc(len);
   if ( rtp->data == NULL ) {
      free(rtp);
      return;
   }
   memcpy(rtp->data,buf,len);
   rtp->length = len;
   //rtp->media = video;
   rtp->keyframe = is_key_frame;
   rtp->control = type;
   /*if (is_key_frame)
   {  
      //DEBUG("recv key frame, remove all old list, start list with newest keyframe first");
      struct list_head *h;
      int iListSize = rtp_list_size(head);
      //list_for_each(h,&head->list){
      for (int i = 0; i < iListSize; i++){
         rtp_packet_t *p = rtp_list_remove_last(head);
         free(p->data);
         p->data = NULL;
         free(p);        
      }
   }*/
   rtp->last_retransmit = 0;
   rtp_list_add(head,rtp);
   if(rtp_list_size(head) > g_max_rtp_queue) {
      rtp_packet_t *p = rtp_list_remove_last(head);
      free(p->data);
      p->data = NULL;
      free(p);
   }
   //DEBUG("vp8 rtp list, size=%u",rtp_list_size(head));


   return;
}



