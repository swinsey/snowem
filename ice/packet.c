#include "packet.h"
#include "rtp.h"

/**
 * list_size - get size of a list 
 * @head: the list to get size.
 */
/*static inline int list_size(struct list_head *head)
{
	int cnt = 0;
   struct list_head *n;
   list_for_each(n,head){ cnt++; }
   return cnt;
}*/

static inline int rtp_list_size(struct list_head *head)
{
	int cnt = 0;
   struct list_head *n;
   list_for_each(n,head){ cnt++; }
   return cnt;
}

void rtp_list_add(rtp_packet_t* head, rtp_packet_t *item) {

   if ( head == NULL || item == NULL )
      return;

   list_add_tail(&item->list,&head->list);

   return;
}

rtp_packet_t* rtp_list_remove_last(rtp_packet_t* head) {
   if ( head == NULL )
      return NULL;

   if ( !list_empty(&head->list) ) {
      rtp_packet_t *p = list_entry(head->list.next,rtp_packet_t,list);
      list_del(&p->list);
      return p;
   }

   return NULL;
}

int rtp_list_size(rtp_packet_t* head) {
	int cnt = 0;
   struct list_head *n;
   list_for_each(n,&head->list){ cnt++; }
   return cnt;
}

//FIXME: change number to CONSTANTS
int ice_get_packet_type(char* buf, int len) {
   rtp_header *header = NULL;
   
   if (!buf || len <= 0) {
      return UNKNOWN_PT;
   }

   if ((*buf >= 20) && (*buf < 64)) {
      return DTLS_PT;
   }

   if (len < RTP_HEADER_SIZE) {
      return UNKNOWN_PT;
   }

   header = (rtp_header *)buf;
   if ((header->type < 64) || (header->type >= 96)) {
      return RTP_PT;
   } else if ((header->type >= 64) && (header->type < 96)) {
      return RTCP_PT;
   }

   return UNKNOWN_PT;
}






