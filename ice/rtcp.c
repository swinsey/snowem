#include "log.h"
#include "rtcp.h"
#include "types.h"

int 
snw_rtcp_has_payload_type(char *buf, int len, int8_t type) {
	int total, length;
	rtcp_hdr_t *rtcp = (rtcp_hdr_t *)buf;

	if (rtcp->v != 2)
		return 0;

   total = len;
	while (rtcp) {
      if (rtcp->pt == type)
         return 1;
		length = ntohs(rtcp->len);
		if (length == 0)
			break;
		total -= (length+1)*RTCP_LENGTH_IN_WORDS;
		if (total <= 0)
			break;
		rtcp = (rtcp_hdr_t *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

uint32_t
snw_rtcp_get_ssrc(snw_ice_session_t *s, char *buf, int len) {
   snw_log_t *log = 0;
   rtcp_pkt_t *rtcp = 0;
   char *end = buf + len;
   int rtcp_len;

   if (!s || !buf || len == 0) return 0;
   log = s->ice_ctx->log;

   rtcp = (rtcp_pkt_t *)buf;
   if (rtcp->hdr.v != RTCP_VERSION) return 0;

   /* the first rtcp pkt must be either sender report or recevier report.*/
   while (rtcp) {
      switch (rtcp->hdr.pt) {
         case RTCP_SR: {
            DEBUG(log, "got sender report, rc=%u, len=%u", rtcp->hdr.rc, len);
            return ntohl(rtcp->pkt.sr.ssrc);
         }
         case RTCP_RR: {
            DEBUG(log, "got receiver report, rc=%u, len=%u", rtcp->hdr.rc, len);
            return ntohl(rtcp->pkt.rr.ssrc);
         }
         default: {
            break;
         }
      }

      rtcp_len = ntohs(rtcp->hdr.len);
      rtcp = (rtcp_pkt_t *)((uint32_t*)rtcp + rtcp_len + 1); // len + 1 in 32-bits word.
      if (rtcp_len ==0 || (char*)rtcp >= end) break;
   }
   return 0;
}


void 
snw_rtcp_handle_nacks(snw_ice_session_t *s, snw_ice_component_t *c, 
       int video, char *buf, int len, resend_callback_fn cb) {
   snw_log_t *log = 0;
	rtcp_pkt_t *rtcp = 0;
   char *end;
	int total = len;
   uint16_t pid = 0;
   uint16_t blp = 0;
   int i, cnt = 0;

	if (!s || !c || !buf || len == 0) return;
   log = s->ice_ctx->log;

	rtcp = (rtcp_pkt_t *)buf;

	if (rtcp->hdr.v != RTCP_VERSION) return;

   HEXDUMP(log,buf,len,"rtcp");
	while (rtcp) {
		if (rtcp->hdr.pt == RTCP_RTPFB && 
          rtcp->hdr.rc == RTCP_RTPFB_GENERIC_FMT) {
         snw_rtcp_nack_t *nack = rtcp->pkt.fb.fci.nack;
         end = (char*)rtcp + 4*(ntohs(rtcp->hdr.len) + 1);

         DEBUG(log,"nacks info, buf=%p, end=%p,nack=%p(%p)", rtcp,end,nack,rtcp->pkt.fb.fci.nack);

         cnt = 0;
         do {
            pid = ntohs(nack->pid);
            blp = ntohs(nack->blp);
            if (cb) cb(s,c,video,pid,s->curtime);
            for (i=0; i<16; i++) {
               if ((blp & (1 << i)) >> i) {
                  if (cb) cb(s,c,video,pid+i+1,s->curtime);
               }
            }
            cnt++;
            nack++;
            // make sure no loop
            if (cnt > RTCP_PKT_NUM_MAX) break;

         } while ((char*)nack < end);

         DEBUG(log, "total lost packets, flowid=%u, num=%d", s->flowid, cnt);
		}
		int length = ntohs(rtcp->hdr.len);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_pkt_t *)((uint32_t*)rtcp + length + 1);
	}
	return;

}

int
snw_gen_rtcp_fir(char *buf, int len, uint32_t local_ssrc, 
      uint32_t remote_ssrc, int seqnr) {

	if (!buf || len < RTCP_PSFB_FIR_MSG_LEN)
		return -1;

   memset(buf, 0, RTCP_PSFB_FIR_MSG_LEN);
	rtcp_pkt_t *rtcp = (rtcp_pkt_t *)buf;
	rtcp->hdr.v = RTCP_VERSION;
	rtcp->hdr.pt = RTCP_PSFB;
	rtcp->hdr.rc = RTCP_PSFB_FIR_FMT;
   if (len % RTCP_LENGTH_IN_WORDS != 0) {
      // FIXME: has padding
      return -1;
   }
	rtcp->hdr.len = htons((len/RTCP_LENGTH_IN_WORDS)-1);

   rtcp->pkt.fb.ssrc = htonl(local_ssrc);
   rtcp->pkt.fb.media = htonl(remote_ssrc);
   rtcp->pkt.fb.fci.fir->ssrc = htonl(remote_ssrc);
   rtcp->pkt.fb.fci.fir->seqno = htonl(seqnr << 24);
	
	return RTCP_PSFB_FIR_MSG_LEN;
}

int snw_gen_rtcp_pli(char *buf, int len,
      uint32_t local_ssrc, uint32_t remote_ssrc) {

	if (buf == NULL || len < RTCP_PSFB_PLI_MSG_LEN)
		return -1;

	memset(buf, 0, RTCP_PSFB_PLI_MSG_LEN);
	rtcp_pkt_t *rtcp = (rtcp_pkt_t *)buf;
	rtcp->hdr.v = RTCP_VERSION;
	rtcp->hdr.pt = RTCP_PSFB;
	rtcp->hdr.rc = RTCP_PSFB_PLI_FMT;
   if (len % RTCP_LENGTH_IN_WORDS != 0) {
      // FIXME: has padding
      return -1;
   }
	rtcp->hdr.len = htons((len/RTCP_LENGTH_IN_WORDS)-1);

   rtcp->pkt.fb.ssrc = htonl(local_ssrc);
   rtcp->pkt.fb.media = htonl(remote_ssrc);

	return RTCP_PSFB_PLI_MSG_LEN;
}


