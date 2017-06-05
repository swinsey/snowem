#include "log.h"
#include "rtcp.h"
#include "types.h"

uint8_t
snw_rtcp_get_payload_type(snw_ice_session_t *s, char *buf, int len) {
   rtcp_hdr_t *rtcp = 0;

   if (!s || !buf || len == 0)
      return 0;

   rtcp = (rtcp_hdr_t *)buf;
   if (rtcp->v != 2)
      return 0;
   
   return rtcp->pt;
}

int 
snw_rtcp_has_type(char *buf, int len, int8_t type) {
	int total, length;
	rtcp_hdr_t *rtcp = (rtcp_hdr_t *)buf;

	if (rtcp->v != 2)
		return 0;

   total = len;
	while (rtcp) {
      if (rtcp->pt == type)
         return 1;
		// compound packet
		length = ntohs(rtcp->len);
		if (length == 0)
			break;
		//total -= length*4+4
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

   //HEXDUMP(log,(const char*)buf,len,"rtcp");
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


int
snw_rtcp_fix_ssrc(snw_ice_session_t *s, char *packet, int len, int fixssrc, uint32_t newssrcl, uint32_t newssrcr) {
   snw_log_t *log;
	rtcp_hdr_t *rtcp = 0;
	int pno = 0, total = len;

	if (!s || !packet || len == 0)
		return -1;
   log = s->ice_ctx->log;

	rtcp = (rtcp_hdr_t *)packet;
	if (rtcp->v != 2)
		return -2;

	DEBUG(log, "parsing compound packet, flowid=%u, pt=%u, len=%d", 
          s->flowid, rtcp->pt, len);

	while (rtcp) {
		pno++;
		/* TODO Should we handle any of these packets ourselves, or just relay them? */
		switch (rtcp->pt) {
			case RTCP_SR: {
				/* SR, sender report */
				DEBUG(log, "FIXSSRC #%d SR (200)", pno);
				rtcp_sr *sr = (rtcp_sr*)rtcp;
				//ICE_DEBUG2("SSRC: %u (%u in RB)", ntohl(sr->ssrc), report_block_get_ssrc(&sr->rb[0]));
				//ICE_DEBUG2("Lost: %u/%u", report_block_get_fraction_lost(&sr->rb[0]), report_block_get_cum_packet_loss(&sr->rb[0]));
				if(fixssrc && newssrcl) {
					sr->ssrc = htonl(newssrcl);
				}
				if(fixssrc && newssrcr && sr->hdr.rc > 0) {
					sr->rb[0].ssrc = htonl(newssrcr);
				}
				break;
			}
			case RTCP_RR: {
				/* RR, receiver report */
				DEBUG(log, "FIXSSRC #%d RR (201)", pno);
				rtcp_rr *rr = (rtcp_rr*)rtcp;
				//ICE_DEBUG2("SSRC: %u (%u in RB)", ntohl(rr->ssrc), report_block_get_ssrc(&rr->rb[0]));
				//ICE_DEBUG2("Lost: %u/%u", report_block_get_fraction_lost(&rr->rb[0]), report_block_get_cum_packet_loss(&rr->rb[0]));
				if(fixssrc && newssrcl) {
					rr->ssrc = htonl(newssrcl);
				}
				if(fixssrc && newssrcr && rr->hdr.rc > 0) {
					rr->rb[0].ssrc = htonl(newssrcr);
				}
				break;
			}
			case RTCP_SDES: {
				/* SDES, source description */
				DEBUG(log, "FIXSSRC #%d SDES (202)", pno);
				rtcp_sdes *sdes = (rtcp_sdes*)rtcp;
				ICE_DEBUG2("SSRC: %u", ntohl(sdes->ssrc));
				if(fixssrc && newssrcl) {
					sdes->ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_BYE: {
				/* BYE, goodbye */
				DEBUG(log, "FXISSRC #%d BYE (203)", pno);
				rtcp_bye_t *bye = (rtcp_bye_t*)rtcp;
				ICE_DEBUG2("SSRC: %u", ntohl(bye->ssrc[0]));
				if(fixssrc && newssrcl) {
					bye->ssrc[0] = htonl(newssrcl);
				}
				break;
			}
			case RTCP_APP: {
				/* APP, application-defined */
				DEBUG(log, "FIXSSRC #%d APP (204)", pno);
				rtcp_app_t *app = (rtcp_app_t*)rtcp;
				ICE_DEBUG2("SSRC: %u", ntohl(app->ssrc));
				if(fixssrc && newssrcl) {
					app->ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_FIR: {
				/* FIR, rfc2032 */
				DEBUG(log, "FIXSSRC %d FIR (192)", pno);
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				if(fixssrc && newssrcr && (ntohs(rtcp->len) >= 20)) {
					rtcpfb->media = htonl(newssrcr);
				}
				if(fixssrc && newssrcr) {
					uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
					*ssrc = htonl(newssrcr);
				}
				break;
			}
			case RTCP_RTPFB: {
				/* RTPFB, Transport layer FB message (rfc4585) */
				DEBUG(log, "FIXSSRC #%d RTPFB (205)", pno);
				int fmt = rtcp->rc;
				ICE_DEBUG2("FMT: %u", fmt);
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(rtcpfb->ssrc));
				if(fmt == 1) {
					ICE_DEBUG2("#%d NACK -- RTPFB (205)", pno);
					if(fixssrc && newssrcr) {
						rtcpfb->media = htonl(newssrcr);
					}
					int nacks = ntohs(rtcp->len)-2;	/* Skip SSRCs */
					if(nacks > 0) {
						ICE_DEBUG2("Got %d nacks", nacks);
						rtcp_nack *nack = NULL;
						uint16_t pid = 0;
						uint16_t blp = 0;
						int i=0, j=0;
						char bitmask[20];
						for(i=0; i< nacks; i++) {
							nack = (rtcp_nack *)rtcpfb->fci + i;
							pid = ntohs(nack->pid);
							blp = ntohs(nack->blp);
							memset(bitmask, 0, 20);
							for(j=0; j<16; j++) {
								bitmask[j] = (blp & ( 1 << j )) >> j ? '1' : '0';
							}
							bitmask[16] = '\n';
							ICE_DEBUG2("[%d] %u / %s", i, pid, bitmask);
                     (void)pid;
						}
					}
				} else if(fmt == 3) {	/* rfc5104 */
					/* TMMBR: http://tools.ietf.org/html/rfc5104#section-4.2.1.1 */
					DEBUG(log, "FIXSSRC #%d TMMBR -- RTPFB (205)", pno);
					if(fixssrc && newssrcr) {
						uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
						*ssrc = htonl(newssrcr);
					}
				} else {
					DEBUG(log, "FIXSSRC #%d ??? -- RTPFB (205, fmt=%d)", pno, fmt);
				}

				if(fixssrc && newssrcl) {
					rtcpfb->ssrc = htonl(newssrcl);
				}
				break;
			}

			case RTCP_PSFB: {
				int fmt = rtcp->rc;
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				DEBUG(log, "FIXSSRC PSFB (206), pno=%u, fmt=%u, ssrc=%u", pno, fmt, ntohl(rtcpfb->ssrc));
				if (fmt == 1) {
					DEBUG(log, "PLI -- PSFB (206), pno=%u", pno);
					if (fixssrc && newssrcr) {
						rtcpfb->media = htonl(newssrcr);
					}
				} else if(fmt == 2) {
					ICE_DEBUG2("#%d SLI -- PSFB (206)", pno);
				} else if(fmt == 3) {
					ICE_DEBUG2("#%d RPSI -- PSFB (206)", pno);
				} else if(fmt == 4) {	/* rfc5104 */
					/* FIR: http://tools.ietf.org/html/rfc5104#section-4.3.1.1 */
					ICE_DEBUG2("#%d FIR -- PSFB (206)", pno);
					if(fixssrc && newssrcr) {
						rtcpfb->media = htonl(newssrcr);
					}
					if(fixssrc && newssrcr) {
						uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
						*ssrc = htonl(newssrcr);
					}
				} else if(fmt == 5) {	/* rfc5104 */
					/* FIR: http://tools.ietf.org/html/rfc5104#section-4.3.2.1 */
					ICE_DEBUG2("#%d PLI -- TSTR (206)", pno);
					if(fixssrc && newssrcr) {
						uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
						*ssrc = htonl(newssrcr);
					}
				} else if(fmt == 15) {
					ICE_DEBUG2("This is a AFB!\n");
					rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
					rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
					if(remb->id[0] == 'R' && remb->id[1] == 'E' && remb->id[2] == 'M' && remb->id[3] == 'B') {
						ICE_DEBUG2("#%d REMB -- PSFB (206)", pno);
						if(fixssrc && newssrcr) {
							remb->ssrc[0] = htonl(newssrcr);
						}
						/* FIXME From rtcp_utility.cc */
						unsigned char *_ptrRTCPData = (unsigned char *)remb;
						_ptrRTCPData += 4;	// Skip unique identifier and num ssrc
						ICE_DEBUG2("%02X %02X %02X %02X", _ptrRTCPData[0], _ptrRTCPData[1], _ptrRTCPData[2], _ptrRTCPData[3]);
						uint8_t numssrc = (_ptrRTCPData[0]);
						uint8_t brExp = (_ptrRTCPData[1] >> 2) & 0x3F;
						uint32_t brMantissa = (_ptrRTCPData[1] & 0x03) << 16;
						brMantissa += (_ptrRTCPData[2] << 8);
						brMantissa += (_ptrRTCPData[3]);
						uint64_t bitRate = brMantissa << brExp;
						ICE_DEBUG2("REMB: %u * 2^%u = %u (%d SSRCs, %u)",
							brMantissa, brExp, bitRate, numssrc, ntohl(remb->ssrc[0]));
                  (void)numssrc;
                  (void)bitRate;
					} else {
						ICE_DEBUG2("#%d AFB ?? -- PSFB (206)", pno);
					}
				} else {
					ICE_DEBUG2("#%d ?? -- PSFB (206, fmt=%d)", pno, fmt);
				}
				if(fixssrc && newssrcl) {
					rtcpfb->ssrc = htonl(newssrcl);
				}
				break;
			}
			default:
				ICE_ERROR2("Unknown RTCP PT %d", rtcp->pt);
				break;
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->len);
		ICE_DEBUG2("RTCP PT length: %d bytes", length*4+4);
		if(length == 0) {
			//ICE_DEBUG2("0-length, end of compound packet\n");
			break;
		}
		total -= length*4+4;
		//ICE_DEBUG2("Packet has length %d (%d bytes, %d remaining), moving to next one...", length, length*4+4, total);
		if(total <= 0) {
			ICE_DEBUG2("End of compound packet");
			break;
		}
		rtcp = (rtcp_hdr_t *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

void 
snw_rtcp_get_nacks(snw_ice_session_t *s, snw_ice_component_t *c, 
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
		if (rtcp->hdr.pt == RTCP_RTPFB && rtcp->hdr.rc == GENERIC_FMT) {
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
snw_gen_rtcp_fir(snw_ice_context_t *ice_ctx, char *packet, int len, int *seqnr) {
   snw_log_t *log = 0;

   if (!ice_ctx) return -1;
   log = ice_ctx->log;

	if (!packet || len != 20 || !seqnr)
		return -1;

   memset(packet, 0, len);
	rtcp_hdr_t *rtcp = (rtcp_hdr_t *)packet;
	*seqnr = *seqnr + 1;
	if(*seqnr < 0 || *seqnr >= 256)
		*seqnr = 0;	/* Reset sequence number */
	/* Set header */
	rtcp->v = 2;
	rtcp->pt = RTCP_PSFB;
	rtcp->rc = 4;	/* FMT=4 */
	rtcp->len = htons((len/4)-1);
	/* Now set FIR stuff */
	rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
	rtcp_fir *fir = (rtcp_fir *)rtcpfb->fci;
	fir->seqno = htonl(*seqnr << 24);	/* FCI: Sequence number */
	WARN(log, "[FIR] seqnr=%d (%d bytes)", *seqnr, 4*(ntohs(rtcp->len)+1));
	return 20;
}

int snw_gen_rtcp_pli(char *packet, int len) {
	if(packet == NULL || len != 12)
		return -1;
	memset(packet, 0, len);
	rtcp_hdr_t *rtcp = (rtcp_hdr_t *)packet;
	/* Set header */
	rtcp->v = 2;
	rtcp->pt = RTCP_PSFB;
	rtcp->rc = 1;	/* FMT=1 */
	rtcp->len = htons((len/4)-1);
	return 12;
}

int 
snw_ice_rtcp_generate_nacks(char *packet, int len, std::vector<int> nacks) {
	if(packet == NULL || len < 16 || nacks.size() == 0)
		return -1;
	memset(packet, 0, len);
	rtcp_hdr_t *rtcp = (rtcp_hdr_t *)packet;
	/* Set header */
	rtcp->v = 2;
	rtcp->pt = RTCP_RTPFB;
	rtcp->rc = 1;	/* FMT=1 */
	/* Now set NACK stuff */
	rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
	rtcp_nack *nack = (rtcp_nack *)rtcpfb->fci;

	/* FIXME We assume the GSList list is already ordered... */
	//uint16_t pid = GPOINTER_TO_UINT(nacks->data);
	uint16_t pid = nacks[0];
	nack->pid = htons(pid);
	//nacks = nacks->next;
	int words = 3;

   for (unsigned int i=1; i<nacks.size(); i++) {
		uint16_t npid = nacks[i];
		if(npid-pid < 1) {
			ICE_DEBUG2("Skipping PID to NACK, npid=%u, pid=%u", npid, pid);
		} else if(npid-pid > 16) {
			/* We need a new block: this sequence number will be its root PID */
			ICE_DEBUG2("Adding another block of NACKs, npid=%u, pid=%u, delta=%u", npid, pid, npid-pid);
			words++;
			if(len < (words*4+4)) {
				ICE_DEBUG2("Buffer too small, len=%d, nack_blocks=%d, words=%d", len, words, words*4+4);
				return -1;
			}
			char *new_block = packet + words*4;
			nack = (rtcp_nack *)new_block;
			//pid = GPOINTER_TO_UINT(nacks->data);
			pid = nacks[i];
			nack->pid = htons(pid);
		} else {
			uint16_t blp = ntohs(nack->blp);
			blp |= 1 << (npid-pid-1);
			nack->blp = htons(blp);
		}
		//nacks = nacks->next;
	}
	rtcp->len = htons(words);
	return words*4+4;
}


