#include "log.h"
#include "ice_types.h"
#include "rtcp.h"

int
snw_rtcp_fix_ssrc(char *packet, int len, int fixssrc, uint32_t newssrcl, uint32_t newssrcr) {
	rtcp_hdr_t *rtcp = NULL;
	int pno = 0, total = len;

	if (!packet || len == 0)
		return -1;

	rtcp = (rtcp_hdr_t *)packet;
	if (rtcp->v != 2)
		return -2;

	ICE_DEBUG2("Parsing compound packet, total=%d", total);

	while (rtcp) {
		pno++;
		/* TODO Should we handle any of these packets ourselves, or just relay them? */
		switch(rtcp->pt) {
			case RTCP_SR: {
				/* SR, sender report */
				ICE_DEBUG2("#%d SR (200)", pno);
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
				ICE_DEBUG2("#%d RR (201)", pno);
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
				ICE_DEBUG2("#%d SDES (202)", pno);
				rtcp_sdes *sdes = (rtcp_sdes*)rtcp;
				ICE_DEBUG2("SSRC: %u", ntohl(sdes->ssrc));
				if(fixssrc && newssrcl) {
					sdes->ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_BYE: {
				/* BYE, goodbye */
				ICE_DEBUG2("#%d BYE (203)", pno);
				rtcp_bye_t *bye = (rtcp_bye_t*)rtcp;
				ICE_DEBUG2("SSRC: %u", ntohl(bye->ssrc[0]));
				if(fixssrc && newssrcl) {
					bye->ssrc[0] = htonl(newssrcl);
				}
				break;
			}
			case RTCP_APP: {
				/* APP, application-defined */
				ICE_DEBUG2("#%d APP (204)", pno);
				rtcp_app_t *app = (rtcp_app_t*)rtcp;
				ICE_DEBUG2("SSRC: %u", ntohl(app->ssrc));
				if(fixssrc && newssrcl) {
					app->ssrc = htonl(newssrcl);
				}
				break;
			}
			case RTCP_FIR: {
				/* FIR, rfc2032 */
				ICE_DEBUG2("%d FIR (192)", pno);
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
				ICE_DEBUG2("#%d RTPFB (205)", pno);
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
					ICE_DEBUG2("#%d TMMBR -- RTPFB (205)", pno);
					if(fixssrc && newssrcr) {
						uint32_t *ssrc = (uint32_t *)rtcpfb->fci;
						*ssrc = htonl(newssrcr);
					}
				} else {
					ICE_DEBUG2("#%d ??? -- RTPFB (205, fmt=%d)", pno, fmt);
				}

				if(fixssrc && newssrcl) {
					rtcpfb->ssrc = htonl(newssrcl);
				}
				break;
			}

			case RTCP_PSFB: {
				/* PSFB, Payload-specific FB message (rfc4585) */
				ICE_DEBUG2("#%d PSFB (206)", pno);
				int fmt = rtcp->rc;
				//~ JANUS_LOG(LOG_HUGE, "       -- FMT: %u\n", fmt);
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				//~ JANUS_LOG(LOG_HUGE, "       -- SSRC: %u\n", ntohl(rtcpfb->ssrc));
				if(fmt == 1) {
					ICE_DEBUG2("#%d PLI -- PSFB (206)", pno);
					if(fixssrc && newssrcr) {
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

/*
int snw_rtcp_has_type(char *packet, int len, int type) {
	int got_pli = 0;
	rtcp_hdr_t *rtcp = (rtcp_hdr_t *)packet;
	if(rtcp->v != 2)
		return 0;
	int pno = 0, total = len;
	while(rtcp) {
		pno++;
		switch(rtcp->pt) {
			case RTCP_PSFB: {
				int fmt = rtcp->rc;
				if(fmt == 1)
					got_pli = 1;
				break;
			}
			default:
				break;
		}
		// compound packet
		int length = ntohs(rtcp->len);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_hdr_t *)((uint32_t*)rtcp + length + 1);
	}
	return got_pli ? 1 : 0;
}
*/

void
snw_rtcp_get_nacks(char *packet, int len, std::vector<int> &nacklist) {
	rtcp_hdr_t *rtcp = NULL;

	if (!packet || len == 0)
		return;

	rtcp = (rtcp_hdr_t *)packet;
	if (rtcp->v != 2)
		return;

	// Get list of sequence numbers we should send again 
	int total = len;
	while(rtcp) {
		if(rtcp->pt == RTCP_RTPFB) {
			int fmt = rtcp->rc;
			if(fmt == 1) {
				rtcp_fb *rtcpfb = (rtcp_fb *)rtcp;
				int nacks = ntohs(rtcp->len)-2;	// Skip SSRCs
				if(nacks > 0) {
					ICE_DEBUG2("Got nacks, num=%d", nacks);
					rtcp_nack *nack = NULL;
					uint16_t pid = 0;
					uint16_t blp = 0;
					int i=0, j=0;
					char bitmask[20];
					for(i=0; i< nacks; i++) {
						nack = (rtcp_nack *)rtcpfb->fci + i;
						pid = ntohs(nack->pid);
                  nacklist.push_back(pid);
						blp = ntohs(nack->blp);
						memset(bitmask, 0, 20);
						for(j=0; j<16; j++) {
							bitmask[j] = (blp & ( 1 << j )) >> j ? '1' : '0';
							if((blp & ( 1 << j )) >> j) {
								nacklist.push_back(pid+j+1);
                     }
						}
						bitmask[16] = '\n';
						ICE_DEBUG2("[%d] %u / %s", i, pid, bitmask);
					}
				}
			}
		}
		// Is this a compound packet? 
		int length = ntohs(rtcp->len);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_hdr_t *)((uint32_t*)rtcp + length + 1);
	}
	return;
}

int
snw_rtcp_remove_nacks(char *packet, int len) {
	if(packet == NULL || len == 0)
		return len;
	rtcp_hdr_t *rtcp = (rtcp_hdr_t *)packet;
	if(rtcp->v != 2)
		return len;
	/* Find the NACK message */
	char *nacks = NULL;
	int total = len, nacks_len = 0;
	while(rtcp) {
		if(rtcp->pt == RTCP_RTPFB) {
			int fmt = rtcp->rc;
			if(fmt == 1) {
				nacks = (char *)rtcp;
			}
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->len);
		if(length == 0)
			break;
		if(nacks != NULL) {
			nacks_len = length*4+4;
			break;
		}
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (rtcp_hdr_t *)((uint32_t*)rtcp + length + 1);
	}
	if(nacks != NULL) {
		total = len - ((nacks-packet)+nacks_len);
		if(total < 0) {
			/* FIXME Should never happen, but you never know: do nothing */
			return len;
		} else if(total == 0) {
			/* NACK was the last compound packet, easy enough */
			return len-nacks_len;
		} else {
			/* NACK is between two compound packets, move them around */
			int i=0;
			for(i=0; i<total; i++)
				*(nacks+i) = *(nacks+nacks_len+i);
			return len-nacks_len;
		}
	}
	return len;
}

int snw_gen_rtcp_fir(snw_ice_context_t *ice_ctx, char *packet, int len, int *seqnr) {
   snw_log_t *log = 0;

   if (!ice_ctx) return -1;
   log = ice_ctx->log;

	if(packet == NULL || len != 20 || seqnr == NULL)
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
	fir->seqnr = htonl(*seqnr << 24);	/* FCI: Sequence number */
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


