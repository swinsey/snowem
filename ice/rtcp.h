#ifndef _SNOW_ICE_RTCP_H
#define _SNOW_ICE_RTCP_H

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <vector>

#include "ice.h"

#define RTCP_FIR   192
#define RTCP_SR    200
#define RTCP_RR    201
#define RTCP_SDES  202
#define RTCP_BYE   203
#define RTCP_APP   204
#define RTCP_RTPFB 205
#define RTCP_PSFB  206
 
#define GENERIC_FMT 1
  
typedef struct rtcp_hdr rtcp_hdr_t;
struct rtcp_hdr 
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t v:2;
	uint8_t p:1;
	uint8_t rc:5;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t rc:5;
	uint8_t p:1;
	uint8_t v:2;
#endif
	uint8_t  pt;
	uint16_t len;
};

typedef struct report_block report_block_t;
struct report_block
{
	uint32_t ssrc;
#if __BYTE_ORDER == __BIG_ENDIAN
	uint32_t frac_lost:8;
	uint32_t cum_lost:24;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t cum_lost:24;
	uint32_t frac_lost:8;
#endif
	uint32_t highest_seqno;
	uint32_t jitter;
	uint32_t lsr;
	uint32_t dlsr;
};

typedef struct rtcp_sr
{
	rtcp_hdr_t hdr;
	uint32_t ssrc;
	uint32_t ntp_secs;
	uint32_t ntp_frac;
	uint32_t rtp_ts;
	uint32_t packet_cnt;
	uint32_t octet_cnt;
	report_block_t rb[1];
} rtcp_sr;

typedef struct rtcp_rr
{
	rtcp_hdr_t     hdr;
	uint32_t       ssrc;
	report_block_t rb[1];
} rtcp_rr;

/* http://tools.ietf.org/html/rfc3550#section-6.5 */
typedef struct rtcp_sdes_chunk
{
	uint32_t csrc;
} rtcp_sdes_chunk;

typedef struct rtcp_sdes_item
{
	uint8_t type;
	uint8_t len;
	char    content[1];
} rtcp_sdes_item;

typedef struct rtcp_sdes
{
	rtcp_hdr_t header;
	uint32_t ssrc;
	rtcp_sdes_chunk chunk;
	rtcp_sdes_item item;
} rtcp_sdes;

/* http://tools.ietf.org/html/rfc3550#section-6.6 */
typedef struct rtcp_bye
{
	rtcp_hdr_t header;
	uint32_t ssrc[1];
} rtcp_bye_t;

/* http://tools.ietf.org/html/rfc3550#section-6.7 */
typedef struct rtcp_app
{
	rtcp_hdr_t header;
	uint32_t ssrc;
	char name[4];
} rtcp_app_t;

/* http://tools.ietf.org/html/rfc4585#section-6.2.1 */
typedef struct rtcp_nack
{
	uint16_t pid;
	uint16_t blp;
} rtcp_nack;

typedef struct nack_seq {
	uint16_t seq_no;
	struct nack_seq *next;
} nack_seq;


/* look at http://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03 */
typedef struct rtcp_remb
{
	char id[4];
	uint32_t bitrate;
	uint32_t ssrc[1];
} rtcp_remb;


/* look at http://tools.ietf.org/search/rfc5104#section-4.3.1.1 */
typedef struct rtcp_fir
{
	uint32_t ssrc;
	uint32_t seqnr;
} rtcp_fir;


/* look at http://tools.ietf.org/html/rfc4585 */
typedef struct rtcp_fb
{
	rtcp_hdr_t header;
	uint32_t ssrc;
	uint32_t media;
	char fci[1];
} rtcp_fb;

int
snw_rtcp_fix_ssrc(char *packet, int len, int fixssrc, uint32_t newssrcl, uint32_t newssrcr);

//int
//snw_rtcp_has_type(char *packet, int len, int type);

void 
snw_rtcp_get_nacks(char *packet, int len, std::vector<int> &nacklist);

int 
snw_rtcp_remove_nacks(char *packet, int len);

int
snw_gen_rtcp_fir(snw_ice_context_t *ice_ctx, char *packet, int len, int *seqnr);

int
snw_gen_rtcp_pli(char *packet, int len);

int
snw_ice_rtcp_generate_nacks(char *packet, int len, std::vector<int> nacks);

#endif
