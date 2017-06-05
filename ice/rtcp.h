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
#include "ice_types.h"
#include "ice_session.h"

#define RTCP_VERSION    2
#define RTCP_LENGTH_IN_WORDS 4
#define RTCP_HDR_LENGTH 4
#define RTCP_PKT_NUM_MAX 31

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

typedef struct rtcp_sr rtcp_sr_t;
struct rtcp_sr
{
	rtcp_hdr_t hdr;
	uint32_t ssrc;
	uint32_t ntp_secs;
	uint32_t ntp_frac;
	uint32_t rtp_ts;
	uint32_t packet_cnt;
	uint32_t octet_cnt;
	report_block_t rb[1];
};

typedef struct rtcp_rr rtcp_rr_t;
struct rtcp_rr
{
	rtcp_hdr_t     hdr;
	uint32_t       ssrc;
	report_block_t rb[1];
};

typedef struct rtcp_sdes_chunk rtcp_sdes_chunk_t;
struct rtcp_sdes_chunk
{
	uint32_t csrc;
};

typedef struct rtcp_sdes_item rtcp_sdes_item_t;
struct rtcp_sdes_item
{
	uint8_t type;
	uint8_t len;
	char    content[1];
};

typedef struct rtcp_sdes rtcp_sdes_t;
struct rtcp_sdes
{
	rtcp_hdr_t hdr;
	uint32_t ssrc;
	rtcp_sdes_chunk chunk;
	rtcp_sdes_item item;
};

typedef struct rtcp_bye rtcp_bye_t;
struct rtcp_bye
{
	rtcp_hdr_t hdr;
	uint32_t ssrc[1];
};

typedef struct rtcp_app rtcp_app_t;
struct rtcp_app
{
	rtcp_hdr_t hdr;
	uint32_t ssrc;
	char name[4];
};

typedef struct rtcp_nack rtcp_nack_t;
struct rtcp_nack
{
	uint16_t pid;
	uint16_t blp;
};

typedef struct nack_seq  nack_seq_t;
struct nack_seq {
	uint16_t seqno;
	struct nack_seq *next;
};


typedef struct rtcp_remb rtcp_remb_t;
struct rtcp_remb
{
	char id[4];
	uint32_t bitrate;
	uint32_t ssrc[1];
};

typedef struct rtcp_fir rtcp_fir_t;
struct rtcp_fir
{
	uint32_t ssrc;
	uint32_t seqno;
};


typedef struct rtcp_fb rtcp_fb_t;
struct rtcp_fb
{
	rtcp_hdr_t header;
	uint32_t ssrc;
	uint32_t media;
	char fci[1];
};

typedef struct snw_rtcp_nack snw_rtcp_nack_t;
struct snw_rtcp_nack
{
	uint16_t pid;
	uint16_t blp;
};


typedef struct snw_rtcp_fb snw_rtcp_fb_t;
struct snw_rtcp_fb
{
	uint32_t ssrc;
	uint32_t media;
	union fci {
      snw_rtcp_nack_t nack[1];
   } fci;
};


typedef struct snw_rtcp_sr snw_rtcp_sr_t;
struct snw_rtcp_sr
{
	uint32_t ssrc;
	uint32_t ntp_secs;
	uint32_t ntp_frac;
	uint32_t rtp_ts;
	uint32_t packet_cnt;
	uint32_t octet_cnt;
	report_block_t rb[1];
};

typedef struct snw_rtcp_rr snw_rtcp_rr_t;
struct snw_rtcp_rr
{
	uint32_t       ssrc;
	report_block_t rb[1];
};


typedef struct rtcp_pkt rtcp_pkt_t;
struct rtcp_pkt {
   rtcp_hdr_t hdr;
   union pkt {
      snw_rtcp_sr_t   sr;
      snw_rtcp_rr_t   rr;
      rtcp_sdes_t sdes;
      rtcp_bye_t  bye;
      rtcp_app_t  app;
      rtcp_remb_t remb;
      rtcp_fir_t  fir;
      snw_rtcp_fb_t   fb;
   } pkt;
}__attribute__((packed));

uint8_t
snw_rtcp_get_payload_type(snw_ice_session_t *s, char *buf, int len);

int
snw_rtcp_has_type(char *buf, int len, int type);

uint32_t
snw_rtcp_get_ssrc(snw_ice_session_t *s, char *buf, int len);

uint32_t
snw_rtcp_get_ssrc_new(snw_ice_session_t *s, char *buf, int len);

int
snw_rtcp_fix_ssrc(snw_ice_session_t *s, char *buf, int len, 
   int fixssrc, uint32_t newssrcl, uint32_t newssrcr);

typedef int (*resend_callback_fn)(snw_ice_session_t *session, snw_ice_component_t *component,
              int video, int seqnr, int64_t now);

void 
snw_rtcp_get_nacks(snw_ice_session_t *s, snw_ice_component_t *c, 
       int video, char *buf, int len, resend_callback_fn);

int
snw_gen_rtcp_fir(snw_ice_context_t *ice_ctx, char *buf, int len, int *seqnr);

int
snw_gen_rtcp_pli(char *buf, int len);

int
snw_ice_rtcp_generate_nacks(char *buf, int len, std::vector<int> nacks);

#endif
