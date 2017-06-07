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

#ifdef __cplusplus
extern "C" {
#endif

#define RTCP_VERSION    2
#define RTCP_LENGTH_IN_WORDS 4
#define RTCP_HDR_LENGTH 4
#define RTCP_PKT_NUM_MAX 31

/* rtcp payload type */
#define RTCP_FIR   192
#define RTCP_SR    200
#define RTCP_RR    201
#define RTCP_SDES  202
#define RTCP_BYE   203
#define RTCP_APP   204
 
#define RTCP_RTPFB 205
#define RTCP_RTPFB_GENERIC_FMT 1

/* see rfc4858, rfc5104 */
#define RTCP_PSFB  206
#define RTCP_PSFB_PLI_FMT       1
#define RTCP_PSFB_SLI_FMT       2
#define RTCP_PSFB_RPSI_FMT      3
#define RTCP_PSFB_FIR_FMT       4
#define RTCP_PSFB_TSTR_FMT      5
#define RTCP_PSFB_TSTN_FMT      6
#define RTCP_PSFB_VBCM_FMT      7
#define RTCP_PSFB_APP_FMT       15

#define RTCP_PSFB_PLI_MSG_LEN   12
#define RTCP_PSFB_FIR_MSG_LEN   20
  
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

typedef struct snw_report_block snw_report_block_t;
struct snw_report_block
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

typedef struct snw_rtcp_sr snw_rtcp_sr_t;
struct snw_rtcp_sr
{
	uint32_t ssrc;
	uint32_t ntp_secs;
	uint32_t ntp_frac;
	uint32_t rtp_ts;
	uint32_t packet_cnt;
	uint32_t octet_cnt;
	snw_report_block_t rb[1];
};

typedef struct snw_rtcp_rr snw_rtcp_rr_t;
struct snw_rtcp_rr
{
	uint32_t       ssrc;
	snw_report_block_t rb[1];
};

typedef struct snw_rtcp_nack snw_rtcp_nack_t;
struct snw_rtcp_nack
{
	uint16_t pid;
	uint16_t blp;
};

typedef struct snw_rtcp_fir snw_rtcp_fir_t;
struct snw_rtcp_fir
{
	uint32_t ssrc;
	uint32_t seqno;
};


typedef struct snw_rtcp_fb snw_rtcp_fb_t;
struct snw_rtcp_fb
{
	uint32_t ssrc;
	uint32_t media;
	union fci {
      snw_rtcp_nack_t nack[1];
      snw_rtcp_fir_t  fir[1];
   } fci;
};

typedef struct rtcp_pkt rtcp_pkt_t;
struct rtcp_pkt {
   rtcp_hdr_t hdr;
   union pkt {
      snw_rtcp_sr_t   sr;
      snw_rtcp_rr_t   rr;

      /* feedback msg */
      snw_rtcp_fb_t   fb;
   } pkt;
}__attribute__((packed));

typedef int (*resend_callback_fn)(snw_ice_session_t *session, 
                 snw_ice_component_t *component,
                 int video, int seqnr, int64_t now);

int
snw_rtcp_has_payload_type(char *buf, int len, int type);

uint32_t
snw_rtcp_get_ssrc(snw_ice_session_t *s, char *buf, int len);

void 
snw_rtcp_handle_nacks(snw_ice_session_t *s, snw_ice_component_t *c, 
       int video, char *buf, int len, resend_callback_fn);

int
snw_gen_rtcp_fir(char *buf, int len, uint32_t local_ssrc, 
       uint32_t remote_ssrc, int seqnr);

int snw_gen_rtcp_pli(char *buf, int len,
      uint32_t local_ssrc, uint32_t remote_ssrc);

#ifdef __cplusplus
}
#endif

#endif
