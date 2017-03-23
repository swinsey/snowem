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

/*! http://www.networksorcery.com/enp/protocol/rtcp.htm */
typedef enum {
    RTCP_FIR = 192,
    RTCP_SR = 200,
    RTCP_RR = 201,
    RTCP_SDES = 202,
    RTCP_BYE = 203,
    RTCP_APP = 204,
    RTCP_RTPFB = 205,
    RTCP_PSFB = 206,
} rtcp_type;
 
 
/* http://tools.ietf.org/html/rfc3550#section-6.1 */
typedef struct rtcp_header
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t rc:5;
	uint16_t type:8;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rc:5;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:8;
#endif
	uint16_t length:16;
} rtcp_header;

/* http://tools.ietf.org/html/rfc3550#section-6.4.1 */
typedef struct sender_info
{
	uint32_t ntp_ts_msw;
	uint32_t ntp_ts_lsw;
	uint32_t rtp_ts;
	uint32_t s_packets;
	uint32_t s_octets;
} sender_info;

/* http://tools.ietf.org/html/rfc3550#section-6.4.1 */
typedef struct report_block
{
	uint32_t ssrc;
	uint32_t flcnpl;
	uint32_t ehsnr;
	uint32_t jitter;
	uint32_t lsr;
	uint32_t delay;
} report_block;

/* http://tools.ietf.org/html/rfc3550#section-6.4.1 */
typedef struct rtcp_sr
{
	rtcp_header header;
	uint32_t ssrc;
	sender_info si;
	report_block rb[1];
} rtcp_sr;

/* http://tools.ietf.org/html/rfc3550#section-6.4.2 */
typedef struct rtcp_rr
{
	rtcp_header header;
	uint32_t ssrc;
	report_block rb[1];
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
	char content[1];
} rtcp_sdes_item;

typedef struct rtcp_sdes
{
	rtcp_header header;
	uint32_t ssrc;
	rtcp_sdes_chunk chunk;
	rtcp_sdes_item item;
} rtcp_sdes;

/* http://tools.ietf.org/html/rfc3550#section-6.6 */
typedef struct rtcp_bye
{
	rtcp_header header;
	uint32_t ssrc[1];
} rtcp_bye_t;

/* http://tools.ietf.org/html/rfc3550#section-6.7 */
typedef struct rtcp_app
{
	rtcp_header header;
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
	rtcp_header header;
	uint32_t ssrc;
	uint32_t media;
	char fci[1];
} rtcp_fb;

uint32_t
snw_rtcp_get_sender_ssrc(char *packet, int len);

uint32_t
snw_rtcp_get_receiver_ssrc(char *packet, int len);

int
snw_rtcp_parse(char *packet, int len);

int
snw_rtcp_fix_ssrc(char *packet, int len, int fixssrc, uint32_t newssrcl, uint32_t newssrcr);

int
snw_rtcp_has_fir(char *packet, int len);

int
snw_rtcp_has_pli(char *packet, int len);

void 
snw_ice_rtcp_get_nacks(char *packet, int len, std::vector<int> &nacklist);

int 
snw_rtcp_remove_nacks(char *packet, int len);

uint64_t
snw_rtcp_get_remb(char *packet, int len);

int
snw_rtcp_cap_remb(char *packet, int len, uint64_t bitrate);

int
snw_gen_rtcp_sdes(char *packet, int len, const char *cname, int cnamelen);

int
snw_gen_rtcp_remb(char *packet, int len, uint64_t bitrate);

int
snw_gen_rtcp_fir(char *packet, int len, int *seqnr);

int
snw_gen_rtcp_fir_legacy(char *packet, int len, int *seqnr);

int
snw_gen_rtcp_pli(char *packet, int len);

int
snw_ice_rtcp_generate_nacks(char *packet, int len, std::vector<int> nacks);

#endif
