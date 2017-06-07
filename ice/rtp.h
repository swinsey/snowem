#ifndef _SNOW_ICE_RTP_H
#define _SNOW_ICE_RTP_H

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <string.h>

#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RTP_VERSION    2
#define RTP_HEADER_SIZE	12

typedef struct rtp_hdr rtp_hdr_t;
struct rtp_hdr
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t v:2;
	uint16_t p:1;
	uint16_t x:1;
	uint16_t cc:4;
	uint16_t m:1;
	uint16_t pt:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t cc:4;
	uint16_t x:1;
	uint16_t p:1;
	uint16_t v:2;
	uint16_t pt:7;
	uint16_t m:1;
#endif
	uint16_t seq;
	uint32_t ts;
	uint32_t ssrc;
	uint32_t csrc[1];
};

/* RTP extension */
typedef struct rtp_hdr_ext rtp_hdr_ext_t;
struct rtp_hdr_ext {
	uint16_t type;
	uint16_t len;
};

void 
snw_ice_handle_incoming_rtp(snw_ice_session_t *handle, 
      int type, int video, char *buf, int len);

#ifdef __cplusplus
}
#endif

#endif
