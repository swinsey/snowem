#ifndef _SNOW_ICE_RTP_H
#define _SNOW_ICE_RTP_H

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <string.h>

#include "ice_types.h"

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

#define DEFAULT_MAX_NACK_QUEUE   300
#define MAX_NACK_IGNORE       100000 /* retransmission time (100ms) */
#define SEQ_MISSING_WAIT 12000 /*  12ms */
#define SEQ_NACKED_WAIT 155000 /* 155ms */

typedef struct seq_info seq_info_t;
struct seq_info {
   int64_t ts;
   uint16_t seq;
   uint16_t state;
   seq_info_t *next;
   seq_info_t *prev;
};

enum {
   SEQ_MISSING,
   SEQ_NACKED,
   SEQ_GIVEUP,
   SEQ_RECVED
};

void 
snw_ice_seq_append(seq_info_t **head, seq_info_t *new_seq);

seq_info_t *
snw_ice_seq_pop_head(seq_info_t **head);

void 
snw_ice_seq_list_free(seq_info_t **head);

int 
snw_ice_seq_in_range(uint16_t seqn, uint16_t start, uint16_t len);

void 
snw_ice_handle_incoming_rtp(snw_ice_session_t *handle, int type, int video, char *buf, int len);

#endif
