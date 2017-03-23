#ifndef _SNOW_ICE_RTP_H
#define _SNOW_ICE_RTP_H

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>

#include "ice_types.h"

#define RTP_HEADER_SIZE	12

/*! \brief RTP Header (http://tools.ietf.org/html/rfc3550#section-5.1) */
typedef struct rtp_header
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t extension:1;
	uint16_t csrccount:4;
	uint16_t markerbit:1;
	uint16_t type:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t csrccount:4;
	uint16_t extension:1;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:7;
	uint16_t markerbit:1;
#endif
	uint16_t seq_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[16];
} rtp_header;

/* RTP extension */
typedef struct rtp_header_extension {
	uint16_t type;
	uint16_t length;
} rtp_header_extension;

#define DEFAULT_MAX_NACK_QUEUE   300
#define MAX_NACK_IGNORE       100000 /* retransmission time (100ms) */
#define SEQ_MISSING_WAIT 12000 /*  12ms */
#define SEQ_NACKED_WAIT 155000 /* 155ms */

extern uint16_t g_rtp_range_min;
extern uint16_t g_rtp_range_max;
extern int g_max_nack_queue;

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
