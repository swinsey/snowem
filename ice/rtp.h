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

#define DEFAULT_MAX_NACK_QUEUE   300
#define MAX_NACK_IGNORE       100000 /* retransmission time (100ms) */
#define SEQ_MISSING_WAIT 12000 /*  12ms */
#define SEQ_NACKED_WAIT 155000 /* 155ms */
#define LAST_SEQS_MAX_LEN 160

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

#define RTP_SEQ_NUM_MAX   (1<<16)
#define RTP_SLIDEWIN_SIZE 16
#define RTP_SYNC_TIME_MAX 500000 //500ms

#define RTP_MISS 0
#define RTP_RECV 1

typedef struct nack_data nack_data_t;
struct nack_data {
   uint16_t seq;
   uint16_t blp;
};
typedef struct nack_payload nack_payload_t;
struct nack_payload {
   union {
      nack_data_t pl;
      uint32_t    num;
   } data;
};

typedef struct rtp_seq rtp_seq_t;
struct rtp_seq {
   uint16_t  seq;
   uint16_t  status;
   uint64_t  ts;
   char     *pkt;
   int       len;
};

typedef struct rtp_slidewin rtp_slidewin_t;
struct rtp_slidewin {
   uint16_t   head;
   uint16_t   last_seq;
   int64_t    last_ts;
   rtp_seq_t  seqlist[RTP_SLIDEWIN_SIZE];
};

void
snw_rtp_slidewin_put(snw_ice_session_t *session, rtp_slidewin_t *win, uint16_t seq);

void 
snw_ice_handle_incoming_rtp(snw_ice_session_t *handle, 
      int type, int video, char *buf, int len);

#ifdef __cplusplus
}
#endif

#endif
