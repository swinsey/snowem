#ifndef _ICE_RTP_H
#define _ICE_RTP_H

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>

#include "icetypes.h"

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

/* SDP offer/answer templates */
#define OPUS_PT      111
#define VP8_PT    100
#define sdp_template \
      "v=0\r\n" \
      "o=- %lu %lu IN IP4 127.0.0.1\r\n"  /* We need current time here */ \
      "s=%s\r\n"                          /* Recording playout id */ \
      "t=0 0\r\n" \
      "%s%s"                              /* Audio and/or video m-lines */
#define sdp_audio_mline \
      "m=audio 1 RTP/SAVPF %d\r\n"        /* Opus payload type */ \
      "c=IN IP4 1.1.1.1\r\n" \
      "a=%s\r\n"                          /* Media direction */ \
      "a=rtpmap:%d opus/48000/2\r\n"      /* Opus payload type */
#define sdp_video_mline \
      "m=video 1 RTP/SAVPF %d\r\n"        /* VP8 payload type */ \
      "c=IN IP4 1.1.1.1\r\n" \
      "a=%s\r\n"                          /* Media direction */ \
      "a=rtpmap:%d VP8/90000\r\n"         /* VP8 payload type */ \
      "a=rtcp-fb:%d ccm fir\r\n"          /* VP8 payload type */ \
      "a=rtcp-fb:%d nack\r\n"             /* VP8 payload type */ \
      "a=rtcp-fb:%d nack pli\r\n"         /* VP8 payload type */ \
      "a=rtcp-fb:%d goog-remb\r\n"        /* VP8 payload type */

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

void ice_seq_append(seq_info_t **head, seq_info_t *new_seq);
seq_info_t *ice_seq_pop_head(seq_info_t **head);
void ice_seq_list_free(seq_info_t **head);
int ice_seq_in_range(uint16_t seqn, uint16_t start, uint16_t len);
void ice_handle_incoming_rtp(ice_session_t *handle, int type, int video, char *buf, int len);

#endif
