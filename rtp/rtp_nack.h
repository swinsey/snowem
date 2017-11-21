#ifndef _SNOW_RTP_NACK_H_
#define _SNOW_RTP_NACK_H_

#include "rtp/rtcp.h"
#include "rtp/rtp.h"

#ifdef __cplusplus
extern "C" {
#endif

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

uint32_t
snw_rtp_slidewin_put(snw_ice_session_t *session, 
     rtp_slidewin_t *win, uint16_t seq);


int snw_rtp_nack_init(void *ctx);
int snw_rtp_nack_handle_pkg(void *ctx, char *buffer, int len);
int snw_rtp_nack_fini();

extern snw_rtp_module_t g_rtp_nack_module;

int snw_rtcp_nack_handle_pkg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_NACK_H_



