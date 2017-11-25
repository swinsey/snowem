#ifndef _SNOW_RTP_NACK_H_
#define _SNOW_RTP_NACK_H_

#include "rtp/rtcp.h"
#include "rtp/rtp.h"

#ifdef __cplusplus
extern "C" {
#endif

int snw_rtp_nack_init(void *ctx);
int snw_rtp_nack_handle_pkg(void *ctx, char *buffer, int len);
int snw_rtp_nack_fini();

extern snw_rtp_module_t g_rtp_nack_module;

int snw_rtcp_nack_handle_pkg(snw_rtp_ctx_t* ctx, rtcp_pkt_t *rtcp);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_NACK_H_



