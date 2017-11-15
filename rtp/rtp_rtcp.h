#ifndef _SNOW_RTP_RTCP_H_
#define _SNOW_RTP_RTCP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rtp/rtp.h"

int snw_rtp_rtcp_init(void *ctx);
int snw_rtp_rtcp_handle_pkg(void *ctx, char *buffer, int len);
int snw_rtp_rtcp_hanle_pkg_next(void *ctx, char *buffer, int len);
int snw_rtp_rtcp_fini();

extern snw_rtp_module_t g_rtp_rtcp_module;

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_RTCP_H_



