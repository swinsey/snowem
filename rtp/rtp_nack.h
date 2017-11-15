#ifndef _SNOW_RTP_NACK_H_
#define _SNOW_RTP_NACK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rtp/rtp.h"

int snw_rtp_nack_init(void *ctx);
int snw_rtp_nack_handle_pkg(void *ctx, char *buffer, int len);
int snw_rtp_nack_hanle_pkg_next(void *ctx, char *buffer, int len);
int snw_rtp_nack_fini();

extern snw_rtp_module_t g_rtp_nack_module;

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_NACK_H_



