#ifndef _SNOW_RTP_H264_H_
#define _SNOW_RTP_H264_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rtp/rtp.h"

int snw_rtp_h264_init(void *ctx);
int snw_rtp_h264_handle_pkg(void *ctx, char *buffer, int len);
int snw_rtp_h264_hanle_pkg_next(void *ctx, char *buffer, int len);
int snw_rtp_h264_fini();

extern snw_rtp_module_t g_rtp_h264_module;

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_H264_H_



