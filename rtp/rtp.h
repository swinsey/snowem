#ifndef _SNOW_RTP_H_
#define _SNOW_RTP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "core/types.h"
#include "core/linux_list.h"
#include "ice/ice.h"
#include "rtmp/srs_librtmp.h"

#define RTP_VERSION         2
#define RTP_HEADER_SIZE     12
#define MIN_RTP_HEADER_SIZE RTP_HEADER_SIZE

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



typedef struct snw_rtp_module snw_rtp_module_t;
struct snw_rtp_module {
   char  *name;
   void  *ctx;
   int  (*init)(void *ctx);
   int  (*handle_pkg)(void *ctx, char *buffer, int len);
   int  (*fini)();

   snw_rtp_module_t *next;
};

typedef struct snw_rtp_ctx snw_rtp_ctx_t;
struct snw_rtp_ctx {
   void      *session;
   snw_log_t *log;

   // rtmp settings
   char               *rtmp_url;
   int                 rtmp_inited;
   int64_t             first_video_ts;
   int64_t             current_ts;
   srs_rtmp_t          rtmp; //pointer to void

   int64_t             pts;

   // rtmp aac
   char               *audio_pos;
   char               *audio_raw;
   off_t               file_size;
   uint32_t            delta_ts;
   uint32_t            audio_ts;

};

int
snw_rtp_init(snw_ice_context_t *ctx);

int
snw_rtp_handle_pkg(snw_rtp_ctx_t *ctx, char *buffer, int len);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_H_



