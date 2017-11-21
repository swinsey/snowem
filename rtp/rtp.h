#ifndef _SNOW_RTP_RTP_H_
#define _SNOW_RTP_RTP_H_

#include "core/types.h"
#include "core/linux_list.h"
#include "core/log.h"
#include "ice/ice.h"
#include "rtmp/srs_librtmp.h"
#include "rtp/rtcp_stats.h"

#ifdef __cplusplus
extern "C" {
#endif

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


#define M_FLAGS_INIT (1<<0)

#define MODULE_SET_FLAG(m,flag) (m).flags &= flag;
#define MODULE_CLEAR_FLAG(m,flag) (m).flags &= ~flag;
#define MODULE_IS_FLAG(m,flag) ((m).flags & flag)

typedef struct snw_rtp_module snw_rtp_module_t;
struct snw_rtp_module {
   const char  *name;
   void  *ctx;
   int    pkt_type;
   int    flags;
   int  (*init)(void *ctx);
   int  (*handle_pkg)(void *ctx, char *buffer, int len);
   int  (*fini)();

   snw_rtp_module_t *next;
};

/* packet type */
#define   RTP_AUDIO  (1<<0)
#define   RTP_VIDEO  (1<<1)
#define   RTP_RTCP   (1<<2)

typedef struct snw_rtp_ctx snw_rtp_ctx_t;
struct snw_rtp_ctx {
   void      *session;
   void      *stream;
   void      *component;
   snw_log_t *log;

   int        pkt_type;

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

#define MAX_RECEIVER_NUM 2
   snw_rtcp_stats_t    sender_stats[MAX_RECEIVER_NUM];
   //snw_rtcp_stats_t    receiver_stats[MAX_RECEIVER_NUM];
};

int
snw_rtp_init(snw_ice_context_t *ctx);

void
print_rtp_header(snw_log_t *log, char *buf, int buflen, const char *msg);

int
snw_rtp_get_pkt_type(char* buf, int len);

int
snw_rtp_handle_pkg(snw_rtp_ctx_t *ctx, char *buffer, int len);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_RTP_RTP_H_



