#ifndef _SNOW_ICE_STREAM_H_
#define _SNOW_ICE_STREAM_H_

#include <inttypes.h>

#include "core.h"
#include "dtls.h"
#include "ice_component.h"
#include "ice_types.h"
#include "linux_list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct snw_ice_stream {
   uint32_t stream_id;

   snw_ice_session_t *session;

   uint32_t audio_ssrc;
   uint32_t video_ssrc;
   uint32_t audio_ssrc_peer;
   uint32_t video_ssrc_peer;

   int payload_type;              /* rtp payload type */
   int dtls_role;                 /* dtls role */
   //char *rhashing;                /* hashing algorhitm for dtls */
   //char *rfingerprint;            /* hashed fingerprint in SDP */
   //char *ruser;                   /* ice username */
   //char *rpass;                   /* ice password */
   char rhashing[16];                /* hashing algorhitm for dtls */
   char rfingerprint[256];            /* hashed fingerprint in SDP */
   char ruser[32];                   /* ice username */
   char rpass[64];                   /* ice password */

   ice_component_t components;      /* list of components */
   ice_component_t *rtp_component;  /* rtp component */
   ice_component_t *rtcp_component; /* rtcp component */

   uint8_t cdone:1;
   uint8_t disabled:1;              /* a stream has been disabled or not (e.g., m=audio 0) */

   struct list_head list;
};

void
snw_stream_mempool_init(snw_ice_context_t *ctx);

snw_ice_stream_t*
snw_stream_allocate(snw_ice_context_t *ctx);

void
snw_stream_deallocate(snw_ice_context *ctx, snw_ice_stream_t* p);

snw_ice_stream_t* 
snw_stream_find(snw_ice_stream_t *head, uint32_t id);

void
snw_stream_insert(snw_ice_stream_t *head, snw_ice_stream_t *item);

void
snw_stream_free(snw_ice_stream_t *streams, snw_ice_stream_t *stream);


#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_STREAM_H_



