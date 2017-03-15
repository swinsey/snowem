#ifndef _MEDIASVR_STREAM_H_
#define _MEDIASVR_STREAM_H_

#include <inttypes.h>

#include "dtls.h"
#include "icetypes.h"
#include "linux_list.h"
#include "component.h"

struct ice_stream {
   uint32_t stream_id;

   ice_session_t *session;

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

void stream_mempool_init();
ice_stream_t* stream_allocate();
void stream_deallocate(ice_stream_t* p);
ice_stream_t* stream_find(ice_stream_t *head, uint32_t id);
void stream_insert(ice_stream_t *head, ice_stream_t *item);
void stream_free(ice_stream_t *streams, ice_stream_t *stream);



#endif // _CCD_STREAM_H_



