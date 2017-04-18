#ifndef _SNOW_ICE_SESSION_H_
#define _SNOW_ICE_SESSION_H_

#include <stdint.h>

#include "cicero/agent.h"
#include "ice_channel.h"
#include "ice_stream.h"
#include "ice_types.h"

struct snw_ice_session {
   uint32_t flowid;
   uint32_t channelid;
   uint32_t live_channelid;
   uint32_t forwardid;

   snw_ice_context_t *ice_ctx;
   struct event_base *base;
   agent_t           *agent;

   uint32_t status;
   uint32_t flags;                   /* WebRTC-related flags */
   uint32_t ready;
   
   char *sdp;                        /* Hold temporary local sdp */
   int cdone;                        /* Number of gathered candidates */
   int controlling;                  /* ICE role (controlling or controlled) */
   uint32_t audio_id;                /* audio ID */
   uint32_t video_id;                /* video ID */
   char *audio_mid;                  /* Audio mid (media ID) */
   char *video_mid;                  /* Video mid (media ID) */
   int streams_num;                  /* Number of streams */

   snw_ice_stream_t streams;
   snw_ice_stream_t *audio_stream;   /* Audio stream */
   snw_ice_stream_t *video_stream;   /* Video stream */

   char *rtp_profile;                /* RTP profile set by caller (so that we can match it) */
   char *local_sdp;                  /* SDP generated locally */
   char *remote_sdp;                 /* SDP received by the peer */

   int64_t created;                  /* created time */
   int64_t curtime;                  /* current time */
   int64_t lasttime; 

   char rhashing[16];                /* hashing algorhitm for dtls */
   char rfingerprint[256];           /* hashed fingerprint in SDP */
   char ruser[32];                   /* ice username */
   char rpass[64];                   /* ice password */

   //recorder_t* a_recorder;
   //recorder_t* v_recorder;
   snw_ice_channel_t  *channel;
};


int
snw_ice_session_init(snw_ice_context_t *ctx);

snw_ice_session_t*
snw_ice_session_get(snw_ice_context_t *ctx, uint32_t flowid, int *is_new);

snw_ice_session_t*
snw_ice_session_search(snw_ice_context_t *ctx, uint32_t flowid);

snw_ice_session_t*
snw_ice_session_insert(snw_ice_context_t *ctx, snw_ice_session_t *sitem);

int 
snw_ice_session_remove(snw_ice_context_t *ctx, snw_ice_session_t *sitem);

#endif //_SNOW_ICE_SESSION_H_


