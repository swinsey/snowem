#ifndef _ICE_COMPONENT_H_
#define _ICE_COMPONENT_H_

#include <stdint.h>
#include <jansson.h>

#include "cicero/agent.h"
#include "dtls.h"
#include "types.h"
#include "packet.h"
#include "vp8.h"
#include "rtp.h"


typedef struct stats_item stats_item_t;
struct stats_item {
   uint64_t bytes; /* Bytes sent or received */
   int64_t when;   /* Time at which this happened */
};
  
typedef struct ice_trickle ice_trickle_t;
struct ice_trickle {
   ice_session_t *session;    /* Janus ICE handle this trickle candidate belongs to */
   int64_t received;         /* Monotonic time of when this trickle candidate has been received */
   char *transaction;        /* Janus API transaction ID of the original trickle request */
   json_t *candidate;        /* JSON object of the trickle candidate(s) */
};

/* Media statistics */
typedef struct ice_stats ice_stats_t;
struct ice_stats {
   uint32_t audio_packets;     /* Audio packets sent or received */
   uint64_t audio_bytes;       /* Audio bytes sent or received */
   int audio_notified_lastsec; /* Whether or not we notified about audio lastsec issues already */
   uint32_t audio_nacks;       /* Number of audio NACKs sent or received */
   uint32_t video_packets;     /* Video packets sent or received */
   uint64_t video_bytes;       /* Video bytes sent or received */
   int video_notified_lastsec; /* Whether or not we notified about video lastsec issues already */
   uint32_t video_nacks;       /* Number of video NACKs sent or received */
   uint32_t data_packets;      /* Data packets sent or received */
   uint64_t data_bytes;        /* Data bytes sent or received */
};

#define LAST_SEQS_MAX_LEN 160
struct ice_component {
   ice_stream_t *stream;
   uint32_t stream_id;
   uint32_t component_id;

   int state;
   int is_started;                    /* Whether the setup of remote candidates for this component has started or not */

   candidate_t candidates;            /* list of remote candidates */
   dtls_ctx_t *dtls;                  /* DTLS-SRTP stack */

   uint64_t retransmit_log_ts;        /* Last time a log message about sending retransmits was printed */
   uint32_t retransmit_recent_cnt;    /* Number of retransmitted packets since last log message */
   uint64_t nack_sent_log_ts;         /* Last time a log message about sending NACKs was printed */
   uint32_t nack_sent_recent_cnt;     /* Number of NACKs sent since last log message */
   seq_info_t *last_seqs_audio;       /* List of recently received audio sequence numbers (as a support to NACK generation) */
   seq_info_t *last_seqs_video;       /* List of recently received video sequence numbers (as a support to NACK generation) */

   uint64_t last_slowlink_time;       /* Last time the slow_link callback (of the plugin) was called */
   uint64_t sl_nack_period_ts;        /* Start time of recent NACKs (for slow_link) */
   uint32_t sl_nack_recent_cnt;       /* Count of recent NACKs (for slow_link) */
   //ice_stats_t in_stats;          /* Stats for incoming data (audio/video/data) */
   //ice_stats_t out_stats;         /* Stats for outgoing data (audio/video/data) */

   int64_t fir_latest;   
   int     fir_seq;

   rtp_packet_t retransmit_buffer;    /* RTP packets list for restransmission */
   rtp_packet_t rtplist;              /* list of recent frames */

   struct list_head list;
};

void component_mempool_init();
ice_component_t* component_allocate();
void component_deallocate(ice_component_t* p);
ice_component_t* component_find(ice_component_t *head, uint32_t id);
void component_insert(ice_component_t *head, ice_component_t *item);

#endif // ICE_COMPONENT_H_




