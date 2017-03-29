#ifndef _SNOW_ICE_COMPONENT_H_
#define _SNOW_ICE_COMPONENT_H_

#include <stdint.h>
#include <jansson.h>

#include "cicero/agent.h"
#include "core.h"
#include "dtls.h"
#include "ice_types.h"
#include "packet.h"
#include "rtp.h"
#include "vp8.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LAST_SEQS_MAX_LEN 160
struct ice_component {
   snw_ice_stream_t *stream;
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

   int64_t fir_latest;   
   int     fir_seq;

   rtp_packet_t retransmit_buffer;    /* RTP packets list for restransmission */
   rtp_packet_t rtplist;              /* list of recent frames */

   struct list_head list;
};

void
snw_component_mempool_init(snw_ice_context_t *ctx);

ice_component_t*
snw_component_allocate(snw_ice_context_t *ctx);

void
snw_component_deallocate(snw_ice_context_t *ctx, ice_component_t* p);

ice_component_t*
snw_component_find(ice_component_t *head, uint32_t id);

void
snw_component_insert(ice_component_t *head, ice_component_t *item);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_ICE_COMPONENT_H_




