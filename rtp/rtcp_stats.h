#ifndef _SNOW_RTP_RTCP_STATS_H_
#define _SNOW_RTP_RTCP_STATS_H_

#include "core/linux_list.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct snw_rtcp_stats snw_rtcp_stats_t;
struct snw_rtcp_stats {
   uint16_t max_seq;
   uint32_t cycles;
   uint32_t base_seq;
   uint32_t bad_seq;
   uint32_t probation;
   uint32_t received;
   uint32_t expected_prior;
   uint32_t received_prior;
   uint32_t transit;
   uint32_t jitter;

   struct list_head list;
};

#ifdef __cplusplus
}
#endif

#endif
