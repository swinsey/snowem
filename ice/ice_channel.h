#ifndef _SNOW_ICE_CHANNEL_H_
#define _SNOW_ICE_CHANNEL_H_

#include "core/types.h"
#include "ice_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SNW_ICE_CHANNEL_USER_NUM_MAX 5
typedef struct snw_ice_channel snw_ice_channel_t;
struct snw_ice_channel {
   uint32_t id;     //channelid
   uint32_t peerid; //owner's peerid
   uint32_t players[SNW_ICE_CHANNEL_USER_NUM_MAX];
};

int
snw_ice_channel_init(snw_ice_context_t *ctx);

snw_ice_channel_t*
snw_ice_channel_get(snw_ice_context_t *ctx, uint32_t id, int *is_new);

snw_ice_channel_t*
snw_ice_channel_search(snw_ice_context_t *ctx, uint32_t id);

snw_ice_channel_t*
snw_ice_channel_insert(snw_ice_context_t *ctx, snw_ice_channel_t *sitem);

int 
snw_ice_channel_remove(snw_ice_context_t *ctx, snw_ice_channel_t *sitem);

void
snw_print_channel_info(snw_ice_context_t *ctx, snw_ice_channel_t *c);

void
snw_channel_add_subscriber(snw_ice_context_t *ctx, uint32_t channelid, uint32_t flowid);


#ifdef __cplusplus
}
#endif

#endif //_SNOW_ICE_CHANNEL_H_
