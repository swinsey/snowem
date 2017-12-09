#include <stdlib.h>
#include <string.h>

<<<<<<< HEAD
#include "cache.h"
#include "log.h"
=======
#include "core/cache.h"
#include "core/log.h"
>>>>>>> dev
#include "ice.h"
#include "ice_channel.h"
#include "ice_types.h"


inline int
ice_channel_key(const void *item)
{  
   snw_ice_channel_t *so =  (snw_ice_channel_t *)item;
   return so->id;
}

inline int
ice_channel_eq(const void *arg1, const void *arg2)
{  
   snw_ice_channel_t *item1 = (snw_ice_channel_t *)arg1;
   snw_ice_channel_t *item2 = (snw_ice_channel_t *)arg2;
   return (item1->id == item2->id);
}

inline int
ice_channel_isempty(const void *arg)
{
   snw_ice_channel_t *item = (snw_ice_channel_t *)arg;
   return (item->id == 0);
}

inline int            
ice_channel_setempty(const void *arg)
{
   snw_ice_channel_t *item = (snw_ice_channel_t *)arg;
   item->id = 0;
   return 0;
}


int
snw_ice_channel_init(snw_ice_context_t *ctx) {
   ctx->channel_cache = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx->channel_cache == 0)
      return -1;
   snw_cache_init(ctx->channel_cache, ICE_CHANNEL_SHM_KEY, ICE_CHANNEL_HASHTIME, 
         ICE_CHANNEL_HASHLEN, sizeof(snw_ice_channel_t),1, ice_channel_eq, 
         ice_channel_key, ice_channel_isempty, ice_channel_setempty);

   return 0;
}

snw_ice_channel_t*
snw_ice_channel_get(snw_ice_context_t *ctx, uint32_t id, int *is_new) {
   snw_ice_channel_t key;
   snw_ice_channel_t *so;
   
   key.id = id;
   so = CACHE_GET(ctx->channel_cache, &key, is_new, snw_ice_channel_t*);

   if (so == 0) return 0;

   if (!(*is_new)) return so;

   // reset new channel
   memset(so, 0, sizeof(snw_ice_channel_t));
   so->id = id;

   return so;
}

/*CACHE_SEARCH(ctx->channel_cache, sitem, snw_ice_channel_t*);*/
snw_ice_channel_t*
snw_ice_channel_search(snw_ice_context_t *ctx, uint32_t id) {
   snw_ice_channel_t sitem;
   sitem.id = id;
   return (snw_ice_channel_t*)snw_cache_search(ctx->channel_cache, &sitem);
}

/*CACHE_INSERT(ctx->channel_cache, sitem, snw_ice_channel_t*);*/
snw_ice_channel_t*
snw_ice_channel_insert(snw_ice_context_t *ctx, snw_ice_channel_t *sitem) {
   return (snw_ice_channel_t*)snw_cache_insert(ctx->channel_cache, sitem);
}

/*CACHE_REMOVE(ctx->channel_cache, sitem, snw_ice_channel_t*);*/
int 
snw_ice_channel_remove(snw_ice_context_t *ctx, snw_ice_channel_t *sitem) {
   return snw_cache_remove(ctx->channel_cache, sitem);
}


<<<<<<< HEAD
void
snw_print_channel_info(snw_ice_context_t *ctx, snw_ice_channel_t *c) {

   if (!ctx) return;

   DEBUG(ctx->log, "channel info, id=%u, ownerid=%u, players= %u %u %u %u %u", 
         c->id, c->ownerid, c->players[0], c->players[1], c->players[2],
         c->players[3], c->players[4]);

   return;

}

void
snw_channel_add_subscriber(snw_ice_context_t *ice_ctx, uint32_t channelid, uint32_t flowid) {
=======
#ifdef SNW_ENABLE_DEBUG
void
snw_print_channel_info(snw_ice_context_t *ctx, snw_ice_channel_t *c) {
   static char buffer[SNW_ICE_CHANNEL_USER_NUM_MAX * 11];
   int i = 0;

   if (!ctx) return;

   memset(buffer,0, SNW_ICE_CHANNEL_USER_NUM_MAX * 11);
   for(i=0; i< SNW_ICE_CHANNEL_USER_NUM_MAX; i++) {
      sprintf(buffer + i*10, "%9u ", c->players[i]);
   }
   DEBUG(ctx->log, "channel info, id=%u, idx=%u, players= %s",
         c->id, c->idx, buffer);
   return;

}
#endif

void
snw_channel_add_subscriber(snw_ice_context_t *ice_ctx, 
      uint32_t channelid, uint32_t flowid) {
>>>>>>> dev
   snw_log_t *log = 0;
   snw_ice_channel_t *channel = 0;
   int found = 0;

   if (!ice_ctx) return;
   log = ice_ctx->log;

<<<<<<< HEAD

   DEBUG(log, "subscribing channel, flowid=%u, channelid=%u", flowid, channelid);
   channel = (snw_ice_channel_t*)snw_ice_channel_search(ice_ctx,channelid);
   if (!channel) return;
   snw_print_channel_info(ice_ctx,channel); 

   for (int i=0; i<SNW_ICE_CHANNEL_USER_NUM_MAX; i++) {
      if (channel->players[i] == 0) {
         found = 1;
         channel->players[i] = flowid;
         break;
      }
   }
   snw_print_channel_info(ice_ctx,channel); 

   if (!found) {
      ERROR(log, "channel full, flowid=%u, channelid=%u", flowid, channelid);
      snw_print_channel_info(ice_ctx,channel); 
=======
   DEBUG(log, "subscribing channel, flowid=%u, channelid=%u", flowid, channelid);
   channel = (snw_ice_channel_t*)snw_ice_channel_search(ice_ctx,channelid);
   if (!channel) return;

   if (channel->idx >= SNW_ICE_CHANNEL_USER_NUM_MAX) {
      ERROR(log, "channel info full, flowid=%u, channelid=%u", flowid, channelid);
      return;
   }
   channel->players[channel->idx] = flowid;
   channel->idx++;

#ifdef SNW_ENABLE_DEBUG
   snw_print_channel_info(ice_ctx,channel); 
#endif

   return;
}

void
snw_channel_remove_subscriber(snw_ice_context_t *ice_ctx, 
      uint32_t channelid, uint32_t flowid) {
   snw_log_t *log = 0;
   snw_ice_channel_t *channel = 0;
   int found = 0;

   if (!ice_ctx) return;
   log = ice_ctx->log;

   DEBUG(log, "removing from channel, flowid=%u, channelid=%u", 
        flowid, channelid);
   channel = (snw_ice_channel_t*)snw_ice_channel_search(ice_ctx,channelid);
   if (!channel) return;

   for (int i=0; i<channel->idx; i++) {
      if (channel->players[i] == flowid) {
         uint32_t tmp;
         found = 1;
         channel->idx--;
         channel->players[i] = channel->players[channel->idx];
         channel->players[channel->idx] = 0;
         break;
      }
   }

#ifdef SNW_ENABLE_DEBUG
   snw_print_channel_info(ice_ctx,channel); 
#endif

   if (!found) {
      WARN(log, "not found, flowid=%u, channelid=%u", flowid, channelid);
>>>>>>> dev
      return;
   }

   return;
}
