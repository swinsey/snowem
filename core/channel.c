#include <stdlib.h>
#include <string.h>

#include "cache.h"
#include "channel.h"
#include "types.h"


inline int
channel_key(const void *item)
{  
   snw_channel_t *so =  (snw_channel_t *)item;
   return so->id;
}

inline int
channel_eq(const void *arg1, const void *arg2)
{  
   snw_channel_t *item1 = (snw_channel_t *)arg1;
   snw_channel_t *item2 = (snw_channel_t *)arg2;
   return (item1->id == item2->id);
}

inline int
channel_isempty(const void *arg)
{
   snw_channel_t *item = (snw_channel_t *)arg;
   return (item->id == 0);
}

inline int
channel_setempty(const void *arg)
{
   snw_channel_t *item = (snw_channel_t *)arg;
   item->id = 0;
   return 0;
}

snw_hashbase_t*
snw_channel_init() {
   snw_hashbase_t *ctx;
   int ret = 0;

   ctx = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx == 0) return 0;

   ret = snw_cache_init(ctx, CORE_CHANNEL_SHM_KEY, CORE_CHANNEL_HASHTIME, 
         CORE_CHANNEL_HASHLEN, sizeof(snw_channel_t),1, channel_eq, 
         channel_key, channel_isempty, channel_setempty);
   if (ret < 0) return 0;

   return ctx;
}

snw_channel_t*
snw_channel_get(snw_hashbase_t *ctx, uint32_t id, int *is_new) {
   snw_channel_t key;
   snw_channel_t *so;
   
   key.id = id;
   so = CACHE_GET(ctx, &key, is_new, snw_channel_t*);

   if (so == 0) return 0;

   if (!(*is_new)) return so;

   // reset new channel
   memset(so, 0, sizeof(snw_channel_t));
   so->id = id;

   return so;
}

/*CACHE_SEARCH(ctx->channel_cache, sitem, snw_channel_t*);*/
snw_channel_t*
snw_channel_search(snw_hashbase_t *ctx, uint32_t id) {
   snw_channel_t sitem;
   sitem.id = id;
   return (snw_channel_t*)snw_cache_search(ctx, &sitem);
}

/*CACHE_INSERT(ctx->channel_cache, sitem, snw_channel_t*);*/
snw_channel_t*
snw_channel_insert(snw_hashbase_t *ctx, snw_channel_t *sitem) {
   return (snw_channel_t*)snw_cache_insert(ctx, sitem);
}

/*CACHE_REMOVE(ctx->channel_cache, sitem, snw_channel_t*);*/
int 
snw_channel_remove(snw_hashbase_t *ctx, snw_channel_t *sitem) {
   return snw_cache_remove(ctx, sitem);
}



