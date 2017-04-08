#include <stdio.h>

#include "demo.h"
#include "demo_session.h"
#include "cache.h"

inline int
demo_session_key(const void *item)
{  
   snw_demo_session_t *so =  (snw_demo_session_t *)item;
   return so->roomid;
}

inline int
demo_session_eq(const void *arg1, const void *arg2)
{  
   snw_demo_session_t *item1 = (snw_demo_session_t *)arg1;
   snw_demo_session_t *item2 = (snw_demo_session_t *)arg2;
   return (item1->roomid == item2->roomid);
}

inline int
demo_session_isempty(const void *arg)
{
   snw_demo_session_t *item = (snw_demo_session_t *)arg;
   return (item->roomid == 0);
}

inline int            
demo_session_setempty(const void *arg)
{
   snw_demo_session_t *item = (snw_demo_session_t *)arg;
   item->roomid = 0;
   return 0;
}


int
snw_demo_session_init(snw_demo_context_t *ctx) {
   ctx->session_cache = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx->session_cache == 0)
      return -1;
   snw_cache_init(ctx->session_cache, SNW_DEMO_KEY, SNW_DEMO_HASHTIME, SNW_DEMO_HASHLEN, 
                  sizeof(snw_demo_session_t),1, demo_session_eq, demo_session_key, 
                  demo_session_isempty, demo_session_setempty);

   return 0;
}

snw_demo_session_t*
snw_demo_session_get(snw_demo_context_t *ctx, uint32_t roomid, int *is_new) {
   snw_demo_session_t key;
   snw_demo_session_t *so;
   
   key.roomid = roomid;
   so = CACHE_GET(ctx->session_cache, &key, is_new, snw_demo_session_t*);

   if (so == 0)
      return 0;

   if (!is_new)
      return so;

   // reset new session
   memset(so, 0, sizeof(snw_demo_session_t));
   so->roomid = roomid;

   return so;
}

/*CACHE_SEARCH(ctx->session_cache, sitem, snw_demo_session_t*);*/
snw_demo_session_t*
snw_demo_session_search(snw_demo_context_t *ctx, uint32_t roomid) {
   snw_demo_session_t sitem;
   sitem.roomid = roomid;
   return (snw_demo_session_t*)snw_cache_search(ctx->session_cache, &sitem);
}

/*CACHE_INSERT(ctx->session_cache, sitem, snw_demo_session_t*);*/
snw_demo_session_t*
snw_demo_session_insert(snw_demo_context_t *ctx, snw_demo_session_t *sitem) {
   return (snw_demo_session_t*)snw_cache_insert(ctx->session_cache, sitem);
}

/*CACHE_REMOVE(ctx->session_cache, sitem, snw_demo_session_t*);*/
int 
snw_demo_session_remove(snw_demo_context_t *ctx, snw_demo_session_t *sitem) {
   return snw_cache_remove(ctx->session_cache, sitem);
}



