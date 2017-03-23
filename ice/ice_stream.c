#include <assert.h>

#include "ice.h"
#include "ice_stream.h"
#include "mempool.h"

void 
snw_stream_mempool_init(snw_ice_context_t *ctx) {

   if (!ctx) return;

   ctx->stream_mempool = snw_mempool_create(
         sizeof(snw_ice_stream_t),sizeof(snw_ice_stream_t)*1024,1);
   assert(ctx->stream_mempool!=NULL);

   return;
}

snw_ice_stream_t* 
snw_stream_allocate(snw_ice_context_t *ctx) {
   snw_ice_stream_t* stream;

   if (!ctx || !ctx->stream_mempool)
      return 0;
   
   stream = (snw_ice_stream_t*) snw_mempool_allocate(ctx->stream_mempool); 
   if (!stream)
      return 0;

   memset(stream,0,sizeof(*stream));
   INIT_LIST_HEAD(&stream->list);
   return stream;
}


void
snw_stream_deallocate(snw_ice_context_t *ctx, snw_ice_stream_t* p) {

   if (!ctx || !ctx->stream_mempool)
      return;

   snw_mempool_free(ctx->stream_mempool, p);

   return;
}

snw_ice_stream_t*
snw_stream_find(snw_ice_stream_t *head, uint32_t id) {
   struct list_head *n;

   if ( head == NULL )
      return NULL;
   
   list_for_each(n,&head->list) {
      snw_ice_stream_t *s = list_entry(n,snw_ice_stream_t,list);

      if ( s->stream_id == id )
         return s;
   }

   return NULL;
}

void
snw_stream_insert(snw_ice_stream_t *head, snw_ice_stream_t *item) {
   
   if ( head == NULL || item == NULL )
      return;

   list_add(&item->list,&head->list);

   return;
}

void
snw_stream_free(snw_ice_stream_t *streams, snw_ice_stream_t *stream) {

   return;
}



