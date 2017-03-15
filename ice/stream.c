#include <assert.h>

#include "stream.h"
#include "mempool.h"

snw_mempool_t *g_stream_mempool = NULL;

void stream_mempool_init() {

   g_stream_mempool = snw_mempool_create(sizeof(ice_stream_t),1024,1);
   assert(g_stream_mempool!=NULL);

   return;
}

ice_stream_t* stream_allocate() {
   ice_stream_t* stream;

   if ( g_stream_mempool == NULL )
      return NULL;
   
   stream = (ice_stream_t*) snw_mempool_allocate(g_stream_mempool); 
   if ( stream == NULL )
      return NULL;
   memset(stream,0,sizeof(*stream));
   INIT_LIST_HEAD(&stream->list);

   return stream;
}


void stream_deallocate(ice_stream_t* p) {

   if ( g_stream_mempool == NULL )
      return;

   snw_mempool_free(g_stream_mempool, p);

   return;
}

ice_stream_t* stream_find(ice_stream_t *head, uint32_t id) {
   struct list_head *n;

   if ( head == NULL )
      return NULL;
   
   list_for_each(n,&head->list) {
      ice_stream_t *s = list_entry(n,ice_stream_t,list);

      if ( s->stream_id == id )
         return s;
   }

   return NULL;
}

void stream_insert(ice_stream_t *head, ice_stream_t *item) {
   
   if ( head == NULL || item == NULL )
      return;

   list_add(&item->list,&head->list);

   return;
}

void stream_free(ice_stream_t *streams, ice_stream_t *stream) {

   return;
}



