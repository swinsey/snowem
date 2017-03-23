#include <assert.h>

#include "ice_component.h"
#include "mempool.h"

void
snw_component_mempool_init(snw_ice_context_t *ctx) {

   if (!ctx) return;

   ctx->component_mempool = snw_mempool_create(
         sizeof(ice_component_t),sizeof(ice_component_t)*1024,1);
   assert(ctx->component_mempool!=NULL);

   return;
}

ice_component_t* 
snw_component_allocate(snw_ice_context_t *ctx) {
   ice_component_t* component;

   if (!ctx->component_mempool)
      return 0;
   
   component = (ice_component_t*) snw_mempool_allocate(ctx->component_mempool); 
   if (!component)
      return NULL;
   memset(component,0,sizeof(*component));
   INIT_LIST_HEAD(&component->list);
	INIT_LIST_HEAD(&component->candidates.list);
	INIT_LIST_HEAD(&component->rtplist.list);

   return component;
}

void 
snw_component_deallocate(snw_ice_context_t *ctx, ice_component_t* p) {

   if (!ctx->component_mempool)
      return;

   snw_mempool_free(ctx->component_mempool, p);

   return;
}

ice_component_t* 
snw_component_find(ice_component_t *head, uint32_t id) {
   struct list_head *n;

   if ( head == NULL )
      return NULL;
   
   list_for_each(n,&head->list) {
      ice_component_t *s = list_entry(n,ice_component_t,list);

      if ( s->component_id == id )
         return s;
   }

   return NULL;
}

void
snw_component_insert(ice_component_t *head, ice_component_t *item) {
   
   if ( head == NULL || item == NULL )
      return;

   list_add(&item->list,&head->list);

   return;
}


