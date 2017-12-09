#include <assert.h>

<<<<<<< HEAD
#include "ice_component.h"
#include "mempool.h"
=======
#include "core/mempool.h"
#include "ice_component.h"
>>>>>>> dev

void
snw_component_mempool_init(snw_ice_context_t *ctx) {

   if (!ctx) return;

   ctx->component_mempool = snw_mempool_create(
         sizeof(snw_ice_component_t),sizeof(snw_ice_component_t)*1024,1);
   assert(ctx->component_mempool!=NULL);

   return;
}

snw_ice_component_t* 
snw_component_allocate(snw_ice_context_t *ctx) {
   snw_ice_component_t* component;

   if (!ctx->component_mempool)
      return 0;
   
   component = (snw_ice_component_t*) snw_mempool_allocate(ctx->component_mempool); 
   if (!component)
      return NULL;
   memset(component,0,sizeof(*component));
   INIT_LIST_HEAD(&component->list);
	INIT_LIST_HEAD(&component->remote_candidates.list);
	//INIT_LIST_HEAD(&component->rtplist.list);

   return component;
}

void 
snw_component_deallocate(snw_ice_context_t *ctx, snw_ice_component_t* p) {

   if (!ctx->component_mempool)
      return;

   snw_mempool_free(ctx->component_mempool, p);

   return;
}

snw_ice_component_t* 
snw_component_find(snw_ice_component_t *head, uint32_t id) {
   struct list_head *n;

   if ( head == NULL )
      return NULL;
   
   list_for_each(n,&head->list) {
      snw_ice_component_t *s = list_entry(n,snw_ice_component_t,list);

      if ( s->id == id )
         return s;
   }

   return NULL;
}

void
snw_component_insert(snw_ice_component_t *head, snw_ice_component_t *item) {
   
   if ( head == NULL || item == NULL )
      return;

   list_add(&item->list,&head->list);

   return;
}


