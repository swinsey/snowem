#include <assert.h>

#include "component.h"
#include "mempool.h"

snw_mempool_t *g_component_mempool = NULL;

void component_mempool_init() {

   g_component_mempool = snw_mempool_create(sizeof(ice_component_t),2*1024,1);
   assert(g_component_mempool!=NULL);

   return;
}

ice_component_t* component_allocate() {
   ice_component_t* component;

   if ( g_component_mempool == NULL )
      return NULL;
   
   component = (ice_component_t*) snw_mempool_allocate(g_component_mempool); 
   if ( component == NULL )
      return NULL;
   memset(component,0,sizeof(*component));
   INIT_LIST_HEAD(&component->list);
	INIT_LIST_HEAD(&component->candidates.list);
	INIT_LIST_HEAD(&component->rtplist.list);

   return component;
}

void component_deallocate(ice_component_t* p) {

   if ( g_component_mempool == NULL )
      return;

   snw_mempool_free(g_component_mempool, p);

   return;
}

ice_component_t* component_find(ice_component_t *head, uint32_t id) {
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

void component_insert(ice_component_t *head, ice_component_t *item) {
   
   if ( head == NULL || item == NULL )
      return;

   list_add(&item->list,&head->list);

   return;
}


