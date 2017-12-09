#include <string.h>

#include "sdp.h"
#include "util.h"

static su_home_t *g_home = NULL;

int
sdp_init() {

   g_home = (su_home_t*)su_home_new(sizeof(su_home_t));
   if(su_home_init(g_home) < 0) { 
      DEBUG("error setting up sofia-sdp?");
      return -1;  
   }    
   return 0;
}

void
sdp_deinit(void) {
   su_home_deinit(g_home);
   su_home_unref(g_home);
   g_home = NULL;
}

sdp_parser_t*
sdp_get_parser(const char *sdp) {
   sdp_parser_t *parser = NULL;

   if (!sdp) {
      DEBUG("sdp is null, sdp=%p",sdp);
      return NULL;
   }    

   parser = sdp_parse(g_home, sdp, strlen(sdp), 0);  
   return parser;
}


