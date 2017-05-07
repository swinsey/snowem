#include <event2/event.h>

#include "wsclient.h"

static void write_to_file_cb(int severity, const char *msg)
{
    const char *s;
    switch (severity) {
        case _EVENT_LOG_DEBUG: s = "debug"; break;
        case _EVENT_LOG_MSG:   s = "msg";   break;
        case _EVENT_LOG_WARN:  s = "warn";  break;
        case _EVENT_LOG_ERR:   s = "error"; break;
        default:               s = "?";     break; /* never reached */
    }
    printf("[%s] %s\n", s, msg);
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
   //printf("preverify_ok: %d\n", preverify_ok);
   return preverify_ok;
}

typedef struct bm_config_ bm_config;
struct bm_config_ {
   int total_client_num;
   int started_client_num;
   int stopped_client_num;
   struct event *ev;
   int n_calls;

   struct event_base *base;
   struct evdns_base *dns_base;
   SSL_CTX *ssl_ctx;
};
bm_config g_config;

void timer_callback(evutil_socket_t fd, short what, void *arg) {
   WsClient *client = new WsClient();
   bm_config *config= (bm_config *)arg;
   //printf("cb_func called %d times so far.\n", ++config->n_calls);
   ++config->n_calls;
   if (config->n_calls > 1) {
      event_del(config->ev);
      config->ev = 0;
      return;
   }

   client->init(config->base,config->dns_base,config->ssl_ctx);
   client->do_http_handshake("media.peercall.vn","443","/");

   return;
}

int main(int argc, char** argv) {
   struct event_base *base = 0;
   struct evdns_base *dns_base = 0;
   SSL_CTX *ssl_ctx = 0;

   event_set_log_callback(write_to_file_cb);
   base = event_base_new();
   dns_base = evdns_base_new(base, 1);
   if (!base || !dns_base) {
      fprintf(stderr, "Null pointer.\n");
      return -2;
   }

   SSL_load_error_strings();
   SSL_library_init();
   RAND_poll();

   ssl_ctx = SSL_CTX_new(SSLv23_method());
   SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_callback);

   if (SSL_CTX_load_verify_locations(ssl_ctx, "letsen/ca.cert", NULL) != 1){ 
      fprintf(stderr, "Couldn't load certificate trust store.\n");
      return -1;
   }

   memset(&g_config,0,sizeof(g_config));
   g_config.base = base;
   g_config.dns_base = dns_base;
   g_config.ssl_ctx = ssl_ctx;

   struct event *ev;
   struct timeval one_sec;
   one_sec.tv_sec = 1;
   one_sec.tv_usec = 0;
   
   ev = event_new(base, -1, EV_PERSIST, timer_callback, &g_config);
   g_config.ev = ev;
   event_add(ev, &one_sec);

   event_base_dispatch(base);
   return 0;
}


