#include <sys/time.h>
#include <cstdio>
#include <event2/event.h>

#include "dtls.h"
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

void 
ben_ice_log_cb(int severity, const char *msg, void *data) {

   DEBUG("%s",msg);
   return; 
}


int main(int argc, char** argv) {
   struct event_base *base = 0;
   struct evdns_base *dns_base = 0;
   SSL_CTX *ssl_ctx = 0;
   int ret = -1;

   event_set_log_callback(write_to_file_cb);
   ice_set_log_callback(ben_ice_log_cb,NULL);

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
   g_config.channel_id =  atoi(argv[3]);
   printf("channel_id=%u\n",g_config.channel_id);

   g_config.dtls_params = (DTLSParams*)malloc(sizeof(DTLSParams));
   if (!g_config.dtls_params)
      return -2;
   //memset(dtls_params,0,sizeof(DTLSParams));
   ret = init_dtls_srtp_ctx(g_config.dtls_params,"client");
   if (ret<0)  {
      DEBUG("failed to init dlts, ret=%d",ret);
      return -3;
   }

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


