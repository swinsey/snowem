#include <stdlib.h>
#include <signal.h>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core.h"
#include "mq.h"
#include "module.h"
#include "log.h"
#include "ice/ice.h"
#include "websocket/websocket.h"

snw_context_t*
snw_create_context()
{   
   snw_context_t *ctx;

   ctx = (snw_context_t*)malloc(sizeof(snw_context_t));
   if ( ctx == NULL )
      return 0;

   memset(ctx, 0, sizeof(*ctx));
   INIT_LIST_HEAD(&ctx->modules.list);
   return ctx; 
}

void
daemonize() 
{
   pid_t pid;

   if ((pid = fork() ) != 0 ) 
   {   
      exit( 0); 
   }   

   setsid();

   signal( SIGINT,  SIG_IGN);
   signal( SIGHUP,  SIG_IGN);
   signal( SIGPIPE, SIG_IGN);
   signal( SIGTTOU, SIG_IGN);
   signal( SIGTTIN, SIG_IGN);
   signal( SIGCHLD, SIG_IGN);
   signal( SIGTERM, SIG_IGN);

   struct sigaction sig;

   sig.sa_handler = SIG_IGN;
   sig.sa_flags = 0;
   sigemptyset( &sig.sa_mask);
   sigaction( SIGHUP,&sig,NULL);

   if ((pid = fork() ) != 0 ) 
   {   
      exit(0);
   }   

   umask(0);
   setpgrp();

   return;
}

void
snw_net_init_log(snw_context_t *ctx) {
   /*TODO: get log file from config*/  
   ctx->log = snw_log_init("./net.log",0,0,0);
   if (ctx->log == 0) {
      exit(-1);   
   }

   return;
}

int
snw_net_init_ssl(snw_context_t *ctx) {
   SSL_CTX  *server_ctx = NULL;
   std::string cert_str,key_str;

   /* Initialize the OpenSSL library */
   SSL_load_error_strings();
   SSL_library_init();
   OpenSSL_add_all_algorithms();

   /* We MUST have entropy, or else there's no point to crypto. */
   if (!RAND_poll())
      return -1;

   server_ctx = SSL_CTX_new(SSLv23_server_method());
   if (server_ctx == NULL) { 
      ERROR(ctx->log,"failed to create ssl ctx");
      return -2; 
   }

   DEBUG(ctx->log,"ssl info, cert_file=%s, key_file=%s",
         ctx->wss_cert_file,ctx->wss_key_file);

   if (! SSL_CTX_use_certificate_chain_file(server_ctx, ctx->wss_cert_file) ||
       ! SSL_CTX_use_PrivateKey_file(server_ctx, ctx->wss_key_file, SSL_FILETYPE_PEM)) {
       ERROR(ctx->log,"failed to read cert or key files");
       return -3;
   }
   ctx->ssl_ctx = server_ctx;

   return 0;
}


void
snw_net_dispatch_msg(int fd, short int event,void* data) {
   static char buf[MAX_BUFFER_SIZE];
   snw_websocket_context_t *ws_ctx = (snw_websocket_context_t *)data;
   snw_context_t *ctx = ws_ctx->ctx;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;
   int ret = 0; 
   
   while (true) {
     len = 0;
     flowid = 0;
     cnt++;

     if ( cnt >= 100) {
         break;
     }

     ret = snw_shmmq_dequeue(ctx->snw_core2net_mq, buf, MAX_BUFFER_SIZE, &len, &flowid);
     DEBUG(ctx->log,"core2net fd=%d, ret=%d, len=%u, flowid=%u",
                    ctx->snw_core2net_mq->fd, ret, len, flowid);
     if ( (len == 0 && ret == 0) || (ret < 0) )
        return;
     
     buf[len] = 0;
     snw_websocket_send_msg(ws_ctx,buf,len,flowid);
   }

   return;
}

int
snw_net_init_shmqueue(snw_context_t *ctx) {
   int ret = 0;

   ctx->snw_net2core_mq = (snw_shmmq_t *)
          malloc(sizeof(*ctx->snw_net2core_mq));
   if (ctx->snw_net2core_mq == 0) {
      return -1;
   }

   ret = snw_shmmq_init(ctx->snw_net2core_mq,
             "/tmp/snw_net2core_mq.fifo", 0, 0, 
             NET2CORE_KEY, SHAREDMEM_SIZE);
   if (ret < 0) {
      ERROR(ctx->log,"failed to message queue");
      return -2;
   }

   ctx->snw_core2net_mq = (snw_shmmq_t *)
          malloc(sizeof(*ctx->snw_core2net_mq));
   if (ctx->snw_core2net_mq == 0) {
      return -1;
   }

   ret = snw_shmmq_init(ctx->snw_core2net_mq,
             "/tmp/snw_core2net_mq.fifo", 0, 0, 
             CORE2NET_KEY, SHAREDMEM_SIZE);
   if (ret < 0) {
      ERROR(ctx->log,"failed to message queue");
      return -2;
   }

   return 0;
}

void
snw_net_setup(snw_context_t *ctx) {

   if (ctx == 0)
      return;

   ctx->ev_base = event_base_new();
   if (ctx->ev_base == 0) {
      exit(-2);
   }

   /*initialize stuff before ice process*/
   snw_net_init_log(ctx);
   snw_net_init_shmqueue(ctx);
   snw_net_init_ssl(ctx);

   snw_websocket_init(ctx,snw_net_dispatch_msg);
  
   return;
}

void
snw_worker_setup(snw_context_t *ctx) {
   /*TODO: get log file from config*/  
   ctx->log = snw_log_init("./worker.log",0,0,0);
   if ( ctx->log == 0 )
      exit(0);   

   //FIXME: impl

   return;
}


