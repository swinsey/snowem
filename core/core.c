#include <stdlib.h>
#include <signal.h>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core.h"
#include "mq.h"
#include "log.h"
#include "ice.h"
#include "websocket/websocket.h"

snw_context_t*
snw_create_context()
{   
   snw_context_t *ctx;

   ctx = (snw_context_t*)malloc(sizeof(snw_context_t));
   if ( ctx == NULL )
      return 0;

   memset(ctx, 0, sizeof(*ctx));
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

   DEBUG(ctx->log,"init net ssl");

   /* Initialize the OpenSSL library */
   SSL_load_error_strings();
   SSL_library_init();
   OpenSSL_add_all_algorithms();

   /* We MUST have entropy, or else there's no point to crypto. */
   if (!RAND_poll())
      return -1;

   server_ctx = SSL_CTX_new(SSLv23_server_method());
   if (server_ctx == NULL) { 
      ERROR(ctx->log,"failed to init ssll");
      return -2; 
   }

   DEBUG(ctx->log,"ssl info, cert_file=%s,key_file=%s",ctx->wss_cert_file,ctx->wss_key_file);

   if (! SSL_CTX_use_certificate_chain_file(server_ctx, ctx->wss_cert_file) ||
       ! SSL_CTX_use_PrivateKey_file(server_ctx, ctx->wss_key_file, SSL_FILETYPE_PEM)) {
       ERROR(ctx->log,"failed to read cert or key files");
       return -3;
   }
   //SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);*/
   ctx->ssl_ctx = server_ctx;

   return 0;
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
             NET2CORE_KEY, SHAREDMEM_SIZE, 0);
   if (ret < 0) {
      ERROR(ctx->log,"failed to init net2core mq");
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

   DEBUG(ctx->log,"start websocket process");
   snw_websocket_init(ctx);
  
   return;
}

void
snw_worker_setup(snw_context_t *ctx) {
   /*TODO: get log file from config*/  
   ctx->log = snw_log_init("./worker.log",0,0,0);
   if ( ctx->log == 0 )
      exit(0);   

   DEBUG(ctx->log,"start worker process");
   return;
}

void
snw_ice_init_log(snw_context_t *ctx) {
   /*TODO: get log file from config*/  
   ctx->log = snw_log_init("./ice.log",0,0,0);
   if (ctx->log == 0) {
      exit(-1);   
   }

   return;
}

int
snw_ice_init_ssl(snw_context_t *ctx) {
   SSL_CTX  *server_ctx = NULL;
   std::string cert_str,key_str;

   DEBUG(ctx->log,"init ssl");

   /* Initialize the OpenSSL library */
   SSL_load_error_strings();
   SSL_library_init();
   OpenSSL_add_all_algorithms();

   /* We MUST have entropy, or else there's no point to crypto. */
   if (!RAND_poll())
      return -1;

   server_ctx = SSL_CTX_new(SSLv23_server_method());
   if (server_ctx == NULL) { 
      ERROR(ctx->log,"failed to init ssll");
      return -2; 
   }

   DEBUG(ctx->log,"ssl info, cert_file=%s,key_file=%s",ctx->ice_cert_file,ctx->ice_key_file);
   if (! SSL_CTX_use_certificate_chain_file(server_ctx, ctx->ice_cert_file) ||
       ! SSL_CTX_use_PrivateKey_file(server_ctx, ctx->ice_key_file, SSL_FILETYPE_PEM)) {
       ERROR(ctx->log,"failed to read cert or key files");
       return -3;
   }
   //SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);*/
   ctx->ssl_ctx = server_ctx;

   return 0;
}

int
snw_ice_init_shmqueue(snw_context_t *ctx) {
   int ret = 0;

   ctx->snw_ice2core_mq = (snw_shmmq_t *)
          malloc(sizeof(*ctx->snw_ice2core_mq));
   if (ctx->snw_ice2core_mq == 0) {
      return -1;
   }

   ret = snw_shmmq_init(ctx->snw_ice2core_mq,
             "/tmp/snw_ice2core_mq.fifo", 0, 0, 
             ICE2CORE_KEY, SHAREDMEM_SIZE, 0);
   if (ret < 0) {
      ERROR(ctx->log,"failed to init ice2core mq");
      return -2;
   }

   return 0;
}

void
snw_ice_setup(snw_context_t *ctx) {

   if (ctx == 0)
      return;

   ctx->ev_base = event_base_new();
   if (ctx->ev_base == 0) {
      exit(-2);
   }

   /*initialize stuff before ice process*/
   snw_ice_init_log(ctx);
   snw_ice_init_shmqueue(ctx);
   snw_ice_init_ssl(ctx);

   DEBUG(ctx->log,"start ice process");
   snw_ice_init(ctx);

   return;
}


