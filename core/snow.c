#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config_file.h"
#include "core.h"
#include "snow.h"

using namespace mqf::base;

int
snw_conf_init(snw_context_t *ctx, const char *file) {
   CFileConfig &page = * new CFileConfig();

   printf("config file: %s\n",file);

   page.Init(file);
   ctx->config_file = file;
   ctx->cert_file = page["root\\ice\\cert_file"].c_str();
   ctx->key_file = page["root\\ice\\key_file"].c_str();
   return 0;
}

int
main(int argc, char** argv) {
   int pid;
   snw_context_t *ctx;

   ctx = snw_create_context();
   if (ctx == NULL)
      exit(-1);

   if (argc < 2)
      exit(-2);

   snw_conf_init(ctx,argv[1]);
   daemonize();

   pid = fork();
   if (pid < 0) {
      printf("error");
   } else if (pid == 0) {//child
      snw_ice_setup(ctx);
   } else {
      //continue 
   }

   /*pid = fork();
   if (pid < 0) {
      printf("error");
   } else if (pid == 0) {
      snw_ice_setup(ctx);
   } else {
      //usnet_net_setup(ctx);
   }*/




   return 0;
}

