#include <libconfig.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "conf.h"


void
snw_config_init(snw_context_t *ctx, const char *file) {
   config_t cfg;
   config_setting_t *setting;
   const char *str;
   int number;

   config_init(&cfg);
   if (!config_read_file(&cfg, file)) {
      fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
      config_destroy(&cfg);
      exit(0);
   }

   if (config_lookup_string(&cfg, "ice_cert_file", &str)) {
      printf("ice_cert_file: %s\n", str);
      ctx->ice_cert_file = strdup(str);
   } else {
      printf("ice_cert_file not found\n");
      exit(0);
   }

   if (config_lookup_string(&cfg, "ice_key_file", &str)) {
      printf("ice_key_file: %s\n", str);
      ctx->ice_key_file = strdup(str);
   } else {
      printf("ice_cert_file not found\n");
      exit(0);
   }

   if (config_lookup_string(&cfg, "wss_cert_file", &str)) {
      printf("wss_cert_file: %s\n", str);
      ctx->wss_cert_file = strdup(str);
   } else {
      printf("wss_cert_file not found\n");
      exit(0);
   }

   if (config_lookup_string(&cfg, "wss_key_file", &str)) {
      printf("wss_key_file: %s\n", str);
      ctx->wss_key_file = strdup(str);
   } else {
      printf("wss_key_file not found\n");
      exit(0);
   }

   if (config_lookup_int(&cfg, "wss_bind_port", &number)) {
      printf("wss_bind_port: %u\n", number);
      ctx->wss_port = (uint16_t)number;
   } else {
      printf("wss_bind_port not found\n");
      exit(0);
   }

   if (config_lookup_string(&cfg, "wss_bind_ip", &str)) {
      printf("wss_bind_ip: %s\n", str);
      ctx->wss_ip = strdup(str);
   } else {
      printf("wss_bind_ip not found\n");
      exit(0);
   }

   if (config_lookup_int(&cfg, "log_level", &number)) {
      printf("log_level: %u\n", number);
      ctx->log_level = number;
   } else {
      printf("log_level not found\n");
      exit(0);
   }


   setting = config_lookup(&cfg, "modules");
   if (setting != NULL) {
      snw_module_t *module;
      const char *name, *sofile;
      int type;
      int count = config_setting_length(setting);
      int i;

      for (i = 0; i < count; ++i) {
         config_setting_t *elem = config_setting_get_elem(setting, i);
         if (!(config_setting_lookup_string(elem,"name",&name) 
               && config_setting_lookup_string(elem,"sofile",&sofile)
               && config_setting_lookup_int(elem,"type",&type)))
            continue;

         printf("module info, name=%s, type=%u, sofile=%s\n", name, type, sofile);

         module = (snw_module_t*)malloc(sizeof(snw_module_t));
         if (!module) return;
         INIT_LIST_HEAD(&module->list);
         module->name = strdup(name);
         module->type = type;
         module->sofile = strdup(sofile);
         list_add_tail(&module->list,&ctx->modules.list);
      }
   }

   return;
}





