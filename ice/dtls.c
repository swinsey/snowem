#include "dtls.h"

#include "log.h"
#include "ice.h"
#include "ice_types.h"
#include "ice_session.h"
#include "rtcp.h"
#include "session.h"
#include "types.h"
#include "utils.h"

int
srtp_print_fingerprint(char *buf, unsigned int len, 
      unsigned char *rfingerprint, unsigned int rsize) {
   unsigned int i = 0;

   if (len < (rsize*3 - 1))
      return -1;

   for (i = 0; i < rsize; i++) {
      snprintf(buf + i*3, 4, "%.2X:", rfingerprint[i]);
   }
   buf[rsize*3-1] = 0;

   return 0;
}

int
srtp_setup(snw_ice_context_t *ctx, char *server_pem, char *server_key) {
   unsigned char fingerprint[EVP_MAX_MD_SIZE];
   snw_log_t *log = 0;
   BIO *certbio = 0;
   X509 *cert = 0;
   unsigned int size;
   //char *tempbuf = 0;
   //unsigned int i = 0;

   ctx->ssl_ctx = SSL_CTX_new(DTLSv1_method());
   if (!ctx->ssl_ctx) {
      ERROR(log, "failed to create ssl context");
      return -1;
   }

   SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, srtp_verify_cb);
   SSL_CTX_set_tlsext_use_srtp(ctx->ssl_ctx, "SRTP_AES128_CM_SHA1_80");
   if (!server_pem || !SSL_CTX_use_certificate_file(ctx->ssl_ctx, server_pem, SSL_FILETYPE_PEM)) {
      ERROR(log, "certificate error, err=%s", SRTP_ERR_STR);
      return -2;
   }

   if (!server_key || !SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, server_key, SSL_FILETYPE_PEM)) {
      ERROR(log, "certificate key error, err=%s", SRTP_ERR_STR);
      return -3;
   }

   if (!SSL_CTX_check_private_key(ctx->ssl_ctx)) {
      ERROR(log, "certificate check error,err-%s", SRTP_ERR_STR);
      return -4;
   }

   SSL_CTX_set_read_ahead(ctx->ssl_ctx,1);
   certbio = BIO_new(BIO_s_file());
   if (!certbio) {
      ERROR(log, "certificate BIO error");
      return -5;
   }

   if (BIO_read_filename(certbio, server_pem) == 0) {
      ERROR(log, "failed to read certificate, err=%s", SRTP_ERR_STR);
      BIO_free_all(certbio);
      return -6;
   }

   cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
   if (!cert) {
      ERROR(log, "failed to read certificate, err=%s", SRTP_ERR_STR);
      BIO_free_all(certbio);
      return -7;
   }

   if (X509_digest(cert, EVP_sha256(), (unsigned char *)fingerprint, &size) == 0) {
      ERROR(log, "failed to convert X509 structure, err=%s", SRTP_ERR_STR);
      X509_free(cert);
      BIO_free_all(certbio);
      return -8;
   }
   
   srtp_print_fingerprint((char *)&ctx->local_fingerprint,160,fingerprint,size);
   DEBUG(log, "fingerprint of certificate: %s", ctx->local_fingerprint);
   X509_free(cert);
   BIO_free_all(certbio);
   SSL_CTX_set_cipher_list(ctx->ssl_ctx, DTLS_CIPHERS);

   /* Initialize libsrtp */
   if(srtp_init() != err_status_ok) {
      ERROR(log, "failed to set up libsrtp");
      return -9;
   }

   return 0;
}

dtls_ctx_t *
srtp_context_new(snw_ice_context_t *ice_ctx, void *component, int role) {
   snw_log_t *log = 0;
   dtls_ctx_t *dtls = 0;

   if (!ice_ctx) return 0;
   log = ice_ctx->log;

   DEBUG(log, "create DTLS/SRTP, role=%d", role);

   dtls = (dtls_ctx_t*)malloc(sizeof(dtls_ctx_t));
   if (!dtls) {
      ERROR(log, "getting dtls failed");
      return 0;
   }
   memset(dtls,0,sizeof(dtls_ctx_t));

   /* Create SSL context */
   dtls->ctx = ice_ctx;
   dtls->is_valid = 0;
   dtls->ssl = SSL_new(ice_ctx->ssl_ctx);
   if (!dtls->ssl) {
      ERROR(log, "failed to create DTLS session, err=%s",
         ERR_reason_error_string(ERR_get_error()));
      srtp_context_free(dtls);
      return 0;
   }

   SSL_set_ex_data(dtls->ssl, 0, dtls);
   SSL_set_info_callback(dtls->ssl, srtp_callback);
   dtls->read_bio = BIO_new(BIO_s_mem());
   if (!dtls->read_bio) {
      ERROR(log, "failed to create read_BIO, err=%s", SRTP_ERR_STR);
      srtp_context_free(dtls);
      return 0;
   }

   BIO_set_mem_eof_return(dtls->read_bio, -1);
   dtls->write_bio = BIO_new(BIO_s_mem());
   if (!dtls->write_bio) {
      ICE_ERROR2("failed to create write_BIO, err=%s", SRTP_ERR_STR);
      srtp_context_free(dtls);
      return 0;
   }
   BIO_set_mem_eof_return(dtls->write_bio, -1);

   /* The write BIO needs our custom filter, or fragmentation won't work */
   dtls->filter_bio = BIO_new(BIO_ice_dtls_filter()); //call: dtls_bio_filter_ctrl
   if (!dtls->filter_bio) {
      ERROR(log, "failed to create filter_BIO, err=%s", SRTP_ERR_STR);
      srtp_context_free(dtls);
      return 0;
   }
   dtls->filter_bio->ptr = dtls;

   /* Chain filter and write BIOs */
   BIO_push(dtls->filter_bio, dtls->write_bio);
   /* Set the filter as the BIO to use for outgoing data */
   SSL_set_bio(dtls->ssl, dtls->read_bio, dtls->filter_bio);
   dtls->role = role;
   if (dtls->role == DTLS_ROLE_CLIENT) {
      SSL_set_connect_state(dtls->ssl);
   } else {
      SSL_set_accept_state(dtls->ssl);
   }

   /* https://code.google.com/p/chromium/issues/detail?id=406458 
    * Specify an ECDH group for ECDHE ciphers, otherwise they cannot be
    * negotiated when acting as the server. Use NIST's P-256 which is
    * commonly supported.
    */
   EC_KEY* ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
   if (!ecdh) {
      ERROR(log, "failed to create ECDH group, err=%s",
         ERR_reason_error_string(ERR_get_error()));
      srtp_context_free(dtls);
      return 0;
   }
   SSL_set_options(dtls->ssl, SSL_OP_SINGLE_ECDH_USE);
   SSL_set_tmp_ecdh(dtls->ssl, ecdh);
   EC_KEY_free(ecdh);
   dtls->ready = 0;
   dtls->component = component;

   return dtls;
}

void srtp_do_handshake(dtls_ctx_t *dtls) {
   snw_log_t *log;
   snw_ice_component_t *c = (snw_ice_component_t*)dtls->component;

   if (dtls == NULL || dtls->ssl == NULL)
      return;
   log = c->stream->session->ice_ctx->log;

   //FIXME: state not used?
   if (dtls->state == DTLS_STATE_CREATED)
      dtls->state = DTLS_STATE_TRYING;

   SSL_do_handshake(dtls->ssl);
   DEBUG(log, "Start DTLS handshake");

   return;
}

void
ice_srtp_handshake_done(snw_ice_session_t *session, snw_ice_component_t *component) {
   snw_ice_context_t *ice_ctx = 0;
   snw_log_t *log = 0;

   if (!session || !component)
      return;
   ice_ctx = session->ice_ctx;
   log = ice_ctx->log;

   DEBUG(log, "srtp handshake is completed, cid=%u, sid=%u",
         component->id, component->stream->id);

   struct list_head *n,*p;
   list_for_each(n,&session->streams.list) {
      snw_ice_stream_t *s = list_entry(n,snw_ice_stream_t,list);
      if (s->is_disable)
         continue;
      list_for_each(p,&s->components.list) {
         snw_ice_component_t *c = list_entry(p,snw_ice_component_t,list);
         DEBUG(log, "checking component, sid=%u, cid=%u",s->id, c->id);
         if (!c->dtls || !c->dtls->is_valid) {
            DEBUG(log, "component not ready, sid=%u, cid=%u",s->id, c->id);
            return;
         }    
      }    
   }

   SET_FLAG(session, WEBRTC_READY);
   ice_rtp_established(session);
   return;
}

int
srtp_dtls_setup(dtls_ctx_t *dtls) {
   unsigned char rfingerprint[EVP_MAX_MD_SIZE];
   char remote_fingerprint[160];
   snw_ice_component_t *component = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_session_t *session = 0;
   snw_log_t *log = 0;
   unsigned int rsize;

   if (!dtls) return -1;

   component = (snw_ice_component_t *)dtls->component;
   if (!component || !component->stream 
       || !component->stream->session
       || !component->stream->session->agent) 
      return -2;
   stream = component->stream;
   session = stream->session;
   log = session->ice_ctx->log;

   if (!stream->remote_fingerprint) {
      ERROR(log,"no remote fingerprint, flowid=%u", session->flowid);
      return -4;
   }

   X509 *rcert = SSL_get_peer_certificate(dtls->ssl);
   if (!rcert) {
      ERROR(log,"no remote certificate, s=%s", ERR_reason_error_string(ERR_get_error()));
      return -3;
   } 

   if (stream->remote_hashing && !strcasecmp(stream->remote_hashing, "sha-1")) {
      X509_digest(rcert, EVP_sha1(), (unsigned char *)rfingerprint, &rsize);
   } else {
      X509_digest(rcert, EVP_sha256(), (unsigned char *)rfingerprint, &rsize);
   }

   srtp_print_fingerprint(remote_fingerprint,160,rfingerprint,rsize);

   DEBUG(log, "remote fingerprint, remote_hashing=%s, remote_fingerprint=%s",
      stream->remote_hashing ? stream->remote_hashing : "sha-256", remote_fingerprint);
   if (!strcasecmp(remote_fingerprint, stream->remote_fingerprint)) {
      dtls->state = DTLS_STATE_CONNECTED;
   } else {
      ERROR(log, "fingerprint mismatch, got=%s, expected=%s", 
            remote_fingerprint, stream->remote_fingerprint);
      dtls->state = DTLS_STATE_FAILED;
      goto done;
   }

   if (dtls->state == DTLS_STATE_CONNECTED) {
      //FIX: 28-05 jackiedinh
      if (component->stream->id == session->audio_stream->id 
          || component->stream->id == session->video_stream->id) {
         unsigned char material[SRTP_MASTER_LENGTH*2];
         unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
         if (!SSL_export_keying_material(dtls->ssl, material, SRTP_MASTER_LENGTH*2, 
                  "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
            ERROR(log, "exporting SRTP keying material failed, cid=%u, sid=%u, err=%s",
               component->id, component->stream->id, ERR_reason_error_string(ERR_get_error()));
            goto done;
         }
         // Key derivation (http://tools.ietf.org/html/rfc5764#section-4.2)
         if(dtls->role == DTLS_ROLE_CLIENT) {
            local_key = material;
            remote_key = local_key + SRTP_MASTER_KEY_LENGTH;
            local_salt = remote_key + SRTP_MASTER_KEY_LENGTH;
            remote_salt = local_salt + SRTP_MASTER_SALT_LENGTH;
         } else {
            remote_key = material;
            local_key = remote_key + SRTP_MASTER_KEY_LENGTH;
            remote_salt = local_key + SRTP_MASTER_KEY_LENGTH;
            local_salt = remote_salt + SRTP_MASTER_SALT_LENGTH;
         }
         // Build master keys and set SRTP policies
         // Remote (inbound)
         crypto_policy_set_rtp_default(&(dtls->remote_policy.rtp));
         crypto_policy_set_rtcp_default(&(dtls->remote_policy.rtcp));
         dtls->remote_policy.ssrc.type = ssrc_any_inbound;
         unsigned char remote_policy_key[SRTP_MASTER_LENGTH];
         dtls->remote_policy.key = (unsigned char *)&remote_policy_key;
         memcpy(dtls->remote_policy.key, remote_key, SRTP_MASTER_KEY_LENGTH);
         memcpy(dtls->remote_policy.key + SRTP_MASTER_KEY_LENGTH, remote_salt, SRTP_MASTER_SALT_LENGTH);

         dtls->remote_policy.next = NULL;
         // Local (outbound)
         crypto_policy_set_rtp_default(&(dtls->local_policy.rtp));
         crypto_policy_set_rtcp_default(&(dtls->local_policy.rtcp));
         dtls->local_policy.ssrc.type = ssrc_any_outbound;
         unsigned char local_policy_key[SRTP_MASTER_LENGTH];
         dtls->local_policy.key = (unsigned char *)&local_policy_key;
         memcpy(dtls->local_policy.key, local_key, SRTP_MASTER_KEY_LENGTH);
         memcpy(dtls->local_policy.key + SRTP_MASTER_KEY_LENGTH, local_salt, SRTP_MASTER_SALT_LENGTH);
         dtls->local_policy.next = NULL;
         // Create SRTP sessions
         err_status_t ret = srtp_create(&(dtls->srtp_in), &(dtls->remote_policy));
         if(ret != err_status_ok) {
            ICE_ERROR2("failed to create inbound SRTP session, cid=%u, sid=%u, ret=%d", 
                   component->id, stream->stream_id, ret);
            goto done;
         }
         ICE_DEBUG2("Created inbound SRTP session, cid=%u, sid=%u", 
               component->id, stream->stream_id);
         ret = srtp_create(&(dtls->srtp_out), &(dtls->local_policy));
         if(ret != err_status_ok) {
            ICE_ERROR2("failed to create outbound SRTP session, cid=%u, sid=%u, ret=%d", 
                   component->id, stream->stream_id, ret);
            goto done;
         }
         dtls->is_valid = 1;
         ICE_DEBUG2("Created outbound SRTP session for component %d in stream %d", 
               component->id, stream->stream_id);
      }
      dtls->ready = 1;
   }
done:
   if (dtls->is_valid) {
      ice_srtp_handshake_done(session, component);
   }
      
   if (rcert) X509_free(rcert);

   return 0;
}

int
srtp_process_incoming_msg(dtls_ctx_t *dtls, char *buf, uint16_t len) {
   char data[DTLS_BUFFER_SIZE];
   snw_log_t *log = 0;
   snw_ice_component_t *component = 0;
   int ret = 0;
   int written = 0;

   if (!dtls || !dtls->ssl || !dtls->read_bio) {
      return -1;
   }
   component = (snw_ice_component_t*)dtls->component;
   log = component->stream->session->ice_ctx->log;
   
   DEBUG(log, "dtls message, len=%u",len);

   written = BIO_write(dtls->read_bio, buf, len);
   if (written != len) {
      ERROR(log, "failed to write, written=%u, len=%u", written, len);
   } else {
      DEBUG(log, "bio write, written=%u", written);
   }

   /* XXX: read to push data on bio chain? */
   ret = SSL_read(dtls->ssl, &data, DTLS_BUFFER_SIZE);
   if (ret < 0) {
      unsigned long err = SSL_get_error(dtls->ssl, ret);
      if (err == SSL_ERROR_SSL) {
         char error[256];
         ERR_error_string_n(ERR_get_error(), error, 256);
         ERROR(log,"ssl read error: ret=%d, err=%s", read, error);
         return -9;
      }
   }

   if (!SSL_is_init_finished(dtls->ssl)) {
      return -8;
   }

   if (dtls->ready) {
      WARN(log,"dtls data not supported, ret=%u",ret);
   } else {
      DEBUG(log,"DTLS established");
      srtp_dtls_setup(dtls);
   }

   return 0;
}

void srtp_context_free(dtls_ctx_t *dtls) {

   if(dtls == NULL)
      return;
   dtls->ready = 0;
   
   dtls->component = NULL;
   if(dtls->ssl != NULL) {
      SSL_free(dtls->ssl);
      dtls->ssl = NULL;
   }
   
   dtls->read_bio = NULL;
   dtls->write_bio = NULL;
   dtls->filter_bio = NULL;
   if(dtls->is_valid) {
      if(dtls->srtp_in) {
         srtp_dealloc(dtls->srtp_in);
         dtls->srtp_in = NULL;
      }
      if(dtls->srtp_out) {
         srtp_dealloc(dtls->srtp_out);
         dtls->srtp_out = NULL;
      }
      
   }
   free(dtls);
   dtls = NULL;
}

void srtp_callback(const SSL *ssl, int where, int ret) {
   //FIXME: do real verification
   return;
}

int srtp_verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
   //FIXME: do real verification
   return 1;
}

/* Filter implementation */
int dtls_bio_filter_write(BIO *h, const char *buf,int num);
int dtls_bio_filter_read(BIO *h, char *buf, int len);
long dtls_bio_filter_ctrl(BIO *h, int cmd, long arg1, void *arg2);
int dtls_bio_filter_new(BIO *h);
int dtls_bio_filter_free(BIO *data);

static BIO_METHOD dtls_bio_filter_methods = {
   BIO_TYPE_FILTER,
   "srtp filter",
   dtls_bio_filter_write,
   dtls_bio_filter_read,
   NULL,
   NULL,
   dtls_bio_filter_ctrl,
   dtls_bio_filter_new,
   dtls_bio_filter_free,
   NULL
};

BIO_METHOD *BIO_ice_dtls_filter(void) {
   return(&dtls_bio_filter_methods);
}

int
dtls_bio_filter_new(BIO *bio) {
  
   bio->init = 1;
   bio->flags = 0;
   
   return 1;
}

int
dtls_bio_filter_free(BIO *bio) {

   if (bio == NULL)
      return 0;
      
   bio->ptr = NULL;
   bio->init = 0;
   bio->flags = 0;
   return 1;
}

int
srtp_send_data(dtls_ctx_t *dtls, int len) {
   snw_ice_session_t *session = 0;
   snw_ice_component_t *component = 0;
   snw_ice_stream_t *stream = 0;
   snw_log_t *log = 0;
   char data[DTLS_BUFFER_SIZE];
   int sent, bytes;

   if (!dtls) return -1;

   component = (snw_ice_component_t *)dtls->component;
   if (!component || !component->stream || !component->stream->session) 
      return -2;

   stream = component->stream;
   session = stream->session;
   log = session->ice_ctx->log;
   if (!session || !session->agent || !dtls->write_bio) {
      return -3;
   }

   //FIXME: a loop is needed to read all data?
   sent = BIO_read(dtls->write_bio, data, DTLS_MTU_SIZE);
   if (sent <= 0) {
      DEBUG(log, "failed to read dtls data, sent=%d", sent);
      return -1;
   }
   DEBUG(log, "sending dtls msg, len=%u, sent=%u", len, sent);
   bytes = ice_agent_send(session->agent, component->stream->id, 
                          component->id, data, sent);

   if(bytes < sent) {
      ERROR(log, "failed to send dtls message, cid=%u, sid=%u, len=%d", 
            component->id, stream->id, bytes);
   } 

   return 0;
}

int
dtls_bio_filter_write(BIO *bio, const char *in, int inl) {
   snw_log_t *log = 0;
   dtls_ctx_t *dtls = 0;
   int ret = 0;

   ret = BIO_write(bio->next_bio, in, inl);
   dtls = (dtls_ctx_t *)bio->ptr;
   log = dtls->ctx->log;

   DEBUG(log, "write dtls msg to filter, len=%d, written_len=%ld", inl, ret);
   srtp_send_data(dtls,ret); 

   return ret;
}

int
dtls_bio_filter_read(BIO *bio, char *buf, int len) {
   snw_log_t *log = 0;
   dtls_ctx_t *dtls = 0;

   dtls = (dtls_ctx_t *)bio->ptr;
   log = dtls->ctx->log;

   DEBUG(log, "dtls read, len=%d", len);

   return 0;
}

long
dtls_bio_filter_ctrl(BIO *bio, int cmd, long num, void *ptr) {

   switch(cmd) {
      case BIO_CTRL_FLUSH:
         return 1;
      case BIO_CTRL_DGRAM_QUERY_MTU:
         return DTLS_MTU_SIZE;
      case BIO_CTRL_WPENDING:
         return 0L;
      case BIO_CTRL_PENDING: {
         return 0;
      }
      default:
         ;
   }
   return 0;
}


void
srtp_destroy(dtls_ctx_t *dtls) {
   //FIXME: impl
   return;
}

