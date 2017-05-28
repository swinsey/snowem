#include "dtls.h"
#include "rtcp.h"

#include "log.h"
#include "ice.h"
#include "ice_types.h"
#include "ice_session.h"
#include "utils.h"
#include "session.h"

static SSL_CTX *ssl_ctx = NULL;
SSL_CTX *srtp_get_ssl_ctx(void) {
   return ssl_ctx;
}

static char local_fingerprint[160];
char *srtp_get_local_fingerprint(void) {
   return (char *)local_fingerprint;
}

int srtp_setup(char *server_pem, char *server_key) {
   BIO *certbio = NULL;
   X509 *cert = NULL;
   unsigned int size;
   unsigned char fingerprint[EVP_MAX_MD_SIZE];
   char *tempbuf = NULL;
   unsigned int i = 0;

   ssl_ctx = SSL_CTX_new(DTLSv1_method());
   if (!ssl_ctx) {
      ICE_ERROR2("failed to create ssl context");
      return -1;
   }

   SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, srtp_verify_cb);
   SSL_CTX_set_tlsext_use_srtp(ssl_ctx, "SRTP_AES128_CM_SHA1_80");
   if (!server_pem || !SSL_CTX_use_certificate_file(ssl_ctx, server_pem, SSL_FILETYPE_PEM)) {
      ICE_ERROR2("certificate error, err=%s", SRTP_ERR_STR);
      return -2;
   }

   if (!server_key || !SSL_CTX_use_PrivateKey_file(ssl_ctx, server_key, SSL_FILETYPE_PEM)) {
      ICE_ERROR2("certificate key error, err=%s", SRTP_ERR_STR);
      return -3;
   }

   if (!SSL_CTX_check_private_key(ssl_ctx)) {
      ICE_ERROR2("certificate check error,err-%s", SRTP_ERR_STR);
      return -4;
   }

   SSL_CTX_set_read_ahead(ssl_ctx,1);
   certbio = BIO_new(BIO_s_file());
   if (certbio == NULL) {
      ICE_ERROR2("certificate BIO error");
      return -5;
   }

   if (BIO_read_filename(certbio, server_pem) == 0) {
      ICE_ERROR2("failed to read certificate, err=%s", SRTP_ERR_STR);
      BIO_free_all(certbio);
      return -6;
   }

   cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
   if (cert == NULL) {
      ICE_ERROR2("failed to read certificate, err=%s", SRTP_ERR_STR);
      BIO_free_all(certbio);
      return -7;
   }

   if (X509_digest(cert, EVP_sha256(), (unsigned char *)fingerprint, &size) == 0) {
      ICE_ERROR2("failed to convert X509 structure, err=%s", SRTP_ERR_STR);
      X509_free(cert);
      BIO_free_all(certbio);
      return -8;
   }

   tempbuf = (char *)&local_fingerprint;
   for(i = 0; i < size; i++) {
      snprintf(tempbuf, 4, "%.2X:", fingerprint[i]);
      tempbuf += 3;
   }
   *(tempbuf-1) = 0;

   ICE_DEBUG2("fingerprint of certificate: %s", local_fingerprint);
   X509_free(cert);
   BIO_free_all(certbio);
   SSL_CTX_set_cipher_list(ssl_ctx, DTLS_CIPHERS);

   /* Initialize libsrtp */
   if(srtp_init() != err_status_ok) {
      ICE_ERROR2("failed to set up libsrtp");
      return -9;
   }

   return 0;
}

dtls_ctx_t *
srtp_context_new(snw_ice_context_t *ice_ctx, void *component, int role) {
   snw_log_t *log = 0;
   dtls_ctx_t *dtls = NULL;

   if (!ice_ctx) return 0;
   log = ice_ctx->log;

   DEBUG(log, "create DTLS/SRTP, role=%d", role);

   dtls = (dtls_ctx_t*)malloc(sizeof(dtls_ctx_t));
   if (dtls == NULL) {
      ICE_ERROR2("getting dtls failed");
      return NULL;
   }
   memset(dtls,0,sizeof(dtls_ctx_t));

   /* Create SSL context */
   dtls->is_valid = 0;
   dtls->ssl = SSL_new(srtp_get_ssl_ctx());
   if (!dtls->ssl) {
      ICE_ERROR2("failed to create DTLS session, err=%s",
         ERR_reason_error_string(ERR_get_error()));
      srtp_context_free(dtls);
      return NULL;
   }

   SSL_set_ex_data(dtls->ssl, 0, dtls);
   SSL_set_info_callback(dtls->ssl, srtp_callback);
   dtls->read_bio = BIO_new(BIO_s_mem());
   if (!dtls->read_bio) {
      ICE_ERROR2("failed to create read_BIO, err=%s", SRTP_ERR_STR);
      srtp_context_free(dtls);
      return NULL;
   }

   BIO_set_mem_eof_return(dtls->read_bio, -1);
   dtls->write_bio = BIO_new(BIO_s_mem());
   if (!dtls->write_bio) {
      ICE_ERROR2("failed to create write_BIO, err=%s", SRTP_ERR_STR);
      srtp_context_free(dtls);
      return NULL;
   }
   BIO_set_mem_eof_return(dtls->write_bio, -1);

   /* The write BIO needs our custom filter, or fragmentation won't work */
   dtls->filter_bio = BIO_new(BIO_ice_dtls_filter()); //call: dtls_bio_filter_ctrl
   if (!dtls->filter_bio) {
      ICE_ERROR("failed to create filter_BIO, err=%s", SRTP_ERR_STR);
      srtp_context_free(dtls);
      return NULL;
   }
   dtls->filter_bio->ptr = &dtls->bio_pending_state;

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
   if(ecdh == NULL) {
      ICE_ERROR2("Error creating ECDH group! (%s)",
         ERR_reason_error_string(ERR_get_error()));
      srtp_context_free(dtls);
      return NULL;
   }
   SSL_set_options(dtls->ssl, SSL_OP_SINGLE_ECDH_USE);
   SSL_set_tmp_ecdh(dtls->ssl, ecdh);
   EC_KEY_free(ecdh);
   dtls->ready = 0;
   dtls->dtls_connected = 0;
   dtls->component = component;

   return dtls;
}

void srtp_do_handshake(dtls_ctx_t *dtls) {

   if (dtls == NULL || dtls->ssl == NULL)
      return;

   //FIXME: state not used?
   if (dtls->state == DTLS_STATE_CREATED)
      dtls->state = DTLS_STATE_TRYING;

   //DEBUG("Start DTLS handshake");
   SSL_do_handshake(dtls->ssl);
   srtp_send_data(dtls);

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
         component->component_id, component->stream_id);

   struct list_head *n,*p;
   list_for_each(n,&session->streams.list) {
      snw_ice_stream_t *s = list_entry(n,snw_ice_stream_t,list);
      if (s->is_disable)
         continue;
      list_for_each(p,&s->components.list) {
         snw_ice_component_t *c = list_entry(p,snw_ice_component_t,list);
         DEBUG(log, "checking component, sid=%u, cid=%u",s->id, c->component_id);
         if (!c->dtls || !c->dtls->is_valid) {
            DEBUG(log, "component not ready, sid=%u, cid=%u",s->id, c->component_id);
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
   snw_ice_component_t *component = NULL;
   snw_ice_stream_t *stream = NULL;
   snw_ice_session_t *session = NULL;

   if (dtls == NULL) {
      return -1;
   }

   component = (snw_ice_component_t *)dtls->component;
   if(component == NULL) {
      return -2;
   }

   stream = component->stream;
   if(!stream) {
      return -3;
   }

   session = stream->session;
   if (!session || !session->agent) {
      return -4;
   }

   X509 *rcert = SSL_get_peer_certificate(dtls->ssl);
   if(!rcert) {
      ICE_DEBUG2("No remote certificate, s=%s", ERR_reason_error_string(ERR_get_error()));
   } else {
         unsigned int rsize;
         unsigned char rfingerprint[EVP_MAX_MD_SIZE];
         char remote_fingerprint[160];
         char *rfp = (char *)&remote_fingerprint;
         if(stream->remote_hashing && !strcasecmp(stream->remote_hashing, "sha-1")) {
            ICE_DEBUG2("Computing sha-1 fingerprint of remote certificate...");
            X509_digest(rcert, EVP_sha1(), (unsigned char *)rfingerprint, &rsize);
         } else {
            ICE_DEBUG2("Computing sha-256 fingerprint of remote certificate...");
            X509_digest(rcert, EVP_sha256(), (unsigned char *)rfingerprint, &rsize);
         }
         X509_free(rcert);
         rcert = NULL;
         unsigned int i = 0;
         for(i = 0; i < rsize; i++) {
            snprintf(rfp, 4, "%.2X:", rfingerprint[i]);
            rfp += 3;
         }
         *(rfp-1) = 0;
         ICE_DEBUG2("Remote fingerprint, remote_hashing=%s, remote_fingerprint=%s",
            stream->remote_hashing ? stream->remote_hashing : "sha-256", remote_fingerprint);
         if (!strcasecmp(remote_fingerprint, stream->remote_fingerprint ? stream->remote_fingerprint : "(none)")) {
            ICE_DEBUG2("Fingerprint is a match!");
            dtls->state = DTLS_STATE_CONNECTED;
            dtls->dtls_connected = get_monotonic_time();
         } else {
            // FIXME NOT a match! MITM?
            ICE_ERROR2("Fingerprint mismatch, got=%s, expected=%s", remote_fingerprint, stream->remote_fingerprint);
            dtls->state = DTLS_STATE_FAILED;
            goto done;
         }
         if (dtls->state == DTLS_STATE_CONNECTED) {
            //FIX: 28-05 jackiedinh
            if (component->stream_id == session->audio_stream->id 
                || component->stream_id == session->video_stream->id) {
               // Complete with SRTP setup
               unsigned char material[SRTP_MASTER_LENGTH*2];
               unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
               // Export keying material for SRTP
               if (!SSL_export_keying_material(dtls->ssl, material, SRTP_MASTER_LENGTH*2, "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
                  ICE_DEBUG2("failed to extract SRTP keying material, cid=%u, sid=%u, err=%s",
                     component->component_id, stream->stream_id, ERR_reason_error_string(ERR_get_error()));
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
                         component->component_id, stream->stream_id, ret);
                  goto done;
               }
               ICE_DEBUG2("Created inbound SRTP session, cid=%u, sid=%u", 
                     component->component_id, stream->stream_id);
               ret = srtp_create(&(dtls->srtp_out), &(dtls->local_policy));
               if(ret != err_status_ok) {
                  ICE_ERROR2("failed to create outbound SRTP session, cid=%u, sid=%u, ret=%d", 
                         component->component_id, stream->stream_id, ret);
                  goto done;
               }
               dtls->is_valid = 1;
               ICE_DEBUG2("Created outbound SRTP session for component %d in stream %d", 
                     component->component_id, stream->stream_id);
            }
            dtls->ready = 1;
         }
done:
         if (dtls->is_valid) {
            ice_srtp_handshake_done(session, component);
         } else {
            srtp_callback(dtls->ssl, SSL_CB_ALERT, 0);
         }
   }

   return 0;
}

int
srtp_process_incoming_msg(dtls_ctx_t *dtls, char *buf, uint16_t len) {
   char data[1500];
   snw_log_t *log = 0;
   snw_ice_component_t *component = 0;
   int read = 0;
   int written = 0;

   if (!dtls || !dtls->ssl || !dtls->read_bio) {
      return -1;
   }
   component = (snw_ice_component_t*)dtls->component;
   log = component->stream->session->ice_ctx->log;
   
   DEBUG(log, "dtls message, len=%u",len);

   srtp_send_data(dtls);
   written = BIO_write(dtls->read_bio, buf, len);
   if (written != len) {
      ERROR(log, "failed to write, written=%u, len=%u", written, len);
   } else {
      DEBUG(log, "bio write, written=%u", written);
   }
   //DEBUG(log, "srtp_send_data 1, written=%d",written);
   //srtp_send_data(dtls);

   /* Try to read data */
   memset(&data, 0, 1500);
   read = SSL_read(dtls->ssl, &data, 1500);
   if (read < 0) {
      unsigned long err = SSL_get_error(dtls->ssl, read);
      if (err == SSL_ERROR_SSL) {
         char error[200];
         ERR_error_string_n(ERR_get_error(), error, 200);
         ERROR(log,"Handshake error: read=%d, s=%s", read, error);
         return -9;
      }
   }
   DEBUG(log, "srtp_send_data 2, read=%d",read);
   srtp_send_data(dtls);

   if (!SSL_is_init_finished(dtls->ssl)) {
      return -8;
   }

   if (dtls->ready) {
      DEBUG(log,"data available, read=%u",read);
      if(read > 0) {
         DEBUG(log,"Data available but Data Channels support disabled...");
      }
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
   /* Destroy DTLS stack and free resources */
   dtls->component = NULL;
   if(dtls->ssl != NULL) {
      SSL_free(dtls->ssl);
      dtls->ssl = NULL;
   }
   /* BIOs are destroyed by SSL_free */
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
      /* FIXME What about dtls->remote_policy and dtls->local_policy? */
   }
   free(dtls);
   dtls = NULL;
}

/* DTLS alert callback */
void srtp_callback(const SSL *ssl, int where, int ret) {

   ICE_DEBUG2("dtls callback, where=%u",where);//SSL_CB_ALERT

/*   if (!(where & SSL_CB_ALERT)) {
      return;
   }

   dtls_ctx_t *dtls = (dtls_ctx_t*)SSL_get_ex_data(ssl, 0);
   if (!dtls) {
      ICE_ERROR2("no dtls session, where=%d, ret=%d", where, ret);
      return;
   }

   snw_ice_component_t *component = (snw_ice_component_t*)dtls->component;
   if (component == NULL) {
      ICE_ERROR2("no ice component, where=%d, ret=%d", where, ret);
      return;
   }

   snw_ice_stream_t *stream = (snw_ice_stream_t*)component->stream;
   if (!stream) {
      ICE_ERROR2("no ice stream, where=%d, ret=%d", where, ret);
      return;
   }

   snw_ice_session_t *handle = stream->session;
   if (!handle) {
      ICE_ERROR2("no ice session, where=%d, ret=%d", where, ret);
      return;
   }

   ICE_DEBUG2("DTLS alert triggered, sid=%u, cid=%u", stream->stream_id, component->component_id);
*/
   return;
}

/* DTLS certificate verification callback */
int srtp_verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {

   return 1;
}

int srtp_send_data(dtls_ctx_t *dtls) {
   snw_ice_session_t *session = NULL;
   snw_ice_component_t *component = NULL;
   snw_ice_stream_t *stream = NULL;
   int pending = 0;

   if (dtls == NULL) {
      return -1;
   }

   component = (snw_ice_component_t *)dtls->component;
   if (component == NULL) {
      return -2;
   }

   stream = component->stream;
   if (!stream) {
      return -3;
   }

   session = stream->session;
   if (!session || !session->agent || !dtls->write_bio) {
      return -4;
   }

   pending = BIO_ctrl_pending(dtls->filter_bio);
   while (pending > 0) {
      char outgoing[pending]; //FIXME: change init of array?
      int out = BIO_read(dtls->write_bio, outgoing, sizeof(outgoing));

      ICE_DEBUG2("read data from the write_BIO, pending=%u, len=%u", pending, out);
      if(out > 1500) {
         /* FIXME need proper fragmentation */
         ICE_ERROR2("larger than the MTU, len=%u", out);
      }
      int bytes = ice_agent_send(session->agent, component->stream_id, 
                                 component->component_id, outgoing, out);

      //HEXDUMP(outgoing,out,"dtls");
      if(bytes < out) {
         ICE_ERROR2("failed to send DTLS message, cid=%u, sid=%u, len=%d", 
               component->component_id, stream->stream_id, bytes);
      } else {
         //ICE_DEBUG2("send result, bytes=%u,out=%u",bytes,out);
      }

      /* Check if there's anything left to send (e.g., fragmented packets) */
      pending = BIO_ctrl_pending(dtls->filter_bio);
   }

   return 0;
}

/* Starting MTU value for the DTLS BIO filter */
static int mtu = 1472;
void srtp_bio_filter_set_mtu(int start_mtu) {
   if (start_mtu < 0) {
      ICE_ERROR2("Invalid MTU, mtu=%d",start_mtu);
      return;
   }
   ICE_DEBUG2("Setting starting MTU in the DTLS BIO filter: %d", start_mtu);
   mtu = start_mtu;
   return;
}

/* Filter implementation */
int dtls_bio_filter_write(BIO *h, const char *buf,int num);
long dtls_bio_filter_ctrl(BIO *h, int cmd, long arg1, void *arg2);
int dtls_bio_filter_new(BIO *h);
int dtls_bio_filter_free(BIO *data);

static BIO_METHOD dtls_bio_filter_methods = {
   BIO_TYPE_FILTER,
   "srtp filter",
   dtls_bio_filter_write,
   NULL,
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


/* Helper struct to keep the filter state */
//#define ICE_DTLS_PKT_NUM 10
//typedef struct dtls_bio_filter {
//   int pkts[ICE_DTLS_PKT_NUM+1];
//   int num;
//} dtls_bio_filter;

int
ice_dtls_append_pkt(dtls_bio_filter *filter, int pkt) {

   for (int i=0; i<ICE_DTLS_PKT_NUM; i++) {
      ICE_ERROR2("append, pkt=%d",filter->pkts[i]);
      if ( filter->pkts[i] == 0 ) {
         filter->pkts[i] = pkt;
         filter->num++;
         return 0;
      }
   }

   ICE_ERROR2("no more space, pkt=%d",pkt);
   return -1;
}

int
ice_dtls_get_pkt(dtls_bio_filter *filter) {
   
   for (int i=0; i<ICE_DTLS_PKT_NUM; i++) {
      if ( filter->pkts[i] != 0 ) {
         return filter->pkts[i];
      }
   }

   return 0;
}

int
ice_dtls_remove_pkt(dtls_bio_filter *filter) {
   
   if ( filter->num < 1 )
      return -1; 

   for (int i=1; i<filter->num; i++) {
      filter->pkts[i-1] = filter->pkts[i];
   }
   filter->num--;
   filter->pkts[filter->num] = 0;

   /*for (int i=0; i<filter->num; i++) {
      ICE_ERROR2("after remove, pkt=%d",filter->pkts[i]);
      if ( filter->pkts[i] == 0 ) {
         break;
      }
   }*/

   return 0;
}

/*void print_test(gpointer data, gpointer user_data) {
   int pkt = GPOINTER_TO_INT(data);

   ICE_DEBUG2("old list: %u", pkt);
}*/

void
ice_dtls_print_pkt_list(dtls_bio_filter *filter, const char *type) {
   
   ICE_DEBUG2("type=%s, num=%u",type,filter->num);
   for (int i=0; i<filter->num; i++) {
      ICE_DEBUG2("new list: %u",filter->pkts[i]);
   }

   return;
}

int dtls_bio_filter_new(BIO *bio) {
   /* Create a filter state struct */
   ICE_DEBUG2("dtls bio filter new");
   //dtls_bio_filter *filter = (dtls_bio_filter *)malloc(sizeof(dtls_bio_filter));
   //memset(filter,0,sizeof(dtls_bio_filter));
   //filter->num = 0;
   //bio->ptr = filter;
   
   /* Set the BIO as initialized */
   bio->init = 1;
   bio->flags = 0;
   
   return 1;
}

int dtls_bio_filter_free(BIO *bio) {
   if(bio == NULL)
      return 0;
      
   /* Get rid of the filter state */
   //dtls_bio_filter *filter = (dtls_bio_filter *)bio->ptr;
   //if(filter != NULL) {
   //   free(filter);
   //}
   bio->ptr = NULL;
   bio->init = 0;
   bio->flags = 0;
   return 1;
}
   
int dtls_bio_filter_write(BIO *bio, const char *in, int inl) {
   long ret = BIO_write(bio->next_bio, in, inl);

   ICE_DEBUG2("dtls_bio_filter_write, len=%d, written_len=%ld", inl, ret);
   
   dtls_bio_filter *filter = (dtls_bio_filter *)bio->ptr;
   if(filter != NULL) {
      ice_dtls_append_pkt(filter, ret);
      //ice_dtls_print_pkt_list(filter,"append");
   }
   return ret;
}

long dtls_bio_filter_ctrl(BIO *bio, int cmd, long num, void *ptr) {
   switch(cmd) {
      case BIO_CTRL_FLUSH:
         /* The OpenSSL library needs this */
         return 1;
      case BIO_CTRL_DGRAM_QUERY_MTU:
         /* Let's force the MTU that was configured */
         ICE_DEBUG2("Advertizing MTU: %d", mtu);
         return mtu;
      case BIO_CTRL_WPENDING:
         return 0L;
      case BIO_CTRL_PENDING: {
         /* We only advertize one packet at a time, as they may be fragmented */
         dtls_bio_filter *filter = (dtls_bio_filter *)bio->ptr;
         if(filter == NULL)
            return 0;

         if ( filter->num == 0 )
            return 0;
         int pending = ice_dtls_get_pkt(filter);
         ice_dtls_remove_pkt(filter);
         return pending;
      }
      default:
         ICE_DEBUG2("dtls_bio_filter_ctrl: %d", cmd);
   }
   return 0;
}


void
srtp_destroy(dtls_ctx_t *dtls) {
   //FIXME: impl
   return;
}
