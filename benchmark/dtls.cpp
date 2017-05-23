#include <srtp/srtp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <time.h>

#include <cicero/agent.h>

#include "dtls.h"
#include "util.h"
#include "wsclient.h"

#define SRTP_ERR_STR ERR_reason_error_string(ERR_get_error())

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

int
ice_dtls_append_pkt(dtls_bio_filter *filter, int pkt) {
   int i = 0;
   for (i=0; i<ICE_DTLS_PKT_NUM; i++) {
      DEBUG("append, pkt=%d",filter->pkts[i]);
      if ( filter->pkts[i] == 0 ) {
         filter->pkts[i] = pkt;
         filter->num++;
         return 0;
      }
   }

   DEBUG("no more space, pkt=%d",pkt);
   return -1;
}

int
ice_dtls_get_pkt(dtls_bio_filter *filter) {
   int i = 0; 
   for (i=0; i<ICE_DTLS_PKT_NUM; i++) {
      if ( filter->pkts[i] != 0 ) {
         return filter->pkts[i];
      }
   }

   return 0;
}

int
ice_dtls_remove_pkt(dtls_bio_filter *filter) {
   int i = 0; 
   if (filter->num < 1)
      return -1; 

   for (i=1; i<filter->num; i++) {
      filter->pkts[i-1] = filter->pkts[i];
   }
   filter->num--;
   filter->pkts[filter->num] = 0;

   /*for (int i=0; i<filter->num; i++) {
      DEBUG("after remove, pkt=%d",filter->pkts[i]);
      if ( filter->pkts[i] == 0 ) {
         break;
      }
   }*/

   return 0;
}

/*void print_test(gpointer data, gpointer user_data) {
   int pkt = GPOINTER_TO_INT(data);
   DEBUG("old list: %u", pkt);
}*/

void
ice_dtls_print_pkt_list(dtls_bio_filter *filter, const char *type) {
   int i = 0; 
   DEBUG("type=%s, num=%u",type,filter->num);
   for (i=0; i<filter->num; i++) {
      DEBUG("new list: %u",filter->pkts[i]);
   }

   return;
}


int dtls_bio_filter_new(BIO *bio) {
   /* Create a filter state struct */
   DEBUG("dtls bio filter new");
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

   DEBUG("dtls_bio_filter_write, len=%d, written_len=%ld", inl, ret);
   
   dtls_bio_filter *filter = (dtls_bio_filter *)bio->ptr;
   if(filter != NULL) {
      ice_dtls_append_pkt(filter, ret);
      //ice_dtls_print_pkt_list(filter,"append");
   }
   return ret;
}

long dtls_bio_filter_ctrl(BIO *bio, int cmd, long num, void *ptr) {
   static int mtu = 1476;
   switch(cmd) {
      case BIO_CTRL_FLUSH:
         /* The OpenSSL library needs this */
         return 1;
      case BIO_CTRL_DGRAM_QUERY_MTU:
         /* Let's force the MTU that was configured */
         DEBUG("Advertizing MTU: %d", mtu);
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
         DEBUG("dtls_bio_filter_ctrl: %d", cmd);
   }
   return 0;
}


static int _ssl_verify_peer(int preverify_ok, X509_STORE_CTX *ctx) {
   //printf("preverify_ok: %d\n", preverify_ok);
   return preverify_ok;
}


int
init_dtls_srtp_ctx(DTLSParams* params, const char* keyname)
{
   BIO *certbio = NULL;
   X509 *cert = NULL;
   unsigned char fingerprint[EVP_MAX_MD_SIZE];
   char *tempbuf = NULL;
   unsigned int size;
   int result = 0;
   int i = 0;

    // Create a new context using DTLS
    params->ctx = SSL_CTX_new(DTLSv1_method());
    if (params->ctx == NULL) {
        printf("Error: cannot create SSL_CTX.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set our supported ciphers
    result = SSL_CTX_set_cipher_list(params->ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if (result != 1) {
        printf("Error: cannot set the cipher list.\n");
        ERR_print_errors_fp(stderr);
        return -2;
    }

    // The client doesn't have to send it's certificate
    //SSL_CTX_set_verify(params->ctx, SSL_VERIFY_PEER, _ssl_verify_peer);
    SSL_CTX_set_verify(params->ctx, SSL_VERIFY_NONE, _ssl_verify_peer);

    // Load key and certificate
    char certfile[1024];
    char keyfile[1024];
    sprintf(certfile, "./letsen/%s-cert.pem", keyname);
    sprintf(keyfile, "./letsen/%s-key.pem", keyname);

    // Load the certificate file; contains also the public key
    result = SSL_CTX_use_certificate_file(params->ctx, certfile, SSL_FILETYPE_PEM);
    if (result != 1) {
        printf("Error: cannot load certificate file.\n");
        ERR_print_errors_fp(stderr);
        return -3;
    }

    // Load private key
    result = SSL_CTX_use_PrivateKey_file(params->ctx, keyfile, SSL_FILETYPE_PEM);
    if (result != 1) {
        printf("Error: cannot load private key file.\n");
        ERR_print_errors_fp(stderr);
        return -4;
    }

    // Check if the private key is valid
    result = SSL_CTX_check_private_key(params->ctx);
    if (result != 1) {
        printf("Error: checking the private key failed. \n");
        ERR_print_errors_fp(stderr);
        return -5;
    }

   SSL_CTX_set_read_ahead(params->ctx,1);
   certbio = BIO_new(BIO_s_file());
   if (certbio == NULL) {
      printf("certificate BIO error \n");
      return -5; 
   } 

   if (BIO_read_filename(certbio, certfile) == 0) {
      printf("failed to read certificate, err=%s\n", SRTP_ERR_STR);
      BIO_free_all(certbio);
      return -6; 
   } 

   cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
   if (cert == NULL) {
      printf("failed to read certificate, err=%s\n", SRTP_ERR_STR);
      BIO_free_all(certbio);
      return -7;
   }

   if (X509_digest(cert, EVP_sha256(), (unsigned char *)fingerprint, &size) == 0) {
      printf("failed to convert X509 structure, err=%s\n", SRTP_ERR_STR);
      X509_free(cert);
      BIO_free_all(certbio);
      return -8; 
   }   

   tempbuf = (char*)params->local_fingerprint;
   for(i = 0; i < size; i++) {
      snprintf(tempbuf, 4, "%.2X:", fingerprint[i]);
      tempbuf += 3;
   }   
   *(tempbuf-1) = 0;

   printf("fingerprint of certificate: %s\n", params->local_fingerprint);

#define DTLS_CIPHERS "ALL:NULL:eNULL:aNULL"
   X509_free(cert);
   BIO_free_all(certbio);
   SSL_CTX_set_cipher_list(params->ctx, DTLS_CIPHERS);      

   /* Initialize libsrtp */
   if(srtp_init() != err_status_ok) {
      DEBUG("failed to set up libsrtp");
      return -9; 
   } 
   return 0;
}

void srtp_callback(const SSL *ssl, int where, int ret) {
   return;
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
   if(dtls->srtp_valid) {
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

int srtp_send_data(dtls_ctx_t *dtls) {
   int pending = 0;

   pending = BIO_ctrl_pending(dtls->filter_bio);
   while (pending > 0) {
      char outgoing[pending]; //FIXME: change init of array?
      int out = BIO_read(dtls->write_bio, outgoing, sizeof(outgoing));

      DEBUG("read data from the write_BIO, pending=%u, len=%u", pending, out);
      if(out > 1500) {
         /* FIXME need proper fragmentation */
         DEBUG("larger than the MTU, len=%u", out);
      }
      int bytes = ice_agent_send((agent_t*)dtls->agent, dtls->stream_id, 
                                 dtls->component_id, outgoing, out);

      HEXDUMP(outgoing,out,"dtls");
      if(bytes < out) {
         DEBUG("failed to send DTLS message, cid=%u, sid=%u, len=%d", 
               dtls->component_id, dtls->stream_id, bytes);
      } else {
         //DEBUG("send result, bytes=%u,out=%u",bytes,out);
      }

      /* Check if there's anything left to send (e.g., fragmented packets) */
      pending = BIO_ctrl_pending(dtls->filter_bio);
   }

   return 0;
}


void srtp_do_handshake(dtls_ctx_t *dtls) {

   if (dtls == NULL || dtls->ssl == NULL)
      return;

   //FIXME: state not used?
   if (dtls->state == DTLS_STATE_CREATED) {
      DEBUG("does it happen?");
      dtls->state = DTLS_STATE_TRYING;
   }

   SSL_do_handshake(dtls->ssl);
   DEBUG("After doing DTLS handshake");
   srtp_send_data(dtls);

   return;
}



dtls_ctx_t *
srtp_context_new(DTLSParams *params, void *component, int role) {
   dtls_ctx_t * dtls;

   DEBUG("create DTLS/SRTP, role=%d", role);

   dtls = (dtls_ctx_t*)malloc(sizeof(dtls_ctx_t));
   if (dtls == NULL) {
      DEBUG("getting dtls failed");
      return NULL;
   }
   memset(dtls,0,sizeof(dtls_ctx_t));

   /* Create SSL context */
   dtls->srtp_valid = 0;
   dtls->ssl = SSL_new(params->ctx);
   if (!dtls->ssl) {
      DEBUG("failed to create DTLS session, err=%s",
         ERR_reason_error_string(ERR_get_error()));
      srtp_context_free(dtls);
      return NULL;
   }

   SSL_set_ex_data(dtls->ssl, 0, dtls);
   SSL_set_info_callback(dtls->ssl, srtp_callback);
   dtls->read_bio = BIO_new(BIO_s_mem());
   if (!dtls->read_bio) {
      DEBUG("failed to create read_BIO, err=%s", SRTP_ERR_STR);
      srtp_context_free(dtls);
      return NULL;
   }

   BIO_set_mem_eof_return(dtls->read_bio, -1);
   dtls->write_bio = BIO_new(BIO_s_mem());
   if (!dtls->write_bio) {
      DEBUG("failed to create write_BIO, err=%s", SRTP_ERR_STR);
      srtp_context_free(dtls);
      return NULL;
   }
   BIO_set_mem_eof_return(dtls->write_bio, -1);

   /* The write BIO needs our custom filter, or fragmentation won't work */
   dtls->filter_bio = BIO_new(BIO_ice_dtls_filter()); //call: dtls_bio_filter_ctrl
   if (!dtls->filter_bio) {
      DEBUG("failed to create filter_BIO, err=%s", SRTP_ERR_STR);
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
      DEBUG("Setting state: connect, role=%u",dtls->role);
      SSL_set_connect_state(dtls->ssl);
   } else {
      DEBUG("Setting state: accept, role=%u",dtls->role);
      SSL_set_accept_state(dtls->ssl);
   }

   /* https://code.google.com/p/chromium/issues/detail?id=406458 
    * Specify an ECDH group for ECDHE ciphers, otherwise they cannot be
    * negotiated when acting as the server. Use NIST's P-256 which is
    * commonly supported.
    */
   EC_KEY* ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
   if(ecdh == NULL) {
      DEBUG("Error creating ECDH group! (%s)",
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
   params->dtls_ctx = dtls;

   return dtls;
}

int ice_get_packet_type(char* buf, int len) {
   rtp_header *header = NULL;
   
   if (!buf || len <= 0) {
      return UNKNOWN_PT;
   }   

   if ((*buf >= 20) && (*buf < 64)) {
      return DTLS_PT;
   }   

   if (len < RTP_HEADER_SIZE) {
      return UNKNOWN_PT;
   }   

   header = (rtp_header *)buf;
   if ((header->type < 64) || (header->type >= 96)) {
      return RTP_PT;
   } else if ((header->type >= 64) && (header->type < 96)) {
      return RTCP_PT;
   }   

   return UNKNOWN_PT;
}

int
srtp_process_incoming_msg(dtls_ctx_t *dtls, char *buf, uint16_t len) {
   char data[1500];
   int read = 0;
   int written = 0;

   DEBUG("dtls message, len=%u",len);
   if (!dtls || !dtls->ssl || !dtls->read_bio) {
      return -1;
   }
   DEBUG("srtp_send_data");
   srtp_send_data(dtls);
   written = BIO_write(dtls->read_bio, buf, len);
   if (written != len) {
      DEBUG("failed to write, written=%u, len=%u", written, len);
   } else {
      DEBUG("bio write, written=%u", written);
   }
   DEBUG("srtp_send_data 1, written=%d",written);
   srtp_send_data(dtls);

   /* Try to read data */
   memset(&data, 0, 1500);
   read = SSL_read(dtls->ssl, &data, 1500);
   if (read < 0) {
      unsigned long err = SSL_get_error(dtls->ssl, read);
      if (err == SSL_ERROR_SSL) {
         char error[200];
         ERR_error_string_n(ERR_get_error(), error, 200);
         DEBUG("Handshake error: read=%d, s=%s", read, error);
         return -9;
      }
   }
   DEBUG("srtp_send_data 2, read=%d",read);
   srtp_send_data(dtls);

   if (!SSL_is_init_finished(dtls->ssl)) {
      /* Nothing else to do for now */
      return -8;
   }

   if (dtls->ready) {
      DEBUG("data available, read=%u",read);
      if(read > 0) {
         DEBUG("Data available but Data Channels support disabled...");
      }
   } else {
      DEBUG("DTLS established");
      srtp_dtls_setup(dtls);
   }

   return 0;
}

int
srtp_dtls_setup(dtls_ctx_t *dtls) {

   if (dtls == NULL) {
      return -1;
   }

   X509 *rcert = SSL_get_peer_certificate(dtls->ssl);
   if(!rcert) {
      DEBUG("No remote certificate, s=%s", ERR_reason_error_string(ERR_get_error()));
   } else {
         unsigned int rsize;
         unsigned char rfingerprint[EVP_MAX_MD_SIZE];
         char remote_fingerprint[160];
         char *rfp = (char *)&remote_fingerprint;
         DEBUG("Computing sha-256 fingerprint of remote certificate...");
         X509_digest(rcert, EVP_sha256(), (unsigned char *)rfingerprint, &rsize);
         X509_free(rcert);
         rcert = NULL;
         unsigned int i = 0;
         for(i = 0; i < rsize; i++) {
            snprintf(rfp, 4, "%.2X:", rfingerprint[i]);
            rfp += 3;
         }
         *(rfp-1) = 0;
         DEBUG("Remote fingerprint, remote_hashing=%s, remote_fingerprint=%s",
            "sha-256", remote_fingerprint);
         //if (!strcasecmp(remote_fingerprint, g_config->dtls_params->remote_fingerprint)) {
            DEBUG("Fingerprint is a match!");
            dtls->state = DTLS_STATE_CONNECTED;
            dtls->dtls_connected = get_monotonic_time();
         //} else {
         //   // FIXME NOT a match! MITM?
         //   DEBUG("Fingerprint mismatch, got=%s, expected=%s", remote_fingerprint, stream->rfingerprint);
         //   dtls->state = DTLS_STATE_FAILED;
         //   goto done;
         //}

         if(dtls->state == DTLS_STATE_CONNECTED) {
            if( 1 ) {
               // Complete with SRTP setup
               unsigned char material[SRTP_MASTER_LENGTH*2];
               unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
               // Export keying material for SRTP
               if (!SSL_export_keying_material(dtls->ssl, material, SRTP_MASTER_LENGTH*2, "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
                  DEBUG("failed to extract SRTP keying material, cid=%u, sid=%u, err=%s",
                     dtls->component_id, dtls->stream_id, ERR_reason_error_string(ERR_get_error()));
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
                  DEBUG("failed to create inbound SRTP session, cid=%u, sid=%u, ret=%d", 
                         dtls->component_id, dtls->stream_id, ret);
                  goto done;
               }
               DEBUG("Created inbound SRTP session, cid=%u, sid=%u", 
                     dtls->component_id, dtls->stream_id);
               ret = srtp_create(&(dtls->srtp_out), &(dtls->local_policy));
               if(ret != err_status_ok) {
                  DEBUG("failed to create outbound SRTP session, cid=%u, sid=%u, ret=%d", 
                         dtls->component_id, dtls->stream_id, ret);
                  goto done;
               }
               dtls->srtp_valid = 1;
               DEBUG("Created outbound SRTP session for component %d in stream %d", 
                     dtls->component_id, dtls->stream_id);
            }
            dtls->ready = 1;
         }
done:
         if (dtls->srtp_valid) {
            DEBUG("srtp handshake done");
            //ice_srtp_handshake_done(session, component);
            WsClient *client = (WsClient*)dtls->wsclient;
            client->play();
         } else {
            DEBUG("srtp callback");
            //srtp_callback(dtls->ssl, SSL_CB_ALERT, 0);
         }
   }

   return 0;
}


