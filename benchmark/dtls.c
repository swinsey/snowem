#include <srtp/srtp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "dtls.h"

#define SRTP_ERR_STR ERR_reason_error_string(ERR_get_error())

static int _ssl_verify_peer(int preverify_ok, X509_STORE_CTX *ctx) {
   //printf("preverify_ok: %d\n", preverify_ok);
   return preverify_ok;
}


int
dtls_InitContextFromKeystore(DTLSParams* params, const char* keyname)
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
    SSL_CTX_set_verify(params->ctx, SSL_VERIFY_PEER, _ssl_verify_peer);

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
   return 0;
}

