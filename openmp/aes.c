#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

void handleOpenSSLErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

void initAES(const unsigned char *pass, unsigned char* salt, unsigned char* key, unsigned char* iv){
    bzero(key,sizeof(key)); 
    bzero(iv,sizeof(iv));
  
    EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, pass, strlen(pass), 1, key, iv);
}

unsigned char* decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, int *success ){

    EVP_CIPHER_CTX *ctx;
    unsigned char *plaintexts;
    int len;
    int plaintext_len;
    
    unsigned char* plaintext = malloc(ciphertext_len);
    bzero(plaintext,ciphertext_len);

    if(!(ctx = EVP_CIPHER_CTX_new())){ 
        handleOpenSSLErrors();
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)){
        handleOpenSSLErrors();
    }

  
    EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        handleOpenSSLErrors();
    }

    plaintext_len = len;

    if(1 == EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
         *success = 1;
    }

    plaintext_len += len;

    plaintext[plaintext_len] = 0;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}