/*
    Author: Dr Kun Wei
    Program: AES-128-CBC decryption functions.
    Credits: Jacob J Williams - Refactoring
    Notes: Utilised in coursework for the Parallel Computing masters module at UWE. UFCFFL-15-M.
*/
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

void handleOpenSSLErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void initAES(const unsigned char *pass, unsigned char* salt, unsigned char* key, unsigned char* iv)
{
    //initialisatio of key and iv with 0
    bzero(key,sizeof(key)); 
    bzero(iv,sizeof(iv));
  
    EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, pass, strlen(pass), 1, key, iv);
}

unsigned char* decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, int *success){

    EVP_CIPHER_CTX *ctx;
    unsigned char *plaintexts;
    int len;
    int plaintext_len;
    
    //unsigned char* plaintext = new unsigned char[ciphertext_len];
    unsigned char* plaintext = malloc(ciphertext_len);
    bzero(plaintext,ciphertext_len);

    /* Create and initialise the context */
  
    if(!(ctx = EVP_CIPHER_CTX_new())) handleOpenSSLErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    
    //printf("%lu\n", strlen(key));
    //printf("%lu\n", strlen(iv));
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleOpenSSLErrors();

  
    EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleOpenSSLErrors();
   
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
   // return 1 if decryption successful, otherwise 0
    if(1 == EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
        //handleOpenSSLErrors()
         //printf("Here9!\n");
         *success = 1;
    plaintext_len += len;

   
    /* Add the null terminator */
    plaintext[plaintext_len] = 0;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    //string ret = (char*)plaintext;
    //delete [] plaintext;
    return plaintext;
}