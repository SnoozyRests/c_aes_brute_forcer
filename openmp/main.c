#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <time.h>
#include <omp.h>

int success = 0;

void handleOpenSSLErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char* decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv ){

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
         success = 1;
    plaintext_len += len;

   
    /* Add the null terminator */
    plaintext[plaintext_len] = 0;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    //string ret = (char*)plaintext;
    //delete [] plaintext;
    return plaintext;
}

size_t calcDecodeLength(char* b64input) {
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;
    return (len*3)/4 - padding;
}

void Base64Decode( char* b64message, unsigned char** buffer, size_t* length) {

    
    BIO *bio, *b64;  // A BIO is an I/O strean abstraction

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    //BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

void initAES(const unsigned char *pass, unsigned char* salt, unsigned char* key, unsigned char* iv )
{
    //initialisatio of key and iv with 0
    bzero(key,sizeof(key)); 
    bzero(iv,sizeof(iv));
  
    EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, pass, strlen(pass), 1, key, iv);
}



int main (void)
{

    char* ciphertext_base64 = (char*) "U2FsdGVkX19VjPGO9qgNMHQCCUycG42mf7Ak0JMI79lPmAAu8XCmJfY4T/8T2RLDrnsf9WVPPGqB/rVgfRMhDmLnNsgp1Ukh8ygs+j0cgCYO4O3J5EMVb7utga9xSFSXe0ZsrfngA+ftf4OL6jOioA==\n";
    //This is the top seret message in parallel computing! Please keep it in a safe place.
    int decryptedtext_len, ciphertext_len;

    // cipher (binary) pointer and length
    size_t cipher_len; // size_t is sizeof(type)
    unsigned char* ciphertext;
  
    unsigned char salt[8];
    
    ERR_load_crypto_strings();
    
    Base64Decode(ciphertext_base64, &ciphertext, &cipher_len);
    //printf("%s\n", ciphertext);
    //return 0;
    unsigned char key[16];
    unsigned char iv[16];

    unsigned char plainpassword[] = "00000";
    unsigned char* password = &plainpassword[0];
    int password_length = 5;

    //const char *alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
		       //"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    //clock_t begin = clock();
    // retrive the slater from ciphertext (binary)
    if (strncmp((const char*)ciphertext,"Salted__",8) == 0) {
        memcpy(salt,&ciphertext[8],8);
        ciphertext += 16;
        cipher_len -= 16;
    }
    // generate key and iv
    for(int i = 0; i < 72; i++)
        for(int j = 0; j < 72; j++)
            for(int k = 0; k < 72; k++)
                for(int l = 0; l < 72; l++)
                    for(int m = 0; m < 72; m++){
                        //*password = alphabet[i];
                        //*(password+1) = alphabet[j];
                        //*(password+2) = alphabet[k];
                        //*(password+3) = alphabet[l];
                        //*(password+4) = alphabet[m];

                        *password = 48 + i;
                        *(password+1) = 48 + j;
                        *(password+2) = 48 + k;
                        *(password+3) = 48 + l;
                        *(password+4) = 48 + m;

                printf("%s\n", password);

                initAES(password, salt, key, iv);
                unsigned char* result = decrypt(ciphertext, cipher_len, key, iv);
                if (success == 1){
                    printf("%s\n", result);
                    return 0;
                } //else {
                    //printf("unsuccessful!\n");
                //}
            }

    /**password = 48+1;
    *(password+1) = 48+2;
    *(password+2) = 48+3;

    printf("%c\n", *(password+1));

    initAES(password, salt, key, iv);
    unsigned char* result = decrypt(ciphertext, cipher_len, key, iv);
    if (success == 1){
        printf("%s\n", result);
        return 0;
    }
    else {printf("unsuccessful!\n");}

    */
    // Clean up
    
    EVP_cleanup();
    ERR_free_strings();
    //clock_t end = clock();
    //double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    //printf("\n%f", time_spent);

    return 0;
}