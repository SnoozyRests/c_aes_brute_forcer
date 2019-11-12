#include <openssl/ssl.h>
#include <openssl/err.h>
#include <omp.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <time.h>
#include "b64.c"
#include "aes.c"

int success = 0;
void printTime(clock_t, clock_t);

int checkPlaintext(char* plaintext, char* result){
    int length = 10; 
    return strncmp(plaintext, result, length);
}

int main (void)
{

    clock_t start = clock(), end;
    char* ciphertext_base64 = (char*) "U2FsdGVkX19VjPGO9qgNMHQCCUycG42mf7Ak0JMI79lPmAAu8XCmJfY4T"
                                        "/8T2RLDrnsf9WVPPGqB/rVgfRMhDmLnNsgp1Ukh8ygs+j0cgCYO4O3J"
                                        "5EMVb7utga9xSFSXe0ZsrfngA+ftf4OL6jOioA==\n";
    char* plaintext = "This is the top seret message in parallel computing!"
                        "Please keep it in a safe place.";
    // pasword 12Dec

    char dict[] = "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";
    //char dict[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    //                "abcdefghijklmnopqrstuvwxyz"
    //                "0123456789";
    
    int decryptedtext_len, ciphertext_len, dict_len;

    size_t cipher_len;
    unsigned char* ciphertext;
  
    unsigned char salt[8];
    
    ERR_load_crypto_strings();
    
    Base64Decode(ciphertext_base64, &ciphertext, &cipher_len);

    unsigned char key[16];
    unsigned char iv[16];

    unsigned char plainpassword[] = "00000";
    unsigned char* password = &plainpassword[0];
    int password_length = 3;

    if (strncmp((const char*)ciphertext,"Salted__",8) == 0) {
        
        memcpy(salt,&ciphertext[8],8);
        ciphertext += 16;
        cipher_len -= 16;
    
    }

    dict_len = strlen(dict);
    
    omp_set_num_threads(6);

        int id;
        #pragma omp parallel for collapse(5)
        for(int i = 0; i < dict_len; i++)
            for(int j = 0; j < dict_len; j++)
                for(int k = 0; k < dict_len; k++)
                    for(int l = 0; l < dict_len; l++)
                        for(int m = 0; m < dict_len; m++){
                            id = omp_get_thread_num();
                            *password = dict[i];
                            *(password+1) = dict[j];
                            *(password+2) = dict[k];
                            *(password+3) = dict[l];
                            *(password+4) = dict[m];
                            printf("%s, (%d)\n", password, id);

                            initAES(password, salt, key, iv);
                            unsigned char* result = decrypt(ciphertext, cipher_len, key, iv, &success);
                            
                            if (success == 1){
                                if(checkPlaintext(plaintext, result) == 0){
                                    printf("%s\n", result);
                                    end = clock();
                                    printTime(start, end);
                                    exit(0);
                                }

                            }
                       
                            free(result);
                            //printf("unsuccessful!\n");
                        
                        }
   // }

    // Clean up
    
    EVP_cleanup();
    ERR_free_strings();

    //end = clock();
    //printTime(start, end);

    return 0;
}

void printTime(clock_t start, clock_t end){
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf("\nTime spent: %f\n", time_spent);
}

