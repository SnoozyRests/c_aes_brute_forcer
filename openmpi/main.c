/*
    Author: Jacob John Williams
    Program: AES128-cbc brute forcer using OpenMPI.
    Credits: Dr Kun Wei - underlying base code.
    Notes: Coursework for the Parallel Computing masters module at UWE. UFCFFL-15-M.
*/
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include "../dependencies/b64.c"
#include "../dependencies/aes.c"
#include <sys/time.h>
#include <mpi/mpi.h>

int success = 0;
/*
    Function: checkPlaintext
    Operation: Compares the recently acquired result to the target plaintext.
    Inputs: char* plaintext - pointer to target plaintext
            char* result - pointer to result of decryption attempt.
    Output: return strncmp(plaintext, result, length) - value < 0 : plaintext > result
                                                        value > 0 : plaintext < result
                                                        value = 0 : plaintext = result
    Notes: Complies with the standards of a Known-Plaintext-Attack. 
*/
int checkPlaintext(char* plaintext, char* result){
    int length = 10; // we just check the first then characters
    return strncmp(plaintext, result, length);
}

int main (int argc, char **argv)
{
    int myrank, rbuf, sbuf, count = 1, flag, err;
    MPI_Status status;
    MPI_Request req;
    clock_t start = clock(), end;
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);
    // This is the string Hello, World! encrypted using aes-256-cbc with the
    // pasword 12345
    char* ciphertext_base64 = (char*) "U2FsdGVkX19VjPGO9qgNMHQCCUycG42mf7Ak0JMI79lPmAAu8XCmJfY4T"
                                        "/8T2RLDrnsf9WVPPGqB/rVgfRMhDmLnNsgp1Ukh8ygs+j0cgCYO4O3J"
                                        "5EMVb7utga9xSFSXe0ZsrfngA+ftf4OL6jOioA==\n";
    char* plaintext = "This is the top seret message in parallel computing!"
                        "Please keep it in a safe place.";
    char dict[] = "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";
    //char dict[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    //                "abcdefghijklmnopqrstuvwxyz"
    //                "0123456789";
    
    int decryptedtext_len, ciphertext_len, dict_len;

    // cipher (binary) pointer and length
    size_t cipher_len; // size_t is sizeof(type)
    unsigned char* ciphertext;
  
    unsigned char salt[8];
    
    ERR_load_crypto_strings();
    
    Base64Decode(ciphertext_base64, &ciphertext, &cipher_len);

    unsigned char key[16];
    unsigned char iv[16];

    unsigned char plainpassword[] = "00000";
    unsigned char* password = &plainpassword[0];
    int password_length = 3;

    // retrive the slater from ciphertext (binary)
    if (strncmp((const char*)ciphertext,"Salted__",8) == 0) {
        
        memcpy(salt,&ciphertext[8],8);
        ciphertext += 16;
        cipher_len -= 16;
    
    }
    dict_len = strlen(dict);
    
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &myrank);
    MPI_Irecv(&rbuf, count, MPI_INT, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);
    //printf("Posted Recieve for %d\n", myrank);

        for(int j=0; j<dict_len; j++)
            for(int k=0; k<dict_len; k++)
                for(int l=0; l<dict_len; l++)
                    for(int m=0; m<dict_len; m++){
                        MPI_Test(&req, &flag, &status);
                        if(flag == 1){
                            printf("Another process has found the key, exiting...\n");
                            MPI_Finalize();
                        }
                        *password = dict[myrank];
                        *(password+1) = dict[j];
                        *(password+2) = dict[k];
                        *(password+3) = dict[l];
                        *(password+4) = dict[m];

                        //printf("%s\n", password);

                        initAES(password, salt, key, iv);
                        unsigned char* result = decrypt(ciphertext, cipher_len, key, iv, &success);
                        
                        if (success == 1){
                            if(checkPlaintext(plaintext, result)==0){

                                MPI_Bcast(&sbuf, count, MPI_INT, myrank, MPI_COMM_WORLD);

                                printf("%s\n%s", result, password);
                                gettimeofday(&end1, NULL);
                                double timetaken = end1.tv_sec + end1.tv_usec / 1e6 - start1.tv_sec  - start1.tv_usec / 1e6;
                                printf("\nTime spent: %f\n", timetaken);
                                
                                MPI_Abort(MPI_COMM_WORLD, err);
                                exit(0);
                            }

                        }
                       
                        free(result);
                        //printf("unsuccessful!\n");
                        
                    }

            
    // Clean up
    MPI_Finalize();
}
