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
    int length = 10;
    return strncmp(plaintext, result, length);
}

/*
    Function: main
    Operation: primary runtime, initialise variables, generate password, create parallel region, attempt cracking.
    Inputs: int argc - the amount of arguments passed by command line.
            char argv - arguments passed by command line, in this case it will be the number of desired processes (62)
    Outputs: return 0 - success value.
    Notes: N/A
*/
int main (int argc, char **argv){
    //Initialise OpenMPI specific variables, used in message passing and vector assignment.
    int myrank, rbuf, sbuf, count = 1, flag, err;
    MPI_Status status;
    MPI_Request req;

    //Initialise time keeping variables, clock_t only returned CPU time when using OpenMPI.
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);
    
    //Target Ciphertext and plaintext, Known-Plaintext-Attack standard. Target password is 12Dec.
    char* ciphertext_base64 = (char*) "U2FsdGVkX19VjPGO9qgNMHQCCUycG42mf7Ak0JMI79lPmAAu8XCmJfY4T"
                                        "/8T2RLDrnsf9WVPPGqB/rVgfRMhDmLnNsgp1Ukh8ygs+j0cgCYO4O3J"
                                        "5EMVb7utga9xSFSXe0ZsrfngA+ftf4OL6jOioA==\n";
    char* plaintext = "This is the top seret message in parallel computing!"
                        "Please keep it in a safe place.";

    /*
        Dictionary lookup varibles.
        Key : "Forward" = 0-9 / A-Z / a-z (standard ASCII order)
              "Reverse" = A-Z / a-z / 0-9 (puts target towards end of vector)
    */              
    char dict[] = "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz"; //Forward
    //char dict[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    //                "abcdefghijklmnopqrstuvwxyz"
    //                "0123456789"; //Reverse
    
    //Property variables.
    int decryptedtext_len, ciphertext_len, dict_len;
    size_t cipher_len;

    //Variable for unsalted ciphertext, and the extracted salt.
    unsigned char* ciphertext;
    unsigned char salt[8];
    
    //Load libcrypto error strings.
    ERR_load_crypto_strings();
    
    //Decode from base64 "main.c -> b64.c -> main.c"
    Base64Decode(ciphertext_base64, &ciphertext, &cipher_len);

    //Initialise Key and IV.
    unsigned char key[16];
    unsigned char iv[16];

    //Define password length.    
    unsigned char plainpassword[] = "00000";
    unsigned char* password = &plainpassword[0];
    int password_length = 3;

    //Remove the salt from the decoded ciphertext.
    if (strncmp((const char*)ciphertext,"Salted__",8) == 0) {
        memcpy(salt,&ciphertext[8],8);
        ciphertext += 16;
        cipher_len -= 16;
    }

    //define dictionary length for loops.
    dict_len = strlen(dict);
    
    //Initialise OpenMPI process, get assigned rank in default communication channel.
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &myrank);

    //Post recieves, fufilled by process that finds target.
    MPI_Irecv(&rbuf, count, MPI_INT, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &req);

    //Four for loops, determine value of password characters position, 1,2,3,4
    for(int j=0; j<dict_len; j++){
        for(int k=0; k<dict_len; k++){
            for(int l=0; l<dict_len; l++){
                for(int m=0; m<dict_len; m++){

                    //check if another process has broadcasted that it has found the target.
                    MPI_Test(&req, &flag, &status);
                    if(flag == 1){
                        printf("Another process has found the key, exiting...\n");
                        MPI_Finalize();
                    }
                    
                    //Password character at postion 0 determined by rank.
                    *password = dict[myrank];
                    *(password+1) = dict[j];
                    *(password+2) = dict[k];
                    *(password+3) = dict[l];
                    *(password+4) = dict[m];

                    //Initialise and attempt AES decryption.
                    initAES(password, salt, key, iv);
                    unsigned char* result = decrypt(ciphertext, cipher_len, key, iv, &success);
                    
                    //test success value returned by the decrypt AES function.
                    if (success == 1){
                        //Compare decryption attempt and target plaintext (sometimes success value can return false positives).
                        if(checkPlaintext(plaintext, result)==0){

                            MPI_Bcast(&sbuf, count, MPI_INT, myrank, MPI_COMM_WORLD);
                            
                            //print results.
                            printf("%s\n%s", result, password);

                            //calculate time taken.
                            gettimeofday(&end1, NULL);
                            double timetaken = end1.tv_sec + end1.tv_usec / 1e6 - start1.tv_sec  - start1.tv_usec / 1e6;
                            printf("\nTime spent: %f\n", timetaken);
                            
                            /* 
                                MPI_Abort kills all processes related to the one that calls it
                                Its brutish and can cause data loss, but the process calling it in this case has already found the target.
                            */
                            MPI_Abort(MPI_COMM_WORLD, err);
                            exit(0);
                        }
                    }
                    //free result memeory (program previously seg faulted due to compounding memory usage).
                    free(result);     
                }
            }
        }
    }

            
    // Clean up
    EVP_cleanup();
    ERR_free_strings();
    MPI_Finalize();
}
