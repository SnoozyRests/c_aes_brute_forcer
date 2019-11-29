/*
    Author: Jacob John Williams
    Program: AES128-cbc brute forcer using OpenMP.
    Credits: Dr Kun Wei - underlying base code.
    Notes: Coursework for the Parallel Computing masters module at UWE. UFCFFL-15-M.
*/
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <omp.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <time.h>
#include "../dependencies/b64.c"
#include "../dependencies/aes.c"

int success = 0;
void printTime(clock_t, clock_t);

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
    Inputs: N/A
    Outputs: return 0 - success value.
    Notes: N/A
*/
int main (void){
    //Time keeping variables.
    clock_t start = clock(), end;

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
    
    //OpenMP specific thread variables.
    omp_set_num_threads(5);
    int id;

    //OpenMP collapse nested loops into a parallel runtime.
    #pragma omp parallel for collapse(5)
    for(int i = 0; i < dict_len; i++){
        for(int j = 0; j < dict_len; j++){
            for(int k = 0; k < dict_len; k++){
                for(int l = 0; l < dict_len; l++){
                    for(int m = 0; m < dict_len; m++){

                        //generate password attempt based on the position of the for loops
                        *password = dict[i];
                        *(password+1) = dict[j];
                        *(password+2) = dict[k];
                        *(password+3) = dict[l];
                        *(password+4) = dict[m];
                        
                        //print attempt and attempting thread.
                        id = omp_get_thread_num();
                        printf("%s, (%d)\n", password, id);

                        //Initialise and attempt AES decryption.
                        initAES(password, salt, key, iv);
                        unsigned char* result = decrypt(ciphertext, cipher_len, key, iv, &success);
                        
                        //test success value returned by the decrypt AES function.
                        if (success == 1){
                            //Compare decryption attempt and target plaintext (sometimes success value can return false positives).
                            if(checkPlaintext(plaintext, result) == 0){
                                //print results.
                                printf("%s\n", password);
                                printf("%s\n", result);
                                end = clock();
                                printTime(start, end);
                                exit(0);
                            } else {
                                //reset success value in case of false positive.
                                success = 0;
                            }
                        }

                        //free result memeory (program previously seg faulted due to compounding memory usage).
                        free(result);

                    } //5th for "m"
                } //4th for "l"
            } //3rd for "k"
        } //2nd for "j"
    } //1st for "i"

    // Clean up
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

/*
    Function: printTime
    Operation: calculates and prints the time the algorithm has taken to crack the text.
    Inputs: clock_t start - initialised at the start of the main function.
            clock_t end - initialised before function call.
    Outputs: Commandline print of time taken in seconds.
    Notes: N/A
*/
void printTime(clock_t start, clock_t end){
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf("\nTime spent: %f\n", time_spent);
}

