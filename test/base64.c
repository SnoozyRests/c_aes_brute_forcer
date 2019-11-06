#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/*
    Name: base64Encode
    Operation: Encodes the passed char string to base 64.
    Inputs: -const unsigned char* buffer - containing the string to encode (*string).
            -size_t length - length of the string (strlen(string)).
            -char** b64text - Pointer to the output (char*).
    Outputs: -success value 0.
             -*b64text.
    Notes: No error catching.
*/
int base64Encode(const unsigned char* buffer, size_t length, char** b64text){
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = (*bufferPtr).data;

    return 0;
}

/*
    Name: calcDecodeLength
    Operation: Calculates the length and padding of the supplied base64 string.
    Inputs: -const char* b64input - the supplied base64 string.
    Outputs: The length of the string to decode (length * 3) / 4 - padding.
    Notes: No error handling.
*/
size_t calcDecodeLength(const char* b64input){
    size_t len = strlen(b64input), padding = 0;

    if(b64input[len-1] == '=' && b64input[len-2] == '='){
        padding = 2;
    }else if(b64input[len - 1] == '='){
        padding = 1;
    }

    return (len*3) / 4 - padding;
}

/*
    Name: base64Decode
    Operation: Decodes the supplied base64 string.
    Inputs: +char* b64message - the supplied base64 string. (char / char*)
            +unsigned char** buffer - the output buffer. (char*)
            +size_t* length - output buffer for the length of the decode string. (size_t)
    Outputs: -unsigned char** buffer - decoded output.
             -size_t* length - length of decoded output.
    Notes: No error handling.
*/
int base64Decode(char* b64message, unsigned char** buffer, size_t* length){
    BIO *bio, *b64;
    
    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *length = BIO_read(bio, *buffer, strlen(b64message));
    assert(*length == decodeLen);
    BIO_free_all(bio);

    return 0;
}