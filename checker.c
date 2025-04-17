#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#define BUFFER_LEN 1024
#define MD5_HEX_LEN 32 

/* 
    Takes in a file and string pointer, 
    calculate the hash of the file and store it in string pointer.
    Returns 0 if sucessful, return 1 otherwise.
*/
int calculateHash(FILE *file, char *output) {
    char fBuffer[BUFFER_LEN];
    EVP_MD_CTX *ctxP = NULL;
    EVP_MD *md5P = NULL;
    unsigned char digestOutput[16];                // md5 output is 32 hex, 1 hex is 4 bits so total is 16 bytes
                                                   // unsigned is needed to use all 8 bits of char for storing 2 hex

    // create new context for digest operation
    ctxP = EVP_MD_CTX_new();
    if (!ctxP) {
        printf("Digest context is null\n");
        return 1;
    }

    // fetch the md5 algorithm implementation
    md5P = EVP_MD_fetch(NULL, "MD5", NULL);
    if (md5P == NULL) {
        printf("Fetching failed\n");
        return 1;
    }

    // initialize digest operation
    if (!EVP_DigestInit_ex(ctxP, md5P, NULL)) {
        printf("Error with initializing digest\n");
        return 1;
    }

    // reads from file and put into fBuffer
    while (fgets(fBuffer, BUFFER_LEN-1, file)) {
        // pass fBuffer to be digested
        if (!EVP_DigestUpdate(ctxP, fBuffer, strlen(fBuffer))) {
            printf("Error with digest update\n");
            return 1;
        }
    }

    // calculate the final digest
    if (!EVP_DigestFinal_ex(ctxP, digestOutput, NULL)) {
        printf("Error with calcualting digest\n");
        return 1;
    }

    // store hash hex string as literal in hashBuffer
    char hashBuffer[MD5_HEX_LEN + 1];       // 32 hex characters + null
    int len = 0;

    for (int i = 0; i < 16; i++) {
        // digestOutput[i] is a normal 8-bit char, format it as 2 hex char and store the literal
        // len is the address offset
        len += sprintf(hashBuffer + len, "%02x", digestOutput[i]);
    }

    // clean up all the resources
    EVP_MD_free(md5P);
    EVP_MD_CTX_free(ctxP);

    strcpy(output, hashBuffer);
    return 0;
}

int main() {
    FILE *fileP = fopen("files_to_monitor/m1.txt", "r");
    char hash[MD5_HEX_LEN + 1];
    
    if (calculateHash(fileP, hash) != 0) {
        return 1;
    }
    //free(hash);

    printf("%s\n", hash);
    
    
    // // print out hash hex string
    // for (int i = 0; i < 16; i++) {
    //     printf("%02x", digestOutput[i]);
    // }
    // printf("\n");

    // // store hashs
    // FILE *fileP = fopen("hashes.txt", "w");
    // for (int i = 0; i < 16; i++)
    //     fprintf(fileP, "%02x", digestOutput[i]);
    // fprintf(fileP, " %s", "some_path.txt");

    // // or
    // fputs(hashBuffer, fileP);
    // fprintf(fileP, " %s", "some_path.txt");
    // fclose(fileP);

    return 0;
}