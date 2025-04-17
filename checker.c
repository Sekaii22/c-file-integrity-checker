#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#define BUFFER_LEN 1024
#define MAX_PATHS 1000
#define MD5_HEX_LEN 32 
#define MONITOR_FILE_PATH "monitor.txt"
#define HASH_STORE_FILE_PATH "hashes.txt"

/* BUILD COMMAND: gcc -fsanitize=address -o checker checker.c -lssl -lcrypto */

/* 
    Takes in a file path and string pointer, 
    calculate the hash of the file and store it in string pointer.
    Returns 0 if sucessful, return -1 otherwise.
*/
int calculateHash(char *filePath, char *output) {
    FILE *file = fopen(filePath, "r");
    char fBuffer[BUFFER_LEN];

    EVP_MD_CTX *ctxP = NULL;
    EVP_MD *md5P = NULL;
    unsigned char digestOutput[16];                // md5 output is 32 hex, 1 hex is 4 bits so total is 16 bytes
                                                   // unsigned is needed to use all 8 bits of char for storing 2 hex

    // create new context for digest operation
    ctxP = EVP_MD_CTX_new();
    if (!ctxP) {
        printf("Digest context is null\n");
        return -1;
    }

    // fetch the md5 algorithm implementation
    md5P = EVP_MD_fetch(NULL, "MD5", NULL);
    if (md5P == NULL) {
        printf("Fetching failed\n");
        return -1;
    }

    // initialize digest operation
    if (!EVP_DigestInit_ex(ctxP, md5P, NULL)) {
        printf("Error with initializing digest\n");
        return -1;
    }

    // reads from file and put into fBuffer
    while (fgets(fBuffer, BUFFER_LEN-1, file)) {
        // pass fBuffer to be digested
        if (!EVP_DigestUpdate(ctxP, fBuffer, strlen(fBuffer))) {
            printf("Error with digest update\n");
            return -1;
        }
    }

    // calculate the final digest
    if (!EVP_DigestFinal_ex(ctxP, digestOutput, NULL)) {
        printf("Error with calcualting digest\n");
        return -1;
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
    fclose(file);
    return 0;
}

/*
    Takes an array of char pointer,
    Read paths from monitor.txt and store in array of char pointer.
    Return number of paths.
*/
int getMonitoredPaths(char *monitoredFilePath, char *outputPaths[MAX_PATHS]) {
    FILE* pathsFileP = fopen(monitoredFilePath, "r");
    char pathBuffer[BUFFER_LEN];
    int count = 0;

    while(fgets(pathBuffer, BUFFER_LEN-1, pathsFileP)) {
        pathBuffer[strcspn(pathBuffer, "\n")] = 0;              // remove newline char from path read

        outputPaths[count] = malloc(strlen(pathBuffer) + 1);

        if (outputPaths[count] == NULL) {
            printf("Unable to allocate memory");
            return -1;
        }
        strcpy(outputPaths[count], pathBuffer);
        count++;
    }

    fclose(pathsFileP);
    return count;
}

/* 
    Read all paths in MONITOR_FILE_PATH,
    generate hash for each and store it HASH_STORE_FILE_PATH.
    Return 0 if successful, otherwise -1;
*/
int init() {
    char *monitoredPaths[MAX_PATHS];

    // read all paths
    int numOfPaths = getMonitoredPaths(MONITOR_FILE_PATH, monitoredPaths);
    if (numOfPaths < 0)
        return -1;

    // store all hashes here
    FILE *hashStoreFileP = fopen(HASH_STORE_FILE_PATH, "w");
    
    for (int i = 0; i < numOfPaths; i++) {
        char hash[MD5_HEX_LEN + 1] = {0};

        // calculate the hash for that file and store it in hash variable
        if (calculateHash(monitoredPaths[i], hash) != 0)
            return -1;

        // store hash and file path
        fputs(hash, hashStoreFileP);
        fprintf(hashStoreFileP, " %s\n", monitoredPaths[i]);
    }

    // free allocated memory
    for (int i = 0; i < numOfPaths; i++) {
        free(monitoredPaths[i]);
    }

    fclose(hashStoreFileP);
    return 0;
}

int main() {
    init();
    // char out[MD5_HEX_LEN + 1];
    // calculateHash("files_to_monitor/m2.txt", out);
    // printf("%s\n", out);
    
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