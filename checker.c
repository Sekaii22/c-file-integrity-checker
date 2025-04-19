#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>

#define BUFFER_LEN 1024
#define MAX_PATHS 1000
#define MD5_HEX_LEN 32 
#define MONITOR_FILE_PATH "monitor.txt"
#define HASH_STORE_FILE_PATH "hashes.txt"
#define LOG_FILE_PATH "checker.log"
#define MSG_LEN 300

/* 
    BUILD COMMAND: gcc -fsanitize=address -o checker checker.c -lssl -lcrypto
    RUN COMMAND: ./checker [1-option] 
*/

/*
    Logs message to a file and automatically move to next line.
*/
void logger(char *msg) {
    FILE *logP = fopen(LOG_FILE_PATH, "a");
    fprintf(logP, "%s\n", msg);
    fclose(logP);
}

/*
    Prints fail to read file message.
*/
void printFileFailRead(char *filePath) {
    printf("Fail to read: %s\n", filePath);
    printf("Abort execution...\n");

    // print to log
    char msg[MSG_LEN];
    sprintf(msg, "Fail to read: %s", filePath);
    logger(msg);
    logger("Abort execution...");
}

/* 
    Takes in a file path and string pointer, 
    calculate the hash of the file and store it in string pointer.
    Returns 0 if sucessful, return -1 otherwise.
*/
int calculateHash(char *filePath, char *output) {
    FILE *file = fopen(filePath, "r");
    if (file == NULL) {
        printFileFailRead(filePath);
        return -1;
    }

    char fBuffer[BUFFER_LEN];

    EVP_MD_CTX *ctxP = NULL;
    EVP_MD *md5P = NULL;
    unsigned char digestOutput[16];                // md5 output is 32 hex, 1 hex is 4 bits so total is 16 bytes needed,
                                                   // unsigned is needed to use all 8 bits of char for storing 2 hex.

    // create new context for digest operation
    ctxP = EVP_MD_CTX_new();
    if (!ctxP) {
        printf("Digest context is null\n");
        logger("Digest context is null");
        return -1;
    }

    // fetch the md5 algorithm implementation
    md5P = EVP_MD_fetch(NULL, "MD5", NULL);
    if (md5P == NULL) {
        printf("Fetching failed\n");
        logger("Fetching failed");
        return -1;
    }

    // initialize digest operation
    if (!EVP_DigestInit_ex(ctxP, md5P, NULL)) {
        printf("Error with initializing digest\n");
        logger("Error with initializing digest");
        return -1;
    }

    // reads from file and put into fBuffer
    while (fgets(fBuffer, BUFFER_LEN - 1, file)) {
        // pass fBuffer to be digested
        if (!EVP_DigestUpdate(ctxP, fBuffer, strlen(fBuffer))) {
            printf("Error with digest update\n");
            logger("Error with digest update");
            return -1;
        }
    }

    // calculate the final digest
    if (!EVP_DigestFinal_ex(ctxP, digestOutput, NULL)) {
        printf("Error with calculating final digest\n");
        logger("Error with calculating final digest");
        return -1;
    }

    // store hash hex string as literal in hashBuffer
    char hashBuffer[MD5_HEX_LEN + 1];       // 32 hex characters + null
    int len = 0;

    for (int i = 0; i < sizeof(digestOutput); i++) {
        // digestOutput[i] is a normal 8-bit char, format it as 2 hex char and store the literal
        // len is the address offset
        len += sprintf(hashBuffer + len, "%02x", digestOutput[i]);
    }
    strcpy(output, hashBuffer);

    // clean up all the resources
    EVP_MD_free(md5P);
    EVP_MD_CTX_free(ctxP);
    fclose(file);

    return 0;
}

/*
    Check if path given exists and is a file.
    Return 1 if true, otherwise 0.
*/
int isFile(const char *path) {
    // stat stores info about a path
    struct stat stats;
    int isPathExist;

    // fill stats with data about the path given
    // stat() returns 0 if successful
    isPathExist = stat(path, &stats);

    // S_ISREG returns non-zero if path is a regular file
    if (isPathExist == 0 && S_ISREG(stats.st_mode)) {
        return 1;
    }

    return 0;
}

/*
    Check if path given exists and is a directory.
    Return 1 if true, otherwise 0.
*/
int isDir(const char *path) {
    struct stat stats;
    int isPathExist;

    isPathExist = stat(path, &stats);

    // S_ISDIR returns non-zero if path is a dir
    if (isPathExist == 0 && S_ISDIR(stats.st_mode)) {
        return 1;
    }

    return 0;
}

/*
    comparison function for qsort, sort strings in ascending order.
    *a and *b are void pointers to values.
*/
int strCompare(const void *a, const void *b) {
    // void pointers need to first be casted
    // into a pointer to char array and then
    // dereferenced to get the value.
    return strcmp(*(const char **)a, *(const char **)b);
}

int calculateDirHash(char *dirPath, char *finalOutput) {
    struct dirent *dirEntry;
    DIR *dirP = opendir(dirPath);
    if (dirP == NULL){
        printf("%s cannot be opened\n", dirPath);

        char msg[300];
        sprintf(msg, "%s cannot be opened", dirPath);
        logger(msg);

        return -1;
    }

    int fileCount = 0;
    int dirCount = 0;

    // get file and dir count
    while (dirEntry = readdir(dirP)) {
        if (strcmp(dirEntry->d_name, ".") != 0 && strcmp(dirEntry->d_name, "..") != 0) {
            char newPath[300] = "";
            sprintf(newPath, "%s/%s", dirPath, dirEntry->d_name);
            //printf("Path detected: %s\n", newPath);

            if (isFile(newPath)) 
                fileCount++;
            else if (isDir(newPath))
                dirCount++;
        }
    }

    // printf("File Count: %d\n", fileCount);
    // printf("Dir Count: %d\n", dirCount);
    char *filePathArr[fileCount];
    char *dirPathArr[dirCount];
    int fileArrIndex = 0;
    int dirArrIndex = 0;
    
    rewinddir(dirP);

    // store file and dir path into respective arrays
    while (dirEntry = readdir(dirP)) {
        // ignore . and .. but allow hidden files
        if (strcmp(dirEntry->d_name, ".") != 0 && strcmp(dirEntry->d_name, "..") != 0) {
            char newPath[300] = "";
            sprintf(newPath, "%s/%s", dirPath, dirEntry->d_name);

            if (isFile(newPath)) {
                // store in file array
                filePathArr[fileArrIndex] = malloc(strlen(newPath) + 1);
                strcpy(filePathArr[fileArrIndex], newPath);

                fileArrIndex++;
            }
            else if (isDir(newPath)) {
                // store in dir array
                dirPathArr[dirArrIndex] = malloc(strlen(newPath) + 1);
                strcpy(dirPathArr[dirArrIndex], newPath);

                dirArrIndex++;
            }
        }
    }

    // sort file and dir array
    qsort(filePathArr, fileCount, sizeof(const char *), strCompare);
    qsort(dirPathArr, dirCount, sizeof(const char *), strCompare);

    // set up hashing
    EVP_MD_CTX *ctxP = NULL;
    EVP_MD *md5P = NULL;
    unsigned char digestOutput[16];

    // create new context, fetch md5 algo, initialize digest operation
    ctxP = EVP_MD_CTX_new();
    if (!ctxP) {
        printf("Digest context is null\n");
        logger("Digest context is null");
        return -1;
    }

    md5P = EVP_MD_fetch(NULL, "MD5", NULL);
    if (md5P == NULL) {
        printf("Fetching failed\n");
        logger("Fetching failed");
        return -1;
    }

    if (!EVP_DigestInit_ex(ctxP, md5P, NULL)) {
        printf("Error with initializing digest\n");
        logger("Error with initializing digest");
        return -1;
    }

    // for file in file array
    //      call calculateHash(file, output)
    //      call digestupdate with output
    for (int i = 0; i < fileCount; i++) {
        char intermediateHash[MD5_HEX_LEN + 1];

        // calculate hash for current file and put into intermediateHash
        calculateHash(filePathArr[i], intermediateHash);
        
        // use intermediate file hash for calculating final hash
        if (!EVP_DigestUpdate(ctxP, intermediateHash, strlen(intermediateHash))) {
            printf("Error with digest update\n");
            logger("Error with digest update");
            return -1;
        }
    }

    // for dir in dir array
    //      call calculateDirHash(dir, output)
    //      call digestupdate with output
    for (int i = 0; i < dirCount; i++) {
        char intermediateHash[MD5_HEX_LEN + 1];

        // calculate hash for dir and put into intermediateHash
        calculateDirHash(dirPathArr[i], intermediateHash);
        
        // use intermediate dir hash for calculating final hash
        if (!EVP_DigestUpdate(ctxP, intermediateHash, strlen(intermediateHash))) {
            printf("Error with digest update\n");
            logger("Error with digest update");
            return -1;
        }
    }
    
    // calculate final output digest
    if (!EVP_DigestFinal_ex(ctxP, digestOutput, NULL)) {
        printf("Error with calculating final digest\n");
        logger("Error with calculating final digest");
        return -1;
    }

    //store hash hex string as literal in hashBuffer and copy into finalOutput
    char hashBuffer[MD5_HEX_LEN + 1];
    int len = 0;

    for (int i = 0; i < sizeof(digestOutput); i++) {
        len += sprintf(hashBuffer + len, "%02x", digestOutput[i]);
    }
    strcpy(finalOutput, hashBuffer);

    // clean up all the resources
    for (int i = 0; i < fileCount; i++) {
        free(filePathArr[i]);
    }

    for (int i = 0; i < dirCount; i++) {
        free(dirPathArr[i]);
    }

    EVP_MD_free(md5P);
    EVP_MD_CTX_free(ctxP);
    closedir(dirP);

    return 0;
}

/*
    Takes an array of char pointer,
    Read paths from monitor.txt and store in array of char pointer.
    Return number of paths, if fail, return -1.
*/
int getMonitoredPaths(char *monitoredFilePath, char *outputPaths[MAX_PATHS]) {
    FILE* pathsFileP = fopen(monitoredFilePath, "r");
    if (pathsFileP == NULL) {
        printFileFailRead(monitoredFilePath);
        return -1;
    }

    char pathBuffer[BUFFER_LEN];
    int count = 0;

    while(fgets(pathBuffer, BUFFER_LEN - 1, pathsFileP)) {
        pathBuffer[strcspn(pathBuffer, "\n")] = 0;              // remove newline char from path read

        outputPaths[count] = malloc(strlen(pathBuffer) + 1);    // strlen dont count null terminating char

        if (outputPaths[count] == NULL) {
            printf("Unable to allocate memory\n");
            logger("Unable to allocate memory");
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
        char hash[MD5_HEX_LEN + 1];

        // calculate the hash for that file and store it in hash variable
        if (calculateHash(monitoredPaths[i], hash) != 0)
            return -1;

        // store hash and file path
        fprintf(hashStoreFileP, "%s %s\n", hash, monitoredPaths[i]);

        // log results
        char msg[MSG_LEN];
        sprintf(msg, "%s %s", hash, monitoredPaths[i]);
        logger(msg);
    }

    // free allocated memory
    for (int i = 0; i < numOfPaths; i++) {
        free(monitoredPaths[i]);
    }

    fclose(hashStoreFileP);
    return 0;
}

/*
    Compares old hash with new hash.
    Return 0 if successful, otherwise -1;
*/
int check() {
    FILE *hashStoreFileP = fopen(HASH_STORE_FILE_PATH, "r");
    if (hashStoreFileP == NULL) {
        printFileFailRead(HASH_STORE_FILE_PATH);
        return -1;
    }
    
    char fBuffer[BUFFER_LEN];

    while(fgets(fBuffer, BUFFER_LEN - 1, hashStoreFileP)) {
        // get old hash
        fBuffer[strcspn(fBuffer, "\n")] = 0;              // remove newline char from line read
        char *oldHash = strtok(fBuffer, " ");
        char *filePath = strtok(NULL, " ");               // filepath associated with the old hash

        // generate new hash
        char newHash[MD5_HEX_LEN + 1];
        if (calculateHash(filePath, newHash) != 0)
            return -1;

        // compare
        if (strncmp(oldHash, newHash, MD5_HEX_LEN) != 0) {
            // changes in hash detected
            // red color text
            printf("\033[1;31m");
            printf("%s has changed!\n", filePath);
            printf("\033[0m");
            printf("Previous hash:\t %s\n", oldHash);
            printf("Current hash:\t %s\n\n", newHash);

            // log diff
            char msg[MSG_LEN];
            sprintf(msg, "%s has changed!", filePath);
            logger(msg);
            sprintf(msg, "Previous hash:\t %s", oldHash);
            logger(msg);
            sprintf(msg, "Current hash:\t %s", newHash);
            logger(msg);
        }
    }

    fclose(hashStoreFileP);
    return 0;
}

void printHelp() {
    printf("****************************************\n");
    printf("*                                      *\n");
    printf("*        File Integrity Checker        *\n");
    printf("*                                      *\n");
    printf("****************************************\n");
    printf("\n");
    printf("./checker [option]\n");
    printf("   Checks the integrity of files by comparing baseline hashes with current hashes.\n");
    printf("\n");
    printf("   Options:\n");
    printf("    -h, --help\t  Prints help information.\n");
    printf("    -i, --init\t  Establish bashline hashes from files specified in %s.\n", MONITOR_FILE_PATH);
    printf("    -c, --check\t  Check bashline hashes against current hashes.\n");
}

int main(int argc, char *argv[]) {
    
    // no args given
    if (argc <= 1) {
        char temp[MD5_HEX_LEN + 1];
        calculateDirHash("files_to_monitor", temp);
        printf("Final hash: %s\n", temp);

        printf("No arguments given. Use -h or --help for more information.\n");
        logger("No arguments given.");
        return 0;
    }

    // check for invalid options
    if (strcmp(argv[1], "--help") != 0 && strcmp(argv[1], "-h") != 0 &&
            strcmp(argv[1], "--init") != 0 && strcmp(argv[1], "-i") != 0 &&
            strcmp(argv[1], "--check") != 0 && strcmp(argv[1], "-c") != 0) {

            printf("Unrecognized command-line option %s. Use -h or --help for more information.\n", argv[1]);
            return 0;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        printHelp();
        return 0;
    }
    else if (strcmp(argv[1], "--init") == 0 || strcmp(argv[1], "-i") == 0)
    {
        logger("Start initialization");
        if (init() != 0) {
            // red color text
            printf("\033[1;31m");
            printf("Initiation terminated\n");
            printf("\033[0m");

            logger("Initiation terminated\n");
            return 1;
        }

        printf("Initialization completed\n");
        logger("Initialization completed\n");
    }
    else if (strcmp(argv[1], "--check") == 0 || strcmp(argv[1], "-c") == 0)
    {
        logger("Start integrity check");
        if (check() != 0) {
            // red color text
            printf("\033[1;31m");
            printf("Integrity check terminated\n");
            printf("\033[0m");

            logger("Integrity check terminated\n");
            return 1;
        }

        printf("Check completed\n");
        logger("Check completed\n");
    }

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