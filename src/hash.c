// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: hash.c
// Description: Implements file hash calculation and comparison using OpenSSL for MD5, SHA1, and SHA256.
//              Provides cryptographic hash functions for file integrity checking and change detection.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "hash.h"
#include "error.h"

// Computes the cryptographic hash of a file and retrieves its size and modification time.
int compute_file_hash(const char *path, char *hash, HashType hash_type, off_t *size, time_t *mtime) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Failed to open file %s", path);
        handle_error(msg, 1);
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Failed to stat file %s", path);
        handle_error(msg, 1);
        close(fd);
        return 1;
    }
    *size = st.st_size;
    *mtime = st.st_mtime;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        handle_error("Failed to create EVP_MD_CTX", 1);
        close(fd);
        return 1;
    }

    const EVP_MD *md;
    switch (hash_type) {
        case HASH_MD5:
            md = EVP_md5();
            break;
        case HASH_SHA1:
            md = EVP_sha1();
            break;
        case HASH_SHA256:
            md = EVP_sha256();
            break;
        default:
            handle_error("Unsupported hash type", 1);
            EVP_MD_CTX_free(mdctx);
            close(fd);
            return 1;
    }

    if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
        handle_error("Failed to initialize digest", 1);
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return 1;
    }

    unsigned char buffer[8192];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        if (!EVP_DigestUpdate(mdctx, buffer, bytes_read)) {
            handle_error("Failed to update digest", 1);
            EVP_MD_CTX_free(mdctx);
            close(fd);
            return 1;
        }
    }

    if (bytes_read < 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Error reading file %s", path);
        handle_error(msg, 1);
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return 1;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    if (!EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
        handle_error("Failed to finalize digest", 1);
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return 1;
    }

    for (unsigned int i = 0; i < digest_len; i++) {
        snprintf(hash + i * 2, MAX_HASH_LEN - i * 2, "%02x", digest[i]);
    }
    hash[digest_len * 2] = '\0';

    EVP_MD_CTX_free(mdctx);
    close(fd);
    return 0;
}

// Compares two hash strings for equality. Returns 0 if equal, nonzero otherwise.
int compare_hashes(const char *hash1, const char *hash2) {
    return strcmp(hash1, hash2);
}