// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: types.h
// Description: Defines types and structures for FIMon.

#ifndef TYPES_H
#define TYPES_H
#include <sys/types.h>
#include <time.h>

#define PATH_BUFFER_SIZE 4096
#define MAX_HASH_LEN 128
#define MAX_PATTERNS 100
#define MAX_TAGS 10
#define MAX_USERNAME_LEN 32
#define MAX_GROUPNAME_LEN 32

typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256
} HashType;

typedef struct {
    char path[PATH_BUFFER_SIZE];
    char hash[MAX_HASH_LEN];
    off_t size;
    time_t mtime;
    uid_t uid;
    gid_t gid;
    mode_t permissions;
    char user[MAX_USERNAME_LEN];
    char group[MAX_GROUPNAME_LEN];
    int via_ssh;
    HashType hash_type;
} FileInfo;

typedef struct {
    int pattern_count;
    char **patterns;
} IgnorePatterns;

typedef struct {
    int tag_count;
    char **tags;
} Tags;

typedef struct {
    char path[PATH_BUFFER_SIZE];
    HashType hash_type;
    IgnorePatterns ignore_patterns;
    Tags tags;
    FileInfo info;
} DirectoryConfig;

#endif