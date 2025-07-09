// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: hash.h
// Description: Declares hash calculation and comparison functions.

#ifndef HASH_H
#define HASH_H

#include "types.h"

// Computes the cryptographic hash of a file and retrieves its size and modification time.
int compute_file_hash(const char *path, char *hash, HashType hash_type, off_t *size, time_t *mtime);

// Compares two hash strings for equality.
int compare_hashes(const char *hash1, const char *hash2);

#endif