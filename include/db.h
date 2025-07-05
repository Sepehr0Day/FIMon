// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.0 - Date: 05/07/2025
// License: CC BY-NC 4.0
// File: db.h
// Description: Declares functions for SQLite database operations, including initialization, file metadata storage, comparison, and backup.

#include <sqlite3.h>
#include "types.h"

#ifndef DB_H
#define DB_H

// Initializes the SQLite database and creates the files table if it doesn't exist.
int init_database(const char *db_path, int verbose);

// Saves file metadata (path, hash, size, mtime) to the database.
int save_file_info(const char *db_path, const char *path, const char *hash, off_t size, time_t mtime, int verbose);

// Loads file metadata from the database for comparison.
int load_file_info(const char *db_path, const char *path, char *hash, off_t *size, time_t *mtime, int verbose);

// Compares current file metadata with stored data, logs changes, and updates the database.
int compare_and_log_changes(const char *db_path, const char *path, const char *new_hash, off_t new_size, time_t new_mtime, 
                           const char *log_path, const char *json_log_path, int verbose, const char *event_type);

// Creates a snapshot backup of the SQLite database.
int backup_database(const char *db_path, const char *backup_path, int verbose);

#endif