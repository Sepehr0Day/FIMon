// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: db.c
// Description: Implements SQLite database operations for FIMon, including initialization, 
//              storing file metadata, comparing and logging changes, and creating database backups.

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "db.h"
#include "error.h"
#include "alert.h"
#include "types.h"

// Initializes the SQLite database, enables WAL mode, and creates the files table if it doesn't exist.
int init_database(const char *db_path, int verbose) {
    sqlite3 *db;
    char *err_msg = 0;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Cannot open database: %s", sqlite3_errmsg(db));
        handle_error(msg, verbose);
        sqlite3_close(db);
        return 1;
    }

    rc = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Failed to enable WAL mode: %s", err_msg);
        handle_error(msg, verbose);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    const char *sql = "CREATE TABLE IF NOT EXISTS files ("
                      "path TEXT PRIMARY KEY, "
                      "hash TEXT, "
                      "size INTEGER, "
                      "mtime INTEGER);";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "SQL error: %s", err_msg);
        handle_error(msg, verbose);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_close(db);
    return 0;
}

// Saves file metadata (path, hash, size, modification time) to the database.
int save_file_info(const char *db_path, const char *path, const char *hash, off_t size, time_t mtime, int verbose) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Cannot open database: %s", sqlite3_errmsg(db));
        handle_error(msg, verbose);
        sqlite3_close(db);
        return 1;
    }

    const char *sql = "INSERT OR REPLACE INTO files (path, hash, size, mtime) VALUES (?, ?, ?, ?);";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Failed to prepare statement: %s", sqlite3_errmsg(db));
        handle_error(msg, verbose);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, size);
    sqlite3_bind_int64(stmt, 4, mtime);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Failed to execute statement: %s", sqlite3_errmsg(db));
        handle_error(msg, verbose);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

// Compares file metadata with database records, logs changes, and updates the database if changes are detected.
int compare_and_log_changes(const char *db_path, const char *path, const char *new_hash, off_t new_size, time_t new_mtime, 
                           const char *log_path, const char *json_log_path, int verbose, const char *event_type) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Cannot open database: %s", sqlite3_errmsg(db));
        handle_error(msg, verbose);
        sqlite3_close(db);
        return 1;
    }

    const char *sql = "SELECT hash, size, mtime FROM files WHERE path = ?;";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Failed to prepare statement: %s", sqlite3_errmsg(db));
        handle_error(msg, verbose);
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
    int changes_detected = 0;
    char msg[256], details[1024];

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *old_hash = (const char *)sqlite3_column_text(stmt, 0);
        off_t old_size = sqlite3_column_int64(stmt, 1);
        time_t old_mtime = sqlite3_column_int64(stmt, 2);

        if (strcmp(old_hash, new_hash) != 0) {
            snprintf(msg, sizeof(msg), "%s for %s (hash changed)", event_type, path);
            snprintf(details, sizeof(details), "{\"old_hash\": \"%s\", \"new_hash\": \"%s\", \"size\": %ld, \"mtime\": %ld}", 
                     old_hash, new_hash, (long)new_size, (long)new_mtime);
            log_event(log_path, msg, verbose);
            log_event_json(json_log_path, event_type, path, details, verbose);
            changes_detected = 1;
        } else if (old_size != new_size) {
            snprintf(msg, sizeof(msg), "%s for %s (size changed)", event_type, path);
            snprintf(details, sizeof(details), "{\"hash\": \"%s\", \"old_size\": %ld, \"new_size\": %ld, \"mtime\": %ld}", 
                     new_hash, (long)old_size, (long)new_size, (long)new_mtime);
            log_event(log_path, msg, verbose);
            log_event_json(json_log_path, event_type, path, details, verbose);
            changes_detected = 1;
        } else if (old_mtime != new_mtime) {
            snprintf(msg, sizeof(msg), "%s for %s (mtime changed)", event_type, path);
            snprintf(details, sizeof(details), "{\"hash\": \"%s\", \"size\": %ld, \"old_mtime\": %ld, \"new_mtime\": %ld}", 
                     new_hash, (long)new_size, (long)old_mtime, (long)new_mtime);
            log_event(log_path, msg, verbose);
            log_event_json(json_log_path, event_type, path, details, verbose);
            changes_detected = 1;
        }
    }

    sqlite3_finalize(stmt);

    if (changes_detected) {
        const char *update_sql = "UPDATE files SET hash = ?, size = ?, mtime = ? WHERE path = ?;";
        rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, 0);
        if (rc != SQLITE_OK) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Failed to prepare update statement: %s", sqlite3_errmsg(db));
            handle_error(msg, verbose);
            sqlite3_close(db);
            return 1;
        }

        sqlite3_bind_text(stmt, 1, new_hash, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, new_size);
        sqlite3_bind_int64(stmt, 3, new_mtime);
        sqlite3_bind_text(stmt, 4, path, -1, SQLITE_STATIC);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Failed to execute update statement: %s", sqlite3_errmsg(db));
            handle_error(msg, verbose);
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 1;
        }

        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    return 0;
}

// Creates a snapshot backup of the SQLite database to the specified backup path.
int backup_database(const char *db_path, const char *backup_path, int verbose) {
    sqlite3 *db = NULL, *backup_db = NULL;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        handle_error("Cannot open main DB for backup", verbose);
        return 1;
    }
    rc = sqlite3_open(backup_path, &backup_db);
    if (rc != SQLITE_OK) {
        handle_error("Cannot open backup DB file", verbose);
        sqlite3_close(db);
        return 1;
    }
    sqlite3_backup *backup = sqlite3_backup_init(backup_db, "main", db, "main");
    if (!backup) {
        handle_error("Failed to init sqlite3_backup", verbose);
        sqlite3_close(db);
        sqlite3_close(backup_db);
        return 1;
    }
    rc = sqlite3_backup_step(backup, -1);
    sqlite3_backup_finish(backup);
    sqlite3_close(db);
    sqlite3_close(backup_db);
    if (rc != SQLITE_DONE) {
        handle_error("Failed to backup DB", verbose);
        return 1;
    }
    return 0;
}