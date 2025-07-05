// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.0 - Date: 05/07/2025
// License: CC BY-NC 4.0
// File: monitor.h
// Description: Declares functions for monitoring filesystem changes, including file details retrieval, directory scanning, and notification processing.

#ifndef MONITOR_H
#define MONITOR_H

#include "types.h"
#include "config.h"
#include "alert.h"

// Retrieves detailed metadata for a file, including hash, size, and permissions.
void get_file_details(const char *path, FileInfo *file);

// Checks if a file or directory should be ignored based on specified patterns.
int should_ignore(const char *path, const char *name, IgnorePatterns *ignore_patterns);

// Determines if a directory is non-critical based on its tags.
int is_non_critical(Tags *tags);

// Checks if a directory is configured for monitoring.
int is_configured_directory(const char *dir_path, DirectoryConfig *dirs, int dir_count);

// Adds a file to the tracking system, logging its details and updating the database.
void add_tracked_file(const char *dir_path, const char *file_name, HashType hash_type, 
                     const char *db_path, const char *log_path, const char *json_log_path, 
                     int verbose, const char *event_type, IgnorePatterns *ignore_patterns, Tags *tags);

// Adds a directory to the watch list for monitoring.
void add_watched_dir(const char *dir_path, HashType hash_type, int fd, 
                    const char *log_path, const char *json_log_path, int verbose, 
                    IgnorePatterns *ignore_patterns, Tags *tags, int is_temporary);

// Scans a directory for changes and processes its files.
void scan_directory(const char *dir_path, HashType hash_type, const char *db_path, 
                   const char *log_path, const char *json_log_path, int verbose, int fd, 
                   IgnorePatterns *ignore_patterns, Tags *tags, DirectoryConfig *dirs, int dir_count);

// Monitors configured directories for filesystem changes.
void monitor_files(Config *config, int verbose, int daemon_mode);

// Processes queued events and sends notifications if conditions are met.
void process_notifications(const Config *config);

#endif