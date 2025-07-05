// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.0 - Date: 05/07/2025
// License: CC BY-NC 4.0
// File: main.c
// Description: Entry point of the FIMon application. Parses command-line arguments, validates configuration and log file permissions, initializes notification system, creates database backup, and starts filesystem monitoring.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include "config.h"
#include "monitor.h"
#include "error.h"
#include "db.h"

// Main function: Parses command-line arguments, performs initial setup, and initiates filesystem monitoring.
int main(int argc, char *argv[]) {
    const char *config_path = NULL;
    int verbose = 0;
    int daemon_mode = 0;

    if (argc == 1) {
        printf("Usage: %s --config <path> [--verbose] [--daemon]\n", argv[0]);
        printf("  --config <path>   Path to config file\n");
        printf("  --verbose         Enable verbose output\n");
        printf("  --daemon          Run as daemon\n");
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--daemon") == 0) {
            daemon_mode = 1;
        }
    }

    if (!config_path) {
        handle_error("Configuration file not specified. Use --config <path>", 1);
        return 1;
    }

    struct stat st;
    if (stat(config_path, &st) == 0) {
        if ((st.st_mode & 0077) != 0) {
            fprintf(stderr, "ERROR: Config file %s is world/group readable or writable! Please restrict permissions (chmod 600).\n", config_path);
            return 1;
        }
    }

    Config config = {0};
    if (load_config(config_path, &config, verbose) != 0) {
        return 1;
    }

    if (stat(config.log_path, &st) == 0 && (st.st_mode & 0077) != 0) {
        fprintf(stderr, "ERROR: Log file %s is world/group readable or writable! Please restrict permissions (chmod 600).\n", config.log_path);
        free_config(&config);
        return 1;
    }
    if (stat(config.json_log_path, &st) == 0 && (st.st_mode & 0077) != 0) {
        fprintf(stderr, "ERROR: JSON log file %s is world/group readable or writable! Please restrict permissions (chmod 600).\n", config.json_log_path);
        free_config(&config);
        return 1;
    }

    if (config.notification_config.notification_enabled) {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    char backup_path[PATH_BUFFER_SIZE];
    size_t db_path_len = strlen(config.db_path);
    size_t suffix_len = strlen(".bak");
    if (db_path_len + suffix_len >= PATH_BUFFER_SIZE) {
        fprintf(stderr, "ERROR: Backup path too long for buffer\n");
        free_config(&config);
        return 1;
    }
    snprintf(backup_path, sizeof(backup_path), "%s.bak", config.db_path);
    backup_database(config.db_path, backup_path, verbose);

    if (config.notification_config.notification_enabled && config.notification_config.queue_path) {
        setenv("FIM_QUEUE_PATH", config.notification_config.queue_path, 1);
    }
    monitor_files(&config, verbose, daemon_mode);

    if (config.notification_config.notification_enabled) {
        curl_global_cleanup();
    }

    free_config(&config);
    return 0;
}