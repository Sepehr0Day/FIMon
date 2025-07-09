// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: main.c
// Description: Main entry point for FIMon. Handles argument parsing, configuration loading, 
//              file permission checks, environment setup, and launches the monitoring process.

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

#ifdef __cplusplus
extern "C" {
#endif
void run_as_service(const char *config_path, int daemon_mode);
#ifdef __cplusplus
}
#endif

// Main function for FIMon. Parses arguments, loads config, checks permissions, and starts monitoring.
int main(int argc, char *argv[]) {
    const char *config_path = NULL;
    int verbose = 0;
    int daemon_mode = 0;
    int run_as_service_flag = 0;

    if (argc == 1) {
        printf("Usage: %s --config <path> [--verbose] [--daemon] [--run-as-service]\n", argv[0]);
        printf("  --config <path>       Path to config file\n");
        printf("  --verbose             Enable verbose output\n");
        printf("  --daemon              Run as daemon\n");
        printf("  --run-as-service      Install and start as a service\n");
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--daemon") == 0) {
            daemon_mode = 1;
        } else if (strcmp(argv[i], "--run-as-service") == 0) {
            run_as_service_flag = 1;
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

    // Ensure log, json log, and db files exist with secure permissions
    FILE *f;
    if (access(config.log_path, F_OK) != 0) {
        f = fopen(config.log_path, "a");
        if (f) {
            fclose(f);
            chmod(config.log_path, 0600);
        }
    }
    if (access(config.json_log_path, F_OK) != 0) {
        f = fopen(config.json_log_path, "a");
        if (f) {
            fclose(f);
            chmod(config.json_log_path, 0600);
        }
    }
    if (access(config.db_path, F_OK) != 0) {
        f = fopen(config.db_path, "a");
        if (f) {
            fclose(f);
            chmod(config.db_path, 0600);
        }
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

    if (config.notification_config.notification_enabled && config.notification_config.queue_path) {
        setenv("FIM_QUEUE_PATH", config.notification_config.queue_path, 1);
    }
    if (run_as_service_flag) {
        run_as_service(config_path, daemon_mode);
        return 0;
    }
    monitor_files(&config, verbose, daemon_mode);

    if (config.notification_config.notification_enabled) {
        curl_global_cleanup();
    }

    free_config(&config);
    return 0;
}