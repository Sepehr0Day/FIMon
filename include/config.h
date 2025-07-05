// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.0 - Date: 05/07/2025
// License: CC BY-NC 4.0
// File: config.h
// Description: Defines structures for configuration settings and declares functions for loading and freeing configuration data.

#ifndef CONFIG_H
#define CONFIG_H

#include "types.h"

typedef struct {
    char *smtp_host;
    int smtp_port;
    char *username;
    char *password;
    char *recipient;
    int min_interval_sec;
    int min_events;
    char *queue_path;
    char *archive_path;
    int notification_enabled;
} NotificationConfig;

typedef struct {
    DirectoryConfig *directories;
    int directory_count;
    char log_path[PATH_BUFFER_SIZE];
    char json_log_path[PATH_BUFFER_SIZE];
    char db_path[PATH_BUFFER_SIZE];
    NotificationConfig notification_config;
} Config;

// Loads and parses the JSON configuration file into a Config structure.
int load_config(const char *config_path, Config *config, int verbose);

// Frees memory allocated for the Config structure, including directories and notification settings.
void free_config(Config *config);

#endif