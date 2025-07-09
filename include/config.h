// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: config.h
// Description: Declares configuration structures and functions for FIMon.

#ifndef CONFIG_H
#define CONFIG_H

#include "types.h"

typedef struct {
    // Email
    int email_enabled;
    char *smtp_host;
    int smtp_port;
    char *username;
    char *password;
    int smtp_use_tls;
    char **recipients;
    int recipient_count;

    // Telegram
    int telegram_enabled;
    char *telegram_bot_token;
    char **telegram_chat_ids;
    int telegram_chat_id_count;

    // Telegram SSL
    int telegram_ssl_enabled;

    // Telegram proxy
    int telegram_proxy_enabled;
    char *telegram_proxy_type;   // "http", "socks4", "socks5"
    char *telegram_proxy_host;
    int telegram_proxy_port;
    char *telegram_proxy_username;
    char *telegram_proxy_password;

    // General notification settings
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