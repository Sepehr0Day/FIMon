// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: config.h
// Description: Declares configuration structures and functions for FIMon, including notification and backup settings.

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

    // Webhook
    int webhook_enabled;
    char *webhook_url;

    // General notification settings
    int min_interval_sec;
    int min_events;
    char *queue_path;
    char *archive_path;
    int notification_enabled;
} NotificationConfig;

typedef struct {
    int backup_enabled;
    int backup_interval_sec; // How often to backup (seconds)
    char **backup_paths;     // List of paths to backup (can default to monitored dirs)
    int backup_path_count;
    // backup_method can be "email", "telegram", or "email,telegram"
    char *backup_method;
    char **backup_recipients; // For email: addresses; for telegram: chat_ids
    int backup_recipient_count;
} BackupConfig;

typedef struct {
    DirectoryConfig *directories;
    int directory_count;
    char log_path[PATH_BUFFER_SIZE];
    char json_log_path[PATH_BUFFER_SIZE];
    char db_path[PATH_BUFFER_SIZE];
    NotificationConfig notification_config;
    BackupConfig backup_config; // <-- Add this line
} Config;

// Loads and parses the JSON configuration file into a Config structure.
int load_config(const char *config_path, Config *config, int verbose);

// Frees memory allocated for the Config structure, including directories and notification settings.
void free_config(Config *config);

#endif