// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: config.c
// Description: Loads and frees FIMon configuration.
//              Handles parsing of configuration files and memory management for configuration structures.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cJSON.h>
#include "config.h"
#include "error.h"

// Loads and parses the JSON configuration file into a Config structure.
int load_config(const char *config_path, Config *config, int verbose) {
    FILE *file = fopen(config_path, "r");
    if (!file) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Failed to open config file: %s", config_path);
        handle_error(msg, verbose);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *data = malloc(length + 1);
    if (!data) {
        fclose(file);
        handle_error("Memory allocation failed for config file", verbose);
        return -1;
    }
    if (fread(data, 1, length, file) != (size_t)length) {
        fclose(file);
        free(data);
        handle_error("Failed to read config file", verbose);
        return -1;
    }
    data[length] = '\0';
    fclose(file);

    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json) {
        handle_error("Failed to parse config JSON", verbose);
        return -1;
    }

    cJSON *dirs = cJSON_GetObjectItem(json, "directories");
    if (!dirs || !cJSON_IsArray(dirs)) {
        handle_error("Invalid or missing 'directories' in config", verbose);
        cJSON_Delete(json);
        return -1;
    }

    config->directory_count = cJSON_GetArraySize(dirs);
    if (config->directory_count <= 0) {
        handle_error("Empty directories array in config", verbose);
        cJSON_Delete(json);
        return -1;
    }

    config->directories = malloc(config->directory_count * sizeof(DirectoryConfig));
    if (!config->directories) {
        handle_error("Memory allocation failed for directories", verbose);
        cJSON_Delete(json);
        return -1;
    }

    for (int i = 0; i < config->directory_count; i++) {
        cJSON *dir = cJSON_GetArrayItem(dirs, i);
        cJSON *path = cJSON_GetObjectItem(dir, "path");
        cJSON *hash_type = cJSON_GetObjectItem(dir, "hash_type");
        cJSON *ignore_patterns = cJSON_GetObjectItem(dir, "ignore_patterns");
        cJSON *tags = cJSON_GetObjectItem(dir, "tags");

        if (!path || !hash_type || !cJSON_IsString(path) || !cJSON_IsString(hash_type) ||
            !path->valuestring || !hash_type->valuestring) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Invalid directory config at index %d: missing or invalid path or hash_type", i);
            handle_error(msg, verbose);
            free(config->directories);
            cJSON_Delete(json);
            return -1;
        }

        strncpy(config->directories[i].path, path->valuestring, PATH_BUFFER_SIZE - 1);
        config->directories[i].path[PATH_BUFFER_SIZE - 1] = '\0';

        if (strcmp(hash_type->valuestring, "md5") == 0) {
            config->directories[i].hash_type = HASH_MD5;
        } else if (strcmp(hash_type->valuestring, "sha1") == 0) {
            config->directories[i].hash_type = HASH_SHA1;
        } else if (strcmp(hash_type->valuestring, "sha256") == 0) {
            config->directories[i].hash_type = HASH_SHA256;
        } else {
            char msg[256];
            snprintf(msg, sizeof(msg), "Invalid hash type: %s", hash_type->valuestring);
            handle_error(msg, verbose);
            free(config->directories);
            cJSON_Delete(json);
            return -1;
        }

        config->directories[i].ignore_patterns.pattern_count = 0;
        config->directories[i].ignore_patterns.patterns = malloc(MAX_PATTERNS * sizeof(char *));
        if (!config->directories[i].ignore_patterns.patterns) {
            handle_error("Memory allocation failed for ignore patterns array", verbose);
            free(config->directories);
            cJSON_Delete(json);
            return -1;
        }
        memset(config->directories[i].ignore_patterns.patterns, 0, MAX_PATTERNS * sizeof(char *));
        if (ignore_patterns && cJSON_IsArray(ignore_patterns)) {
            config->directories[i].ignore_patterns.pattern_count = cJSON_GetArraySize(ignore_patterns);
            if (config->directories[i].ignore_patterns.pattern_count > MAX_PATTERNS) {
                handle_error("Too many ignore patterns", verbose);
                free(config->directories[i].ignore_patterns.patterns);
                free(config->directories);
                cJSON_Delete(json);
                return -1;
            }
            for (int j = 0; j < config->directories[i].ignore_patterns.pattern_count; j++) {
                cJSON *pattern = cJSON_GetArrayItem(ignore_patterns, j);
                if (cJSON_IsString(pattern) && pattern->valuestring) {
                    config->directories[i].ignore_patterns.patterns[j] = strdup(pattern->valuestring);
                    if (!config->directories[i].ignore_patterns.patterns[j]) {
                        handle_error("Memory allocation failed for ignore pattern", verbose);
                        for (int k = 0; k < j; k++) free(config->directories[i].ignore_patterns.patterns[k]);
                        free(config->directories[i].ignore_patterns.patterns);
                        free(config->directories);
                        cJSON_Delete(json);
                        return -1;
                    }
                } else {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "Invalid ignore pattern at index %d", j);
                    handle_error(msg, verbose);
                    for (int k = 0; k < j; k++) free(config->directories[i].ignore_patterns.patterns[k]);
                    free(config->directories[i].ignore_patterns.patterns);
                    free(config->directories);
                    cJSON_Delete(json);
                    return -1;
                }
            }
        }

        config->directories[i].tags.tag_count = 0;
        config->directories[i].tags.tags = malloc(MAX_TAGS * sizeof(char *));
        if (!config->directories[i].tags.tags) {
            handle_error("Memory allocation failed for tags array", verbose);
            for (int j = 0; j < config->directories[i].ignore_patterns.pattern_count; j++) {
                free(config->directories[i].ignore_patterns.patterns[j]);
            }
            free(config->directories[i].ignore_patterns.patterns);
            free(config->directories);
            cJSON_Delete(json);
            return -1;
        }
        memset(config->directories[i].tags.tags, 0, MAX_TAGS * sizeof(char *));
        if (tags && cJSON_IsArray(tags)) {
            config->directories[i].tags.tag_count = cJSON_GetArraySize(tags);
            if (config->directories[i].tags.tag_count > MAX_TAGS) {
                handle_error("Too many tags", verbose);
                for (int j = 0; j < config->directories[i].ignore_patterns.pattern_count; j++) {
                    free(config->directories[i].ignore_patterns.patterns[j]);
                }
                free(config->directories[i].ignore_patterns.patterns);
                free(config->directories[i].tags.tags);
                free(config->directories);
                cJSON_Delete(json);
                return -1;
            }
            for (int j = 0; j < config->directories[i].tags.tag_count; j++) {
                cJSON *tag = cJSON_GetArrayItem(tags, j);
                if (cJSON_IsString(tag) && tag->valuestring) {
                    config->directories[i].tags.tags[j] = strdup(tag->valuestring);
                    if (!config->directories[i].tags.tags[j]) {
                        handle_error("Memory allocation failed for tag", verbose);
                        for (int k = 0; k < j; k++) free(config->directories[i].tags.tags[k]);
                        for (int k = 0; k < config->directories[i].ignore_patterns.pattern_count; k++) {
                            free(config->directories[i].ignore_patterns.patterns[k]);
                        }
                        free(config->directories[i].ignore_patterns.patterns);
                        free(config->directories[i].tags.tags);
                        free(config->directories);
                        cJSON_Delete(json);
                        return -1;
                    }
                } else {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "Invalid tag at index %d", j);
                    handle_error(msg, verbose);
                    for (int k = 0; k < j; k++) free(config->directories[i].tags.tags[k]);
                    for (int k = 0; k < config->directories[i].ignore_patterns.pattern_count; k++) {
                        free(config->directories[i].ignore_patterns.patterns[k]);
                    }
                    free(config->directories[i].ignore_patterns.patterns);
                    free(config->directories[i].tags.tags);
                    free(config->directories);
                    cJSON_Delete(json);
                    return -1;
                }
            }
        }
    }

    cJSON *log_path = cJSON_GetObjectItem(json, "log_path");
    cJSON *json_log_path = cJSON_GetObjectItem(json, "json_log_path");
    cJSON *db_path = cJSON_GetObjectItem(json, "db_path");
    if (!log_path || !json_log_path || !db_path || !cJSON_IsString(log_path) || 
        !cJSON_IsString(json_log_path) || !cJSON_IsString(db_path) ||
        !log_path->valuestring || !json_log_path->valuestring || !db_path->valuestring ||
        strlen(log_path->valuestring) == 0 || strlen(json_log_path->valuestring) == 0 ||
        strlen(db_path->valuestring) == 0) {
        handle_error("Invalid or missing log_path, json_log_path, or db_path in config", verbose);
        for (int i = 0; i < config->directory_count; i++) {
            for (int j = 0; j < config->directories[i].ignore_patterns.pattern_count; j++) {
                free(config->directories[i].ignore_patterns.patterns[j]);
            }
            for (int j = 0; j < config->directories[i].tags.tag_count; j++) {
                free(config->directories[i].tags.tags[j]);
            }
            free(config->directories[i].ignore_patterns.patterns);
            free(config->directories[i].tags.tags);
        }
        free(config->directories);
        cJSON_Delete(json);
        return -1;
    }

    strncpy(config->log_path, log_path->valuestring, PATH_BUFFER_SIZE - 1);
    config->log_path[PATH_BUFFER_SIZE - 1] = '\0';
    strncpy(config->json_log_path, json_log_path->valuestring, PATH_BUFFER_SIZE - 1);
    config->json_log_path[PATH_BUFFER_SIZE - 1] = '\0';
    strncpy(config->db_path, db_path->valuestring, PATH_BUFFER_SIZE - 1);
    config->db_path[PATH_BUFFER_SIZE - 1] = '\0';

    // --- Notification config ---
    cJSON *notif_settings = cJSON_GetObjectItem(json, "notification_settings");
    NotificationConfig *nc = &config->notification_config;
    memset(nc, 0, sizeof(NotificationConfig));
    if (notif_settings && cJSON_IsObject(notif_settings)) {
        // Email
        cJSON *email = cJSON_GetObjectItem(notif_settings, "email");
        if (email && cJSON_IsObject(email)) {
            cJSON *enabled = cJSON_GetObjectItem(email, "enabled");
            nc->email_enabled = cJSON_IsTrue(enabled);

            cJSON *smtp = cJSON_GetObjectItem(email, "smtp");
            if (smtp && cJSON_IsObject(smtp)) {
                cJSON *host = cJSON_GetObjectItem(smtp, "host");
                cJSON *port = cJSON_GetObjectItem(smtp, "port");
                cJSON *username = cJSON_GetObjectItem(smtp, "username");
                cJSON *password = cJSON_GetObjectItem(smtp, "password");
                cJSON *use_tls = cJSON_GetObjectItem(smtp, "use_tls");
                nc->smtp_host = host && cJSON_IsString(host) ? strdup(host->valuestring) : NULL;
                nc->smtp_port = port && cJSON_IsNumber(port) ? port->valueint : 0;
                nc->username = username && cJSON_IsString(username) ? strdup(username->valuestring) : NULL;
                nc->password = password && cJSON_IsString(password) ? strdup(password->valuestring) : NULL;
                nc->smtp_use_tls = cJSON_IsTrue(use_tls);
            }
            cJSON *recipients = cJSON_GetObjectItem(email, "recipient");
            if (recipients && cJSON_IsArray(recipients)) {
                int count = cJSON_GetArraySize(recipients);
                nc->recipients = malloc(count * sizeof(char *));
                nc->recipient_count = count;
                for (int i = 0; i < count; ++i) {
                    cJSON *r = cJSON_GetArrayItem(recipients, i);
                    nc->recipients[i] = r && cJSON_IsString(r) ? strdup(r->valuestring) : NULL;
                }
            }
        }
        // Telegram
        cJSON *telegram = cJSON_GetObjectItem(notif_settings, "telegram");
        if (telegram && cJSON_IsObject(telegram)) {
            cJSON *enabled = cJSON_GetObjectItem(telegram, "enabled");
            nc->telegram_enabled = cJSON_IsTrue(enabled);

            cJSON *bot_token = cJSON_GetObjectItem(telegram, "bot_token");
            nc->telegram_bot_token = bot_token && cJSON_IsString(bot_token) ? strdup(bot_token->valuestring) : NULL;

            cJSON *chat_ids = cJSON_GetObjectItem(telegram, "chat_id");
            if (chat_ids && cJSON_IsArray(chat_ids)) {
                int count = cJSON_GetArraySize(chat_ids);
                nc->telegram_chat_ids = malloc(count * sizeof(char *));
                nc->telegram_chat_id_count = count;
                for (int i = 0; i < count; ++i) {
                    cJSON *cid = cJSON_GetArrayItem(chat_ids, i);
                    nc->telegram_chat_ids[i] = cid && cJSON_IsString(cid) ? strdup(cid->valuestring) : NULL;
                }
            }
            cJSON *ssl = cJSON_GetObjectItem(telegram, "SSL");
            nc->telegram_ssl_enabled = cJSON_IsTrue(ssl);

            cJSON *proxy = cJSON_GetObjectItem(telegram, "proxy");
            if (proxy && cJSON_IsObject(proxy)) {
                cJSON *penabled = cJSON_GetObjectItem(proxy, "enabled");
                cJSON *ptype = cJSON_GetObjectItem(proxy, "type");
                cJSON *phost = cJSON_GetObjectItem(proxy, "host");
                cJSON *pport = cJSON_GetObjectItem(proxy, "port");
                cJSON *puser = cJSON_GetObjectItem(proxy, "username");
                cJSON *ppass = cJSON_GetObjectItem(proxy, "password");
                nc->telegram_proxy_enabled = cJSON_IsTrue(penabled);
                nc->telegram_proxy_type = ptype && cJSON_IsString(ptype) ? strdup(ptype->valuestring) : NULL;
                nc->telegram_proxy_host = phost && cJSON_IsString(phost) ? strdup(phost->valuestring) : NULL;
                nc->telegram_proxy_port = pport && cJSON_IsNumber(pport) ? pport->valueint : 0;
                nc->telegram_proxy_username = puser && cJSON_IsString(puser) ? strdup(puser->valuestring) : NULL;
                nc->telegram_proxy_password = ppass && cJSON_IsString(ppass) ? strdup(ppass->valuestring) : NULL;
            }
        }
        // Webhook
        cJSON *webhook = cJSON_GetObjectItem(notif_settings, "webhook");
        if (webhook && cJSON_IsObject(webhook)) {
            cJSON *enabled = cJSON_GetObjectItem(webhook, "enabled");
            nc->webhook_enabled = cJSON_IsTrue(enabled);
            cJSON *url = cJSON_GetObjectItem(webhook, "url");
            nc->webhook_url = url && cJSON_IsString(url) ? strdup(url->valuestring) : NULL;
        }

        // General notification settings
        cJSON *min_interval = cJSON_GetObjectItem(notif_settings, "min_interval_sec");
        nc->min_interval_sec = min_interval && cJSON_IsNumber(min_interval) ? min_interval->valueint : 0;
        cJSON *min_events = cJSON_GetObjectItem(notif_settings, "min_events");
        nc->min_events = min_events && cJSON_IsNumber(min_events) ? min_events->valueint : 0;
        cJSON *queue_path = cJSON_GetObjectItem(notif_settings, "queue_path");
        nc->queue_path = queue_path && cJSON_IsString(queue_path) ? strdup(queue_path->valuestring) : NULL;
        cJSON *archive_path = cJSON_GetObjectItem(notif_settings, "archive_path");
        nc->archive_path = archive_path && cJSON_IsString(archive_path) ? strdup(archive_path->valuestring) : NULL;
    }
    cJSON *notification = cJSON_GetObjectItem(json, "notification");
    nc->notification_enabled = cJSON_IsTrue(notification);

    // --- Backup config ---
    cJSON *backup = cJSON_GetObjectItem(json, "backup");
    config->backup_config.backup_enabled = 0;
    config->backup_config.backup_interval_sec = 0;
    config->backup_config.backup_paths = NULL;
    config->backup_config.backup_path_count = 0;
    config->backup_config.backup_method = NULL;
    config->backup_config.backup_recipients = NULL;
    config->backup_config.backup_recipient_count = 0;
    if (backup && cJSON_IsObject(backup)) {
        cJSON *enabled = cJSON_GetObjectItem(backup, "enabled");
        config->backup_config.backup_enabled = cJSON_IsTrue(enabled);

        cJSON *interval = cJSON_GetObjectItem(backup, "interval_sec");
        config->backup_config.backup_interval_sec = interval && cJSON_IsNumber(interval) ? interval->valueint : 0;

        cJSON *paths = cJSON_GetObjectItem(backup, "paths");
        if (paths && cJSON_IsArray(paths)) {
            int count = cJSON_GetArraySize(paths);
            config->backup_config.backup_path_count = count;
            config->backup_config.backup_paths = malloc(count * sizeof(char *));
            for (int i = 0; i < count; ++i) {
                cJSON *p = cJSON_GetArrayItem(paths, i);
                config->backup_config.backup_paths[i] = p && cJSON_IsString(p) ? strdup(p->valuestring) : NULL;
            }
        }

        // Backup notification (email/telegram) recipients
        cJSON *backup_notif = cJSON_GetObjectItem(backup, "notification");
        int backup_email_count = 0;
        int backup_telegram_count = 0;
        char **backup_email_recipients = NULL;
        char **backup_telegram_chat_ids = NULL;
        int email_enabled = 0, telegram_enabled = 0;

        if (backup_notif && cJSON_IsObject(backup_notif)) {
            // Email
            cJSON *email = cJSON_GetObjectItem(backup_notif, "email");
            if (email && cJSON_IsObject(email)) {
                cJSON *email_enabled_json = cJSON_GetObjectItem(email, "enabled");
                email_enabled = cJSON_IsTrue(email_enabled_json);
                cJSON *recipients = cJSON_GetObjectItem(email, "recipients");
                if (recipients && cJSON_IsArray(recipients)) {
                    backup_email_count = cJSON_GetArraySize(recipients);
                    backup_email_recipients = malloc(backup_email_count * sizeof(char *));
                    for (int i = 0; i < backup_email_count; ++i) {
                        cJSON *r = cJSON_GetArrayItem(recipients, i);
                        backup_email_recipients[i] = r && cJSON_IsString(r) ? strdup(r->valuestring) : NULL;
                    }
                }
            }
            // Telegram
            cJSON *telegram = cJSON_GetObjectItem(backup_notif, "telegram");
            if (telegram && cJSON_IsObject(telegram)) {
                cJSON *telegram_enabled_json = cJSON_GetObjectItem(telegram, "enabled");
                telegram_enabled = cJSON_IsTrue(telegram_enabled_json);
                cJSON *chat_ids = cJSON_GetObjectItem(telegram, "chat_id");
                if (chat_ids && cJSON_IsArray(chat_ids)) {
                    backup_telegram_count = cJSON_GetArraySize(chat_ids);
                    backup_telegram_chat_ids = malloc(backup_telegram_count * sizeof(char *));
                    for (int i = 0; i < backup_telegram_count; ++i) {
                        cJSON *cid = cJSON_GetArrayItem(chat_ids, i);
                        backup_telegram_chat_ids[i] = cid && cJSON_IsString(cid) ? strdup(cid->valuestring) : NULL;
                    }
                }
            }
        }

        // Set backup method string: "email", "telegram", or "email,telegram"
        if (email_enabled && telegram_enabled) {
            config->backup_config.backup_method = strdup("email,telegram");
        } else if (email_enabled) {
            config->backup_config.backup_method = strdup("email");
        } else if (telegram_enabled) {
            config->backup_config.backup_method = strdup("telegram");
        } else {
            config->backup_config.backup_method = NULL;
        }

        // Set backup recipients for email (prefer backup-specific, fallback to main notification)
        if (backup_email_count > 0) {
            config->backup_config.backup_recipient_count = backup_email_count;
            config->backup_config.backup_recipients = backup_email_recipients;
        } else if (config->notification_config.recipient_count > 0) {
            config->backup_config.backup_recipient_count = config->notification_config.recipient_count;
            config->backup_config.backup_recipients = config->notification_config.recipients;
        }

        // Optionally, you can store backup_telegram_chat_ids in backup_config if you want to support telegram backup
        // For now, not used in perform_backup, but you can add if needed.
    }

    cJSON_Delete(json);
    return 0;
}

// Frees memory allocated for the Config structure, including directories, ignore patterns, tags, and notification settings.
void free_config(Config *config) {
    if (!config) return;

    for (int i = 0; i < config->directory_count; i++) {
        for (int j = 0; j < config->directories[i].ignore_patterns.pattern_count; j++) {
            free(config->directories[i].ignore_patterns.patterns[j]);
        }
        for (int j = 0; j < config->directories[i].tags.tag_count; j++) {
            free(config->directories[i].tags.tags[j]);
        }
        free(config->directories[i].ignore_patterns.patterns);
        free(config->directories[i].tags.tags);
    }
    free(config->directories);

    free(config->notification_config.smtp_host);
    free(config->notification_config.username);
    free(config->notification_config.password);
    if (config->notification_config.recipients) {
        for (int i = 0; i < config->notification_config.recipient_count; ++i) {
            free(config->notification_config.recipients[i]);
        }
        free(config->notification_config.recipients);
    }
    free(config->notification_config.queue_path);
    free(config->notification_config.archive_path);
    free(config->notification_config.telegram_bot_token);
    if (config->notification_config.telegram_chat_ids) {
        for (int i = 0; i < config->notification_config.telegram_chat_id_count; ++i) {
            free(config->notification_config.telegram_chat_ids[i]);
        }
        free(config->notification_config.telegram_chat_ids);
    }
    free(config->notification_config.telegram_proxy_type);
    free(config->notification_config.telegram_proxy_host);
    free(config->notification_config.telegram_proxy_username);
    free(config->notification_config.telegram_proxy_password);

    // Free Webhook
    free(config->notification_config.webhook_url);

    // Free backup config
    if (config->backup_config.backup_paths) {
        for (int i = 0; i < config->backup_config.backup_path_count; ++i) {
            free(config->backup_config.backup_paths[i]);
        }
        free(config->backup_config.backup_paths);
    }
    free(config->backup_config.backup_method);
    if (config->backup_config.backup_recipients && config->backup_config.backup_recipients != config->notification_config.recipients) {
        for (int i = 0; i < config->backup_config.backup_recipient_count; ++i) {
            free(config->backup_config.backup_recipients[i]);
        }
        free(config->backup_config.backup_recipients);
    }
    config->backup_config.backup_paths = NULL;
    config->backup_config.backup_path_count = 0;
    config->backup_config.backup_method = NULL;
    config->backup_config.backup_recipients = NULL;
    config->backup_config.backup_recipient_count = 0;

    config->directory_count = 0;
    config->directories = NULL;
    config->notification_config.smtp_host = NULL;
    config->notification_config.smtp_port = 0;
    config->notification_config.username = NULL;
    config->notification_config.password = NULL;
    config->notification_config.recipients = NULL;
    config->notification_config.recipient_count = 0;
    config->notification_config.telegram_bot_token = NULL;
    config->notification_config.telegram_chat_ids = NULL;
    config->notification_config.telegram_chat_id_count = 0;
    config->notification_config.min_interval_sec = 0;
    config->notification_config.min_events = 0;
    config->notification_config.queue_path = NULL;
    config->notification_config.archive_path = NULL;
    config->notification_config.telegram_enabled = 0;
    config->notification_config.email_enabled = 0;
    config->notification_config.notification_enabled = 0;
}