// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.0 - Date: 05/07/2025
// License: CC BY-NC 4.0
// File: config.c
// Description: Handles loading and parsing of JSON configuration file for FIMon, including directory settings, hash types, ignore patterns, tags, and notification settings. Also manages memory cleanup.

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

    cJSON *notification = cJSON_GetObjectItem(json, "notification");
    config->notification_config.notification_enabled = cJSON_IsTrue(notification);
    if (config->notification_config.notification_enabled) {
        cJSON *smtp = cJSON_GetObjectItem(json, "smtp");
        cJSON *recipient = cJSON_GetObjectItem(json, "recipient");
        cJSON *min_interval_sec = cJSON_GetObjectItem(json, "min_interval_sec");
        cJSON *min_events = cJSON_GetObjectItem(json, "min_events");
        cJSON *queue_path = cJSON_GetObjectItem(json, "queue_path");
        cJSON *archive_path = cJSON_GetObjectItem(json, "archive_path");

        if (!smtp || !recipient || !min_interval_sec || !min_events || !queue_path || !archive_path ||
            !cJSON_IsObject(smtp) || !cJSON_IsString(recipient) || !cJSON_IsNumber(min_interval_sec) ||
            !cJSON_IsNumber(min_events) || !cJSON_IsString(queue_path) || !cJSON_IsString(archive_path) ||
            !recipient->valuestring || !queue_path->valuestring || !archive_path->valuestring ||
            strlen(recipient->valuestring) == 0 || strlen(queue_path->valuestring) == 0 ||
            strlen(archive_path->valuestring) == 0) {
            handle_error("Invalid or missing notification config", verbose);
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

        cJSON *smtp_host = cJSON_GetObjectItem(smtp, "host");
        cJSON *smtp_port = cJSON_GetObjectItem(smtp, "port");
        cJSON *username = cJSON_GetObjectItem(smtp, "username");
        cJSON *password = cJSON_GetObjectItem(smtp, "password");

        if (!smtp_host || !smtp_port || !username || !password ||
            !cJSON_IsString(smtp_host) || !cJSON_IsNumber(smtp_port) ||
            !cJSON_IsString(username) || !cJSON_IsString(password) ||
            !smtp_host->valuestring || !username->valuestring || !password->valuestring ||
            strlen(smtp_host->valuestring) == 0 || strlen(username->valuestring) == 0 ||
            strlen(password->valuestring) == 0) {
            handle_error("Invalid or missing SMTP config", verbose);
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

        config->notification_config.smtp_host = strdup(smtp_host->valuestring);
        config->notification_config.smtp_port = smtp_port->valueint;
        config->notification_config.username = strdup(username->valuestring);
        config->notification_config.password = strdup(password->valuestring);
        config->notification_config.recipient = strdup(recipient->valuestring);
        config->notification_config.min_interval_sec = min_interval_sec->valueint;
        config->notification_config.min_events = min_events->valueint;
        config->notification_config.queue_path = strdup(queue_path->valuestring);
        config->notification_config.archive_path = strdup(archive_path->valuestring);

        if (!config->notification_config.smtp_host || !config->notification_config.username ||
            !config->notification_config.password || !config->notification_config.recipient ||
            !config->notification_config.queue_path || !config->notification_config.archive_path) {
            handle_error("Memory allocation failed for notification config strings", verbose);
            free(config->notification_config.smtp_host);
            free(config->notification_config.username);
            free(config->notification_config.password);
            free(config->notification_config.recipient);
            free(config->notification_config.queue_path);
            free(config->notification_config.archive_path);
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
    } else {
        config->notification_config.smtp_host = NULL;
        config->notification_config.smtp_port = 0;
        config->notification_config.username = NULL;
        config->notification_config.password = NULL;
        config->notification_config.recipient = NULL;
        config->notification_config.min_interval_sec = 0;
        config->notification_config.min_events = 0;
        config->notification_config.queue_path = NULL;
        config->notification_config.archive_path = NULL;
        config->notification_config.notification_enabled = 0;
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
    free(config->notification_config.recipient);
    free(config->notification_config.queue_path);
    free(config->notification_config.archive_path);

    config->directory_count = 0;
    config->directories = NULL;
    config->notification_config.smtp_host = NULL;
    config->notification_config.smtp_port = 0;
    config->notification_config.username = NULL;
    config->notification_config.password = NULL;
    config->notification_config.recipient = NULL;
    config->notification_config.min_interval_sec = 0;
    config->notification_config.min_events = 0;
    config->notification_config.queue_path = NULL;
    config->notification_config.archive_path = NULL;
    config->notification_config.notification_enabled = 0;
}