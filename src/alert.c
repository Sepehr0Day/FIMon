// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: alert.c
// Description: Handles event logging for FIMon, including plain text and JSON logs,
//              log rotation, digital signature for tamper detection, and appending
//              events to the notification queue. This file ensures all file system
//              events are logged securely and can be audited for integrity.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cJSON.h>
#include "alert.h"
#include "error.h"
#include <openssl/sha.h>
#include <sys/stat.h>

#define LOG_ROTATE_SIZE (1024 * 1024) // 1MB

// Rotates the log file if it exceeds the maximum allowed size.
static void rotate_log_if_needed(const char *log_path) {
    struct stat st;
    if (stat(log_path, &st) == 0 && st.st_size > LOG_ROTATE_SIZE) {
        char rotated[PATH_BUFFER_SIZE];
        snprintf(rotated, sizeof(rotated), "%s.%ld", log_path, time(NULL));
        rename(log_path, rotated);
    }
}

// Signs the log file with a SHA256 digital signature for tamper detection.
static void sign_log_file(const char *log_path) {
    FILE *f = fopen(log_path, "rb");
    if (!f) return;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    SHA256_Init(&sha256);
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        SHA256_Update(&sha256, buf, n);
    }
    fclose(f);
    SHA256_Final(hash, &sha256);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

    char sig_path[PATH_BUFFER_SIZE];
    snprintf(sig_path, sizeof(sig_path), "%s.sig", log_path);
    FILE *sig = fopen(sig_path, "w");
    if (sig) {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            fprintf(sig, "%02x", hash[i]);
        fprintf(sig, "\n");
        fclose(sig);
    }
}

// Logs a text-based event with a timestamp to a specified log file and prints to stdout if verbose mode is enabled.
void log_event(const char *log_path, const char *message, int verbose) {
    rotate_log_if_needed(log_path);
    FILE *log_file = fopen(log_path, "a");
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    if (log_file) {
        fprintf(log_file, "[%s] %s\n", timestamp, message);
        fclose(log_file);
        sign_log_file(log_path); // sign after each write
    }
    if (verbose) {
        char logline[4096];
        snprintf(logline, sizeof(logline), "[%s] %s\n", timestamp, message);
        // Just print directly, no color
        fputs(logline, stdout);
        fflush(stdout);
    }
}

// Logs a JSON-formatted event to a file, appends to a notification queue, and writes detailed logs to a fixed integrity log file.
void log_event_json(const char *json_log_path, const char *event_type, const char *path, const char *details, int verbose) {
    rotate_log_if_needed(json_log_path);
    cJSON *root = NULL;
    cJSON *events = NULL;

    FILE *log_file = fopen(json_log_path, "r");
    if (log_file) {
        fseek(log_file, 0, SEEK_END);
        long length = ftell(log_file);
        fseek(log_file, 0, SEEK_SET);
        if (length > 0) {
            char *data = malloc(length + 1);
            if (!data) {
                fclose(log_file);
                handle_error("Memory allocation failed for JSON log", verbose);
                return;
            }
            if (fread(data, 1, length, log_file) != (size_t)length) {
                fclose(log_file);
                free(data);
                handle_error("Failed to read JSON log file", verbose);
                return;
            }
            data[length] = '\0';
            root = cJSON_Parse(data);
            free(data);
            fclose(log_file);
        } else {
            fclose(log_file);
        }
    }

    if (!root) {
        root = cJSON_CreateObject();
        events = cJSON_CreateArray();
        cJSON_AddItemToObject(root, "events", events);
    } else {
        events = cJSON_GetObjectItem(root, "events");
        if (!events) {
            events = cJSON_CreateArray();
            cJSON_AddItemToObject(root, "events", events);
        }
    }

    cJSON *log_entry = cJSON_CreateObject();
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);
    cJSON_AddStringToObject(log_entry, "timestamp", timestamp);
    cJSON_AddStringToObject(log_entry, "event", event_type);
    cJSON_AddStringToObject(log_entry, "path", path);

    cJSON *details_obj = cJSON_Parse(details);
    if (!details_obj) {
        handle_error("Failed to parse details string for JSON log", verbose);
        cJSON_Delete(log_entry);
        cJSON_Delete(root);
        return;
    }
    cJSON_AddItemToObject(log_entry, "details", details_obj);
    cJSON_AddItemToArray(events, log_entry);

    log_file = fopen(json_log_path, "w");
    if (log_file) {
        char *formatted = cJSON_Print(root);
        fprintf(log_file, "%s", formatted);
        free(formatted);
        fclose(log_file);
        sign_log_file(json_log_path); // sign after each write
    } else {
        handle_error("Failed to write JSON log file", verbose);
    }

    char superlog[4096];
    snprintf(superlog, sizeof(superlog),
        "[%s] [EVENT] type=%s path=%s details=%s | JSON_LOG=%s | ",
        timestamp, event_type, path, details, json_log_path
    );
    const char *queue_path = getenv("FIM_QUEUE_PATH");
    if (queue_path && strlen(queue_path) > 0) {
        strncat(superlog, "[QUEUE_APPEND] ", sizeof(superlog) - strlen(superlog) - 1);
        strncat(superlog, queue_path, sizeof(superlog) - strlen(superlog) - 1);
    }
    FILE *logf = fopen("/home/sepehr/FIM/integrity.log", "a");
    if (logf) {
        fprintf(logf, "%s\n", superlog);
        fclose(logf);
    }
    FILE *mainlog = fopen("/home/sepehr/FIM/integrity.log", "a");
    if (mainlog) {
        fprintf(mainlog, "%s\n", superlog);
        fclose(mainlog);
    }
    if (verbose) {
        printf("%s\n", superlog);
    }

    cJSON_Delete(root);

    if (queue_path && strlen(queue_path) > 0) {
        FILE *queue_file = fopen(queue_path, "r+");
        cJSON *queue_root = NULL;
        cJSON *queue_events = NULL;
        if (!queue_file) {
            queue_file = fopen(queue_path, "w+");
            queue_root = cJSON_CreateObject();
            queue_events = cJSON_CreateArray();
            cJSON_AddItemToObject(queue_root, "events", queue_events);
        } else {
            fseek(queue_file, 0, SEEK_END);
            long qsize = ftell(queue_file);
            fseek(queue_file, 0, SEEK_SET);
            if (qsize > 0) {
                char *qdata = malloc(qsize + 1);
                if (qdata && fread(qdata, 1, qsize, queue_file) == (size_t)qsize) {
                    qdata[qsize] = '\0';
                    queue_root = cJSON_Parse(qdata);
                    free(qdata);
                }
            }
            if (!queue_root) {
                queue_root = cJSON_CreateObject();
            }
            queue_events = cJSON_GetObjectItem(queue_root, "events");
            if (!queue_events) {
                queue_events = cJSON_CreateArray();
                cJSON_AddItemToObject(queue_root, "events", queue_events);
            }
        }
        cJSON *queue_entry = cJSON_CreateObject();
        cJSON_AddStringToObject(queue_entry, "timestamp", timestamp);
        cJSON_AddStringToObject(queue_entry, "event", event_type);
        cJSON_AddStringToObject(queue_entry, "path", path);
        cJSON *details_obj2 = cJSON_Parse(details);
        if (details_obj2) {
            cJSON_AddItemToObject(queue_entry, "details", details_obj2);
        }
        cJSON_AddItemToArray(queue_events, queue_entry);
        fseek(queue_file, 0, SEEK_SET);
        char *queue_str = cJSON_Print(queue_root);
        if (queue_str) {
            fprintf(queue_file, "%s", queue_str);
            free(queue_str);
        }
        fflush(queue_file);
        fclose(queue_file);
        cJSON_Delete(queue_root);
    }
}