// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: alert.c
// Description: Handles event logging for FIMon, including plain text and JSON logs, 
//              and appending events to the notification queue.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cJSON.h>
#include "alert.h"
#include "error.h"

// Log a text event.
// Writes a timestamped message to the specified log file and optionally prints to stdout if verbose.
void log_event(const char *log_path, const char *message, int verbose) {
    FILE *log_file = fopen(log_path, "a");
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    if (log_file) {
        fprintf(log_file, "[%s] %s\n", timestamp, message);
        fclose(log_file);
    }
    if (verbose) {
        char logline[4096];
        snprintf(logline, sizeof(logline), "[%s] %s\n", timestamp, message);
        // Just print directly, no color
        fputs(logline, stdout);
        fflush(stdout);
    }
}

// Log a JSON event.
// Appends a JSON-formatted event to the log file, updates the notification queue, and logs to integrity log.
void log_event_json(const char *json_log_path, const char *event_type, const char *path, const char *details, int verbose) {
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