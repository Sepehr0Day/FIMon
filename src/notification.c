// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.0 - Date: 05/07/2025
// License: CC BY-NC 4.0
// File: notification.c
// Description: Handles email notifications and event archiving for FIMon. Sends HTML-formatted emails with event details and archives processed events in a JSON file.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <curl/curl.h>
#include <cJSON.h>
#include "config.h"
#include "monitor.h"
#include <sys/file.h>

#define MSG_BUFFER_SIZE 16384
#define MAX_EMAIL_BODY_SIZE 65536

// Callback function to read email body data for libcurl.
static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp) {
    FILE *stream = (FILE *)userp;
    return fread(ptr, size, nmemb, stream);
}

// Sends an email with the specified subject and HTML body using SMTP configuration.
int send_email(const NotificationConfig *config, const char *subject, const char *body) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    struct curl_slist *recipients = NULL;
    char smtp_url[256];
    snprintf(smtp_url, sizeof(smtp_url), "smtp://%s:%d", config->smtp_host, config->smtp_port);

    curl_easy_setopt(curl, CURLOPT_URL, smtp_url);
    curl_easy_setopt(curl, CURLOPT_USERNAME, config->username);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, config->password);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_LOGIN_OPTIONS, "AUTH=LOGIN");
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, config->username);
    recipients = curl_slist_append(recipients, config->recipient);
    if (!recipients) {
        curl_easy_cleanup(curl);
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    char email_body[MAX_EMAIL_BODY_SIZE];
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char date_str[128];
    strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S +0000", tm_info);

    snprintf(email_body, sizeof(email_body),
        "Date: %s\r\n"
        "To: %s\r\n"
        "From: \"FIMon Alert\" <%s>\r\n"
        "Subject: %s\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "\r\n"
        "%s\r\n",
        date_str,
        config->recipient,
        config->username,
        subject,
        body
    );

    FILE *email_file = fmemopen(email_body, strlen(email_body), "r");
    if (!email_file) {
        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_READDATA, email_file);
    CURLcode res = curl_easy_perform(curl);
    fclose(email_file);
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return -1;
    }
    return 0;
}

// Archives processed events to a JSON file for historical reference.
void archive_events(const char *archive_path, cJSON *events) {
    FILE *file = fopen(archive_path, "r+");
    cJSON *root = NULL;
    cJSON *archive_events = NULL;

    if (!file) {
        file = fopen(archive_path, "w");
        if (!file) {
            return;
        }
        root = cJSON_CreateObject();
        archive_events = cJSON_CreateArray();
        cJSON_AddItemToObject(root, "events", archive_events);
    } else {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        if (size == 0) {
            root = cJSON_CreateObject();
            archive_events = cJSON_CreateArray();
            cJSON_AddItemToObject(root, "events", archive_events);
        } else {
            fseek(file, 0, SEEK_SET);
            char *buffer = malloc(size + 1);
            if (!buffer) {
                fclose(file);
                return;
            }
            if (fread(buffer, 1, size, file) != (size_t)size) {
                free(buffer);
                fclose(file);
                return;
            }
            buffer[size] = '\0';
            root = cJSON_Parse(buffer);
            free(buffer);
            if (!root) {
                fclose(file);
                return;
            }
            archive_events = cJSON_GetObjectItem(root, "events");
            if (!archive_events) {
                archive_events = cJSON_CreateArray();
                cJSON_AddItemToObject(root, "events", archive_events);
            }
        }
    }

    cJSON *event;
    cJSON_ArrayForEach(event, events) {
        cJSON *event_copy = cJSON_Duplicate(event, 1);
        cJSON_AddItemToArray(archive_events, event_copy);
    }

    fseek(file, 0, SEEK_SET);
    char *json_str = cJSON_Print(root);
    if (json_str) {
        fprintf(file, "%s", json_str);
        free(json_str);
    }
    cJSON_Delete(root);
    fclose(file);
}

// Processes queued events, sends email notifications if conditions are met, and archives events.
void process_notifications(const Config *config) {
    if (!config->notification_config.notification_enabled) {
        return;
    }

    char lock_path[PATH_BUFFER_SIZE];
    snprintf(lock_path, sizeof(lock_path), "%s.lock", config->notification_config.queue_path);
    FILE *lock = fopen(lock_path, "w");
    if (!lock) {
        return;
    }
    if (flock(fileno(lock), LOCK_EX | LOCK_NB) != 0) {
        fclose(lock);
        return;
    }

    FILE *file = fopen(config->notification_config.queue_path, "r");
    if (!file) {
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        return;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    if (size == 0) {
        fclose(file);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        return;
    }
    fseek(file, 0, SEEK_SET);
    char *buffer = malloc(size + 1);
    if (!buffer) {
        fclose(file);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        return;
    }
    if (fread(buffer, 1, size, file) != (size_t)size) {
        free(buffer);
        fclose(file);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        return;
    }
    buffer[size] = '\0';
    fclose(file);

    cJSON *root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        return;
    }

    cJSON *events = cJSON_GetObjectItem(root, "events");
    if (!events) {
        cJSON_Delete(root);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        return;
    }

    int event_count = cJSON_GetArraySize(events);
    if (event_count < config->notification_config.min_events) {
        cJSON_Delete(root);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        return;
    }

    static time_t last_email_time = 0;
    time_t current_time = time(NULL);
    if (current_time - last_email_time < config->notification_config.min_interval_sec) {
        cJSON_Delete(root);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        return;
    }

    char body[MAX_EMAIL_BODY_SIZE];
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&current_time));

    snprintf(body, sizeof(body),
        "<!DOCTYPE html>"
        "<html><head>"
        "<meta charset=\"UTF-8\">"
        "<style>"
        "body { font-family: Arial, sans-serif; background: #f3f4f6; margin: 0; padding: 0; }"
        ".container { max-width: 700px; margin: 30px auto; background: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.05); overflow: hidden; }"
        ".header { background-color: #2563eb; color: white; padding: 20px 30px; font-size: 1.8em; font-weight: bold; }"
        ".section-title { font-size: 1.2em; font-weight: bold; color: #2563eb; margin: 24px 30px 10px 30px; }"
        ".summary-table, .event-table { margin: 0 30px 24px 30px; border-collapse: collapse; width: calc(100%% - 60px); }"
        ".summary-table td { padding: 8px 12px; font-size: 0.95em; }"
        ".event-table th, .event-table td { border: 1px solid #e5e7eb; padding: 10px 14px; font-size: 0.95em; text-align: left; }"
        ".event-table th { background-color: #eff6ff; color: #1d4ed8; font-weight: 600; }"
        ".event-table tr:nth-child(even) { background-color: #f9fafb; }"
        ".footer { font-size: 0.9em; color: #6b7280; margin: 0 30px 30px 30px; text-align: center; }"
        "</style></head><body>"
        "<div class='container'>"
        "<div class='header'>FIMon Alert</div>"
        "<div class='section-title'>Summary</div>"
        "<table class='summary-table'>"
        "<tr><td><strong>Time:</strong></td><td>%s</td></tr>"
        "<tr><td><strong>Event Count:</strong></td><td>%d</td></tr>"
        "</table>"
        "<div class='section-title'>Event List</div>"
        "<table class='event-table'>"
        "<tr><th>Type</th><th>Path</th></tr>",
        timestamp, event_count
    );

    cJSON *event;
    cJSON_ArrayForEach(event, events) {
        cJSON *event_type = cJSON_GetObjectItem(event, "event");
        cJSON *path = cJSON_GetObjectItem(event, "path");
        char row[1024];
        snprintf(row, sizeof(row),
            "<tr><td>%s</td><td>%s</td></tr>",
            event_type && cJSON_IsString(event_type) ? event_type->valuestring : "Unknown",
            path && cJSON_IsString(path) ? path->valuestring : "Unknown"
        );
        strncat(body, row, sizeof(body) - strlen(body) - 1);
    }

    strncat(body,
        "</table>"
        "<div class='footer'>This is an automated alert from your FIMon system.</div>"
        "</div></body></html>",
        sizeof(body) - strlen(body) - 1
    );

    char subject[256];
    snprintf(subject, sizeof(subject), "[FIMon Alert] %d new filesystem events detected", event_count);

    if (send_email(&config->notification_config, subject, body) == 0) {
        last_email_time = current_time;
        archive_events(config->notification_config.archive_path, events);
        file = fopen(config->notification_config.queue_path, "w");
        if (file) {
            cJSON *empty_root = cJSON_CreateObject();
            cJSON_AddItemToObject(empty_root, "events", cJSON_CreateArray());
            char *json_str = cJSON_Print(empty_root);
            if (json_str) {
                fprintf(file, "%s", json_str);
                free(json_str);
            }
            cJSON_Delete(empty_root);
            fclose(file);
        }
    }

    cJSON_Delete(root);
    flock(fileno(lock), LOCK_UN);
    fclose(lock);
}