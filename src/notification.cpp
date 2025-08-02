// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: notification.cpp
// Description: Handles notifications and event archiving for FIMon, including sending email and Telegram alerts, 
//              archiving processed events, and processing notification queues.

#ifndef MAX_EMAIL_BODY_SIZE
#define MAX_EMAIL_BODY_SIZE 65536
#endif

#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <curl/curl.h>
#include <cJSON.h>
#include <sys/file.h>
#include "types.h"
#include "config.h"
#include "monitor.h"

class Notifier {
public:
    Notifier(const NotificationConfig *config);
    int send_email(const char *subject, const char *body);
    int send_telegram(const char *message);
    void archive_events(const char *archive_path, cJSON *events);
    void process_notifications(const Config *config);
    int send_file(const char *subject, const char *body_html, const char *filepath);
    int send_webhook(const char *message);    // <-- only webhook
private:
    const NotificationConfig *config_;
    static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp);
};

size_t Notifier::read_callback(void *ptr, size_t size, size_t nmemb, void *userp) {
    FILE *stream = (FILE *)userp;
    return fread(ptr, size, nmemb, stream);
}

Notifier::Notifier(const NotificationConfig *config) : config_(config) {}

int Notifier::send_email(const char *subject, const char *body) {
    if (!config_->email_enabled || !config_->smtp_host || !config_->username || !config_->password || !config_->recipients || config_->recipient_count == 0)
        return -1;

    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize curl for email" << std::endl;
        return -1;
    }

    struct curl_slist *recipients = NULL;
    char smtp_url[256];
    snprintf(smtp_url, sizeof(smtp_url), "smtp://%s:%d", config_->smtp_host, config_->smtp_port);

    curl_easy_setopt(curl, CURLOPT_URL, smtp_url);
    curl_easy_setopt(curl, CURLOPT_USERNAME, config_->username);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, config_->password);

    if (config_->smtp_use_tls)
        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    else
        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_LOGIN_OPTIONS, "AUTH=LOGIN");
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, config_->username);

    for (int i = 0; i < config_->recipient_count; ++i) {
        if (config_->recipients[i])
            recipients = curl_slist_append(recipients, config_->recipients[i]);
    }
    if (!recipients) {
        curl_easy_cleanup(curl);
        std::cerr << "No valid email recipients" << std::endl;
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
        config_->recipients[0],
        config_->username,
        subject,
        body
    );

    FILE *email_file = fmemopen(email_body, strlen(email_body), "r");
    if (!email_file) {
        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
        std::cerr << "Failed to create email file stream" << std::endl;
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_READDATA, email_file);
    CURLcode res = curl_easy_perform(curl);
    fclose(email_file);
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "Email send failed: " << curl_easy_strerror(res) << std::endl;
        return -1;
    }
    std::cout << "Email sent successfully" << std::endl;
    return 0;
}

int Notifier::send_telegram(const char *message) {
    if (!config_->telegram_enabled || !config_->telegram_bot_token || !config_->telegram_chat_ids || config_->telegram_chat_id_count == 0)
        return -1;

    int success = 0;
    for (int i = 0; i < config_->telegram_chat_id_count; ++i) {
        CURL *curl = curl_easy_init();
        if (!curl) {
            std::cerr << "Failed to initialize curl for Telegram chat_id " << config_->telegram_chat_ids[i] << std::endl;
            continue;
        }
        char url[1024];
        snprintf(url, sizeof(url),
            "https://api.telegram.org/bot%s/sendMessage",
            config_->telegram_bot_token);
        cJSON *payload = cJSON_CreateObject();
        cJSON_AddStringToObject(payload, "chat_id", config_->telegram_chat_ids[i]);
        cJSON_AddStringToObject(payload, "text", message);
        cJSON_AddBoolToObject(payload, "disable_web_page_preview", 1);
        char *json = cJSON_PrintUnformatted(payload);
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        if (config_->telegram_proxy_enabled && config_->telegram_proxy_type && config_->telegram_proxy_host && config_->telegram_proxy_port > 0) {
            char proxy_url[256];
            snprintf(proxy_url, sizeof(proxy_url), "%s://%s:%d",
                strcmp(config_->telegram_proxy_type, "http") == 0 ? "http" :
                strcmp(config_->telegram_proxy_type, "socks4") == 0 ? "socks4" :
                strcmp(config_->telegram_proxy_type, "socks5") == 0 ? "socks5h" : "http",
                config_->telegram_proxy_host,
                config_->telegram_proxy_port
            );
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url);

            if (config_->telegram_proxy_username && strlen(config_->telegram_proxy_username) > 0) {
                curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, config_->telegram_proxy_username);
            }
            if (config_->telegram_proxy_password && strlen(config_->telegram_proxy_password) > 0) {
                curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, config_->telegram_proxy_password);
            }
        }

        if (config_->telegram_ssl_enabled) {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        } else {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        }

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            std::cout << "Telegram message sent successfully to chat_id " << config_->telegram_chat_ids[i] << std::endl;
            success = 1;
        } else {
            std::cerr << "Telegram send failed for chat_id " << config_->telegram_chat_ids[i] << ": " << curl_easy_strerror(res) << std::endl;
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        cJSON_Delete(payload);
        free(json);
    }
    return success ? 0 : -1;
}

void Notifier::archive_events(const char *archive_path, cJSON *events) {
    FILE *file = fopen(archive_path, "r+");
    cJSON *root = NULL;
    cJSON *archive_events = NULL;

    if (!file) {
        file = fopen(archive_path, "w");
        if (!file) {
            std::cerr << "Failed to open archive file: " << archive_path << std::endl;
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
            char *buffer = (char *)malloc(size + 1);
            if (!buffer) {
                fclose(file);
                std::cerr << "Failed to allocate buffer for archive file" << std::endl;
                return;
            }
            if (fread(buffer, 1, size, file) != (size_t)size) {
                free(buffer);
                fclose(file);
                std::cerr << "Failed to read archive file" << std::endl;
                return;
            }
            buffer[size] = '\0';
            root = cJSON_Parse(buffer);
            free(buffer);
            if (!root) {
                fclose(file);
                std::cerr << "Failed to parse archive JSON" << std::endl;
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

void Notifier::process_notifications(const Config *config) {
    if (!config->notification_config.notification_enabled) {
        std::cout << "Notifications disabled" << std::endl;
        return;
    }

    char lock_path[PATH_BUFFER_SIZE];
    snprintf(lock_path, sizeof(lock_path), "%s.lock", config->notification_config.queue_path);
    FILE *lock = fopen(lock_path, "w");
    if (!lock) {
        std::cerr << "Failed to create lock file: " << lock_path << std::endl;
        return;
    }
    if (flock(fileno(lock), LOCK_EX | LOCK_NB) != 0) {
        fclose(lock);
        std::cerr << "Failed to acquire lock on: " << lock_path << std::endl;
        return;
    }

    FILE *file = fopen(config->notification_config.queue_path, "r");
    if (!file) {
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        std::cerr << "Failed to open queue file: " << config->notification_config.queue_path << std::endl;
        return;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    if (size == 0) {
        fclose(file);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        std::cout << "Queue file is empty" << std::endl;
        return;
    }
    fseek(file, 0, SEEK_SET);
    char *buffer = (char *)malloc(size + 1);
    if (!buffer) {
        fclose(file);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        std::cerr << "Failed to allocate buffer for queue file" << std::endl;
        return;
    }
    if (fread(buffer, 1, size, file) != (size_t)size) {
        free(buffer);
        fclose(file);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        std::cerr << "Failed to read queue file" << std::endl;
        return;
    }
    buffer[size] = '\0';
    fclose(file);

    cJSON *root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        std::cerr << "Failed to parse queue JSON" << std::endl;
        return;
    }

    cJSON *events = cJSON_GetObjectItem(root, "events");
    if (!events) {
        cJSON_Delete(root);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        std::cerr << "No events found in queue JSON" << std::endl;
        return;
    }

    int event_count = cJSON_GetArraySize(events);
    if (event_count < config->notification_config.min_events) {
        cJSON_Delete(root);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        std::cout << "Not enough events (" << event_count << ") to send notification, minimum required: " << config->notification_config.min_events << std::endl;
        return;
    }

    static time_t last_email_time = 0;
    time_t current_time = time(NULL);
    if (current_time - last_email_time < config->notification_config.min_interval_sec) {
        cJSON_Delete(root);
        flock(fileno(lock), LOCK_UN);
        fclose(lock);
        std::cout << "Too soon since last email, waiting " << config->notification_config.min_interval_sec << " seconds" << std::endl;
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

    int sent = 0; // Track if any notification was sent

    if (config->notification_config.email_enabled) {
        if (send_email(subject, body) == 0) {
            sent = 1;
        }
    }

    if (config->notification_config.telegram_enabled) {
        char telegram_msg[MAX_EMAIL_BODY_SIZE];
        size_t offset = 0;
        offset += snprintf(telegram_msg + offset, sizeof(telegram_msg) - offset,
            "[FIMon Alert]\nTime: %s\nEvent Count: %d\n\nEvent List:\n", timestamp, event_count);

        cJSON *event;
        cJSON_ArrayForEach(event, events) {
            cJSON *event_type = cJSON_GetObjectItem(event, "event");
            cJSON *path = cJSON_GetObjectItem(event, "path");
            offset += snprintf(telegram_msg + offset, sizeof(telegram_msg) - offset,
                "- %s: %s\n",
                event_type && cJSON_IsString(event_type) ? event_type->valuestring : "Unknown",
                path && cJSON_IsString(path) ? path->valuestring : "Unknown"
            );
            if (offset >= sizeof(telegram_msg) - 128) break;
        }
        send_telegram(telegram_msg);
        sent = 1;
    }

    if (config->notification_config.webhook_enabled && config->notification_config.webhook_url) {
        char webhook_msg[MAX_EMAIL_BODY_SIZE];
        size_t offset = 0;
        offset += snprintf(webhook_msg + offset, sizeof(webhook_msg) - offset,
            "[FIMon Alert]\nTime: %s\nEvent Count: %d\n\nEvent List:\n", timestamp, event_count);
        cJSON *event;
        cJSON_ArrayForEach(event, events) {
            cJSON *event_type = cJSON_GetObjectItem(event, "event");
            cJSON *path = cJSON_GetObjectItem(event, "path");
            offset += snprintf(webhook_msg + offset, sizeof(webhook_msg) - offset,
                "- %s: %s\n",
                event_type && cJSON_IsString(event_type) ? event_type->valuestring : "Unknown",
                path && cJSON_IsString(path) ? path->valuestring : "Unknown"
            );
            if (offset >= sizeof(webhook_msg) - 128) break;
        }
        send_webhook(webhook_msg);
        sent = 1;
    }

    // Only clear the queue and archive if any notification was sent
    if (sent) {
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
int Notifier::send_file(const char *subject, const char *body_html, const char *filepath) {
    (void)body_html; // suppress unused parameter warning
    std::cout << "Entering send_file: subject=" << (subject ? subject : "(null)") 
              << ", filepath=" << (filepath ? filepath : "(null)") << std::endl;
    int result = -1;

    if (config_->telegram_enabled && config_->telegram_bot_token && config_->telegram_chat_ids && config_->telegram_chat_id_count > 0) {
        for (int i = 0; i < config_->telegram_chat_id_count; ++i) {
            CURL *curl = curl_easy_init();
            if (!curl) {
                std::cerr << "Failed to initialize curl for Telegram document chat_id " << config_->telegram_chat_ids[i] << std::endl;
                continue;
            }
            char url[1024];
            snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendDocument", config_->telegram_bot_token);

            curl_mime *mime = curl_mime_init(curl);

            curl_mimepart *part = curl_mime_addpart(mime);
            curl_mime_name(part, "chat_id");
            curl_mime_data(part, config_->telegram_chat_ids[i], CURL_ZERO_TERMINATED);

            part = curl_mime_addpart(mime);
            curl_mime_name(part, "caption");
            curl_mime_data(part, subject ? subject : "FIMon Backup", CURL_ZERO_TERMINATED);

            part = curl_mime_addpart(mime);
            curl_mime_name(part, "document");
            curl_mime_filedata(part, filepath);
            curl_mime_type(part, "application/zip");

            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

            if (config_->telegram_proxy_enabled && config_->telegram_proxy_type && config_->telegram_proxy_host && config_->telegram_proxy_port > 0) {
                char proxy_url[256];
                snprintf(proxy_url, sizeof(proxy_url), "%s://%s:%d",
                    strcmp(config_->telegram_proxy_type, "http") == 0 ? "http" :
                    strcmp(config_->telegram_proxy_type, "socks4") == 0 ? "socks4" :
                    strcmp(config_->telegram_proxy_type, "socks5") == 0 ? "socks5h" : "http",
                    config_->telegram_proxy_host,
                    config_->telegram_proxy_port
                );
                curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url);

                if (config_->telegram_proxy_username && strlen(config_->telegram_proxy_username) > 0) {
                    curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, config_->telegram_proxy_username);
                }
                if (config_->telegram_proxy_password && strlen(config_->telegram_proxy_password) > 0) {
                    curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, config_->telegram_proxy_password);
                }
            }
            if (config_->telegram_ssl_enabled) {
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            } else {
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            }

            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "Telegram document send failed for chat_id " << config_->telegram_chat_ids[i] 
                          << ": " << curl_easy_strerror(res) << std::endl;
            } else {
                std::cout << "Telegram document sent successfully to chat_id " << config_->telegram_chat_ids[i] << std::endl;
                result = 0;
            }
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
        }
    }

    return result;
}

int Notifier::send_webhook(const char *message) {
    if (!config_->webhook_enabled || !config_->webhook_url)
        return -1;
    CURL *curl = curl_easy_init();
    if (!curl) return -1;
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "text", message);
    char *json = cJSON_PrintUnformatted(payload);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, config_->webhook_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    cJSON_Delete(payload);
    free(json);
    return (res == CURLE_OK) ? 0 : -1;
}

#ifdef __cplusplus
extern "C" {
#endif

// Provide a C linkage wrapper for process_notifications
void process_notifications(const Config *config) {
    Notifier notifier(&config->notification_config);
    notifier.process_notifications(config);
}

int send_file(const NotificationConfig *notif_config, const char *subject, const char *body_html, const char *filepath) {
    Notifier notifier(notif_config);
    return notifier.send_file(subject, body_html, filepath);
}

#ifdef __cplusplus
}
#endif