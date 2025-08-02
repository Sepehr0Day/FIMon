// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: backup.c
// Description: Implements backup functionality for FIMon, including zipping monitored paths
//              and sending backups via configured notification channels (e.g., Telegram).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#include "backup.h"
#include "notification.h"
#include "alert.h"

// Creates a zip archive of the specified paths and stores it in a temporary location.
static int zip_paths(const char **paths, int path_count, char *out_zip, size_t out_zip_len, int verbose) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char zipname[PATH_BUFFER_SIZE];
    strftime(zipname, sizeof(zipname), "/tmp/fimon_backup_%Y%m%d_%H%M%S.zip", tm);
    snprintf(out_zip, out_zip_len, "%s", zipname);

    char cmd[PATH_BUFFER_SIZE * 2] = {0};
    snprintf(cmd, sizeof(cmd), "zip -r -q %s", zipname);
    for (int i = 0; i < path_count; ++i) {
        strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        strncat(cmd, paths[i], sizeof(cmd) - strlen(cmd) - 1);
    }
    if (verbose) printf("Executing zip command: %s\n", cmd);
    int ret = system(cmd);
    if (ret != 0) {
        if (verbose) printf("Zip command failed with return code %d\n", ret);
    } else {
        if (verbose) printf("Zip file created: %s\n", zipname);
    }
    return (ret == 0) ? 0 : -1;
}

// Performs backup of configured paths and sends the backup via Telegram if enabled.
int perform_backup(const Config *config, int verbose) {
    if (!config->backup_config.backup_enabled || config->backup_config.backup_path_count == 0)
        return -1;

    char zipfile[PATH_BUFFER_SIZE];
    const char **paths = (const char **)config->backup_config.backup_paths;
    int path_count = config->backup_config.backup_path_count;
    if (zip_paths(paths, path_count, zipfile, sizeof(zipfile), verbose) != 0) {
        if (verbose) fprintf(stderr, "Backup zip failed\n");
        return -1;
    }

    char subject[256], body[1024];
    snprintf(subject, sizeof(subject), "[FIMon Backup] Backup at %ld", time(NULL));
    snprintf(body, sizeof(body), "<html><body><b>FIMon Backup</b><br/>Backup file attached.</body></html>");

    // Only send backup via telegram, remove email sending
    if (config->backup_config.backup_method && strstr(config->backup_config.backup_method, "telegram")) {
        NotificationConfig notif = config->notification_config;
        if (notif.telegram_enabled && notif.telegram_bot_token && notif.telegram_chat_ids && notif.telegram_chat_id_count > 0) {
            if (verbose) printf("Attempting to send backup to telegram chat(s)\n");
            int rc = send_file(&notif, subject, body, zipfile);
            if (verbose) printf("Backup sent via telegram: %s\n", rc == 0 ? "OK" : "FAIL");
        } else {
            if (verbose) printf("Telegram backup: telegram not enabled or missing config\n");
        }
    } else {
        if (verbose) printf("No valid backup method specified or backup_method is NULL.\n");
    }
    unlink(zipfile);
    return 0;
}