// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: main.c
// Description: Main entry point for FIMon. Handles argument parsing, configuration loading,
//              file permission checks, environment setup, and launches the monitoring process.
//              This file manages the overall lifecycle of the FIMon application, including
//              parsing command-line arguments, loading and validating configuration files,
//              checking file and directory permissions, initializing logging and database
//              resources, setting up notification and backup systems, and starting the
//              monitoring process. It also provides health check and status reporting
//              features for operational diagnostics.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sqlite3.h>
#include "config.h"
#include "monitor.h"
#include "error.h"
#include "db.h"
#include "backup.h"
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>

#ifdef __cplusplus
extern "C" {
#endif
// Runs FIMon as a system service, optionally in daemon mode.
void run_as_service(const char *config_path, int daemon_mode);
#ifdef __cplusplus
}
#endif

// Performs a health check on the FIMon configuration and environment, printing results.
int check_health(const Config *config);

// Prints the current status of FIMon, including monitored directories and runtime info.
int print_status(const Config *config);

// Main entry point for FIMon. Parses arguments, loads config, checks permissions, and starts monitoring.
int main(int argc, char *argv[]) {
    const char *config_path = NULL;
    int verbose = 0;
    int daemon_mode = 0;
    int run_as_service_flag = 0;
    int check_flag = 0;
    int status_flag = 0;

    if (argc == 1) {
        printf("Usage: %s --config <path> [--verbose] [--daemon] [--run-as-service] [--check] [--status]\n", argv[0]);
        printf("  --config <path>       Path to config file\n");
        printf("  --verbose             Enable verbose output\n");
        printf("  --daemon              Run as daemon\n");
        printf("  --run-as-service      Install and start as a service\n");
        printf("  --check               Perform health check\n");
        printf("  --status              Print FIMon status\n");
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--daemon") == 0) {
            daemon_mode = 1;
        } else if (strcmp(argv[i], "--run-as-service") == 0) {
            run_as_service_flag = 1;
        } else if (strcmp(argv[i], "--check") == 0) {
            check_flag = 1;
        } else if (strcmp(argv[i], "--status") == 0) {
            status_flag = 1;
        }
    }

    if (!config_path) {
        handle_error("Configuration file not specified. Use --config <path>", 1);
        return 1;
    }

    struct stat st;
    if (stat(config_path, &st) == 0) {
        if ((st.st_mode & 0077) != 0) {
            fprintf(stderr, "ERROR: Config file %s is world/group readable or writable! Please restrict permissions (chmod 600).\n", config_path);
            return 1;
        }
    }

    Config config = {0};
    if (load_config(config_path, &config, verbose) != 0) {
        return 1;
    }

    if (check_flag) {
        int rc = check_health(&config);
        free_config(&config);
        return rc;
    }
    if (status_flag) {
        int rc = print_status(&config);
        free_config(&config);
        return rc;
    }

    // Ensure log, json log, and db files exist with secure permissions
    FILE *f;
    if (access(config.log_path, F_OK) != 0) {
        f = fopen(config.log_path, "a");
        if (f) {
            fclose(f);
            chmod(config.log_path, 0600);
        }
    }
    if (access(config.json_log_path, F_OK) != 0) {
        f = fopen(config.json_log_path, "a");
        if (f) {
            fclose(f);
            chmod(config.json_log_path, 0600);
        }
    }
    if (access(config.db_path, F_OK) != 0) {
        f = fopen(config.db_path, "a");
        if (f) {
            fclose(f);
            chmod(config.db_path, 0600);
        }
    }

    if (stat(config.log_path, &st) == 0 && (st.st_mode & 0077) != 0) {
        fprintf(stderr, "ERROR: Log file %s is world/group readable or writable! Please restrict permissions (chmod 600).\n", config.log_path);
        free_config(&config);
        return 1;
    }
    if (stat(config.json_log_path, &st) == 0 && (st.st_mode & 0077) != 0) {
        fprintf(stderr, "ERROR: JSON log file %s is world/group readable or writable! Please restrict permissions (chmod 600).\n", config.json_log_path);
        free_config(&config);
        return 1;
    }

    if (config.notification_config.notification_enabled) {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    char backup_path[PATH_BUFFER_SIZE];
    size_t db_path_len = strlen(config.db_path);
    size_t suffix_len = strlen(".bak");
    if (db_path_len + suffix_len >= PATH_BUFFER_SIZE) {
        fprintf(stderr, "ERROR: Backup path too long for buffer\n");
        free_config(&config);
        return 1;
    }
    snprintf(backup_path, sizeof(backup_path), "%s.bak", config.db_path);

    if (config.notification_config.notification_enabled && config.notification_config.queue_path) {
        setenv("FIM_QUEUE_PATH", config.notification_config.queue_path, 1);
    }
    if (run_as_service_flag) {
        run_as_service(config_path, daemon_mode);
        return 0;
    }

    monitor_files(&config, verbose, daemon_mode);

    if (config.notification_config.notification_enabled) {
        curl_global_cleanup();
    }

    free_config(&config);
    return 0;
}

// --- Health check implementation ---
// Performs a comprehensive health check of monitored directories, log files, database, notification queue, archive, disk space, resource limits, and backup configuration.
int check_health(const Config *config) {
    int healthy = 1;
    printf("FIMon Health Check:\n");
    printf("  Directories monitored: %d\n", config->directory_count);
    if (config->directories) {
        for (int i = 0; i < config->directory_count; ++i) {
            printf("    - %s\n", config->directories[i].path);
            struct stat st;
            if (stat(config->directories[i].path, &st) != 0) {
                printf("      [ERROR] Directory missing or inaccessible!\n");
                healthy = 0;
            } else {
                printf("      [Owner: %d, Perm: %o, LastMod: %ld]\n", (int)st.st_uid, (int)(st.st_mode & 0777), (long)st.st_mtime);
            }
        }
    }
    // Log file check
    struct stat st;
    printf("  Log path: %s", config->log_path);
    if (stat(config->log_path, &st) == 0) {
        printf(" [OK]");
        if ((st.st_mode & 0077) != 0) {
            printf(" [PERMISSION WARNING: not 600]");
            healthy = 0;
        }
    } else {
        printf(" [ERROR: missing]");
        healthy = 0;
    }
    printf("\n");

    // JSON log file check
    printf("  JSON log path: %s", config->json_log_path);
    if (stat(config->json_log_path, &st) == 0) {
        printf(" [OK]");
        if ((st.st_mode & 0077) != 0) {
            printf(" [PERMISSION WARNING: not 600]");
            healthy = 0;
        }
    } else {
        printf(" [ERROR: missing]");
        healthy = 0;
    }
    printf("\n");

    // DB check
    printf("  DB path: %s", config->db_path);
    if (stat(config->db_path, &st) == 0) {
        printf(" [OK]");
    } else {
        printf(" [ERROR: missing]");
        healthy = 0;
    }
    printf("\n");

    // Notification queue check
    printf("  Notification queue: %s", config->notification_config.queue_path ? config->notification_config.queue_path : "(none)");
    if (config->notification_config.queue_path && stat(config->notification_config.queue_path, &st) == 0) {
        printf(" [OK]");
    } else if (config->notification_config.queue_path) {
        printf(" [ERROR: missing]");
        healthy = 0;
    }
    printf("\n");

    // Archive check
    printf("  Archive: %s", config->notification_config.archive_path ? config->notification_config.archive_path : "(none)");
    if (config->notification_config.archive_path && stat(config->notification_config.archive_path, &st) == 0) {
        printf(" [OK]");
    } else if (config->notification_config.archive_path) {
        printf(" [ERROR: missing]");
        healthy = 0;
    }
    printf("\n");

    // DB open test
    sqlite3 *db = NULL;
    if (sqlite3_open(config->db_path, &db) == SQLITE_OK) {
        printf("  Database open: OK\n");
        sqlite3_close(db);
    } else {
        printf("  Database open: ERROR\n");
        healthy = 0;
    }

    // Check disk space for log/db directory
    char *log_dir = strdup(config->log_path);
    char *db_dir = strdup(config->db_path);
    if (log_dir && db_dir) {
        char *log_slash = strrchr(log_dir, '/');
        char *db_slash = strrchr(db_dir, '/');
        if (log_slash) *log_slash = 0;
        if (db_slash) *db_slash = 0;
        struct statvfs vfs;
        if (statvfs(log_dir, &vfs) == 0) {
            unsigned long free_mb = (vfs.f_bavail * vfs.f_frsize) / (1024 * 1024);
            printf("  Log directory free space: %lu MB\n", free_mb);
            if (free_mb < 10) {
                printf("    [WARNING: Low disk space for logs]\n");
                healthy = 0;
            }
        }
        if (statvfs(db_dir, &vfs) == 0) {
            unsigned long free_mb = (vfs.f_bavail * vfs.f_frsize) / (1024 * 1024);
            printf("  DB directory free space: %lu MB\n", free_mb);
            if (free_mb < 10) {
                printf("    [WARNING: Low disk space for DB]\n");
                healthy = 0;
            }
        }
        free(log_dir);
        free(db_dir);
    }

    // Check process resource limits
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        printf("  Max open files: %ld\n", (long)rl.rlim_cur);
        if (rl.rlim_cur < 1024) {
            printf("    [WARNING: Low open file limit]\n");
            healthy = 0;
        }
    }

    // Check system info
    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("  System: %s %s %s\n", uts.sysname, uts.release, uts.machine);
    }

    // Notification/backup checks
    printf("  Notification: %s\n", config->notification_config.notification_enabled ? "ENABLED" : "DISABLED");
    printf("  Backup: %s\n", config->backup_config.backup_enabled ? "ENABLED" : "DISABLED");

    if (config->notification_config.email_enabled) {
        printf("    Email: ENABLED (SMTP: %s:%d, Recipients: %d)\n",
            config->notification_config.smtp_host ? config->notification_config.smtp_host : "(none)",
            config->notification_config.smtp_port,
            config->notification_config.recipient_count);
    }
    if (config->notification_config.telegram_enabled) {
        printf("    Telegram: ENABLED (Bot: %s, Chats: %d)\n",
            config->notification_config.telegram_bot_token ? config->notification_config.telegram_bot_token : "(none)",
            config->notification_config.telegram_chat_id_count);
    }
    if (config->notification_config.webhook_enabled) {
        printf("    Webhook: ENABLED (URL: %s)\n",
            config->notification_config.webhook_url ? config->notification_config.webhook_url : "(none)");
    }

    if (config->backup_config.backup_enabled) {
        printf("    Backup interval: %d seconds\n", config->backup_config.backup_interval_sec);
        printf("    Backup paths:\n");
        for (int i = 0; i < config->backup_config.backup_path_count; ++i) {
            printf("      - %s\n", config->backup_config.backup_paths[i]);
            struct stat st;
            if (stat(config->backup_config.backup_paths[i], &st) != 0) {
                printf("        [ERROR: Path missing or inaccessible]\n");
                healthy = 0;
            }
        }
        printf("    Backup method: %s\n", config->backup_config.backup_method ? config->backup_config.backup_method : "(none)");
        printf("    Backup recipients: %d\n", config->backup_config.backup_recipient_count);
    }

    // Check for log signature file (tamper detection)
    char sig_path[PATH_BUFFER_SIZE];
    // Use strncat to avoid truncation warning if log_path is very long
    if (strlen(config->log_path) + 4 < sizeof(sig_path)) {
        snprintf(sig_path, sizeof(sig_path), "%s.sig", config->log_path);
    } else {
        strncpy(sig_path, config->log_path, sizeof(sig_path) - 5);
        sig_path[sizeof(sig_path) - 5] = '\0';
        strncat(sig_path, ".sig", sizeof(sig_path) - strlen(sig_path) - 1);
    }
    if (access(sig_path, F_OK) == 0) {
        printf("  Log signature: PRESENT\n");
    } else {
        printf("  Log signature: MISSING [WARNING: Tamper detection disabled]\n");
        healthy = 0;
    }

    printf("  Health: %s\n", healthy ? "OK" : "PROBLEM DETECTED");
    return healthy ? 0 : 1;
}

// --- Status reporting implementation ---
// Prints the current status of FIMon, including monitored directories, log files, database, notification queue, archive, notification and backup configuration, and runtime info.
int print_status(const Config *config) {
    printf("FIMon Status:\n");
    printf("  Monitored directories:\n");
    if (config->directories) {
        for (int i = 0; i < config->directory_count; ++i) {
            printf("    - %s\n", config->directories[i].path);
            printf("      Hash type: %d\n", config->directories[i].hash_type);
            printf("      Ignore patterns: ");
            for (int j = 0; j < config->directories[i].ignore_patterns.pattern_count; ++j) {
                printf("%s%s", j ? ", " : "", config->directories[i].ignore_patterns.patterns[j]);
            }
            printf("\n      Tags: ");
            for (int j = 0; j < config->directories[i].tags.tag_count; ++j) {
                printf("%s%s", j ? ", " : "", config->directories[i].tags.tags[j]);
            }
            printf("\n");
            struct stat st;
            if (stat(config->directories[i].path, &st) == 0) {
                printf("      Owner: %d, Perm: %o, LastMod: %ld\n", (int)st.st_uid, (int)(st.st_mode & 0777), (long)st.st_mtime);
            }
        }
    }
    printf("  Log file: %s\n", config->log_path);
    printf("  JSON log file: %s\n", config->json_log_path);
    printf("  Database: %s\n", config->db_path);
    printf("  Notification queue: %s\n", config->notification_config.queue_path ? config->notification_config.queue_path : "(none)");
    printf("  Archive: %s\n", config->notification_config.archive_path ? config->notification_config.archive_path : "(none)");
    printf("  Notification: %s\n", config->notification_config.notification_enabled ? "ENABLED" : "DISABLED");
    printf("    Email: %s\n", config->notification_config.email_enabled ? "ENABLED" : "DISABLED");
    printf("    Telegram: %s\n", config->notification_config.telegram_enabled ? "ENABLED" : "DISABLED");
    printf("    Webhook: %s\n", config->notification_config.webhook_enabled ? "ENABLED" : "DISABLED");
    printf("  Backup interval: %d seconds\n", config->backup_config.backup_interval_sec);
    printf("  Backup method: %s\n", config->backup_config.backup_method ? config->backup_config.backup_method : "(none)");
    printf("  Backup recipients: %d\n", config->backup_config.backup_recipient_count);
    printf("  Backup paths:\n");
    for (int i = 0; i < config->backup_config.backup_path_count; ++i) {
        printf("    - %s\n", config->backup_config.backup_paths[i]);
    }
    // Print runtime info
    FILE *pidf = fopen("fimon.pid", "r");
    if (pidf) {
        int pid = 0;
        int fscanf_result = fscanf(pidf, "%d", &pid);
        (void)fscanf_result; // explicitly mark as unused
        fclose(pidf);
        printf("  Running as daemon, PID: %d\n", pid);
        // Print uptime if possible
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/stat", pid);
        FILE *statf = fopen(proc_path, "r");
        if (statf) {
            long long starttime = 0;
            char buf[4096];
            if (fgets(buf, sizeof(buf), statf)) {
                char *token = strtok(buf, " ");
                int field = 1;
                while (token) {
                    if (field == 22) { // 22nd field is starttime
                        starttime = atoll(token);
                        break;
                    }
                    token = strtok(NULL, " ");
                    field++;
                }
            }
            fclose(statf);
            if (starttime > 0) {
                long clk_tck = sysconf(_SC_CLK_TCK);
                time_t boot_time = 0;
                FILE *uptimef = fopen("/proc/stat", "r");
                if (uptimef) {
                    char line[256];
                    while (fgets(line, sizeof(line), uptimef)) {
                        if (strncmp(line, "btime ", 6) == 0) {
                            boot_time = atol(line + 6);
                            break;
                        }
                    }
                    fclose(uptimef);
                }
                time_t proc_start = boot_time + (starttime / clk_tck);
                time_t now = time(NULL);
                printf("  Uptime: %ld seconds\n", (long)(now - proc_start));
            }
        }
    }
    // Print system info
    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("  System: %s %s %s\n", uts.sysname, uts.release, uts.machine);
    }
    printf("  Status: READY\n");
    return 0;
}