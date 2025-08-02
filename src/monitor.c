// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: monitor.c
// Description: Implements the core logic for monitoring files and directories using inotify,
//              tracking file changes, handling ignore patterns and tags, and triggering notifications.
//              This file manages the inotify event loop, directory scanning, and event processing.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <fnmatch.h>
#include "monitor.h"
#include "hash.h"
#include "error.h"
#include "db.h"
#include "cJSON.h"
#include "alert.h"
#include "backup.h"
#include <pthread.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))
#define MSG_BUFFER_SIZE 16384
#define MAX_EVENT_NAME_LEN 256

// --- Global/static state for tracking files and directories ---
static FileInfo *tracked_files = NULL;
static int tracked_file_count = 0;
static DirectoryConfig *watched_dirs = NULL;
static int *watch_descriptors = NULL;
static int watched_dir_count = 0;

#ifdef __cplusplus
extern "C" {
#endif
// Processes queued events and sends notifications if conditions are met.
void process_notifications(const Config *config);
#ifdef __cplusplus
}
#endif

// Retrieves file metadata for a given path, including size, modification time, ownership, and permissions.
void get_file_details(const char *path, FileInfo *file) {
    struct stat st;
    if (stat(path, &st) == 0) {
        file->size = st.st_size;
        file->mtime = st.st_mtime;
        file->uid = st.st_uid;
        file->gid = st.st_gid;
        file->permissions = st.st_mode & 0777;
        
        struct passwd *pw = getpwuid(st.st_uid);
        strncpy(file->user, pw ? pw->pw_name : "unknown", sizeof(file->user) - 1);
        file->user[sizeof(file->user) - 1] = '\0';
        
        struct group *gr = getgrgid(st.st_gid);
        strncpy(file->group, gr ? gr->gr_name : "unknown", sizeof(file->group) - 1);
        file->group[sizeof(file->group) - 1] = '\0';
        
        file->via_ssh = getenv("SSH_CONNECTION") || getenv("SSH_CLIENT") ? 1 : 0;
    } else {
        strncpy(file->user, "unknown", sizeof(file->user) - 1);
        file->user[sizeof(file->user) - 1] = '\0';
        strncpy(file->group, "unknown", sizeof(file->group) - 1);
        file->group[sizeof(file->group) - 1] = '\0';
        file->permissions = 0;
        file->via_ssh = 0;
    }
}

// Determines if a file or directory should be ignored based on ignore patterns.
// Returns 1 if the file or directory matches any ignore pattern, otherwise 0.
int should_ignore(const char *path, const char *name, IgnorePatterns *ignore_patterns) {
    char full_path[PATH_BUFFER_SIZE];
    snprintf(full_path, sizeof(full_path) - 1, "%s/%s", path, name);
    full_path[sizeof(full_path) - 1] = '\0';
    
    for (int i = 0; i < ignore_patterns->pattern_count; i++) {
        if (fnmatch(ignore_patterns->patterns[i], name, 0) == 0 || fnmatch(ignore_patterns->patterns[i], full_path, 0) == 0) {
            return 1;
        }
    }
    return 0;
}

// Determines if a directory is non-critical based on its tags.
// Returns 1 if the directory has the "non-critical" tag, otherwise 0.
int is_non_critical(Tags *tags) {
    for (int i = 0; i < tags->tag_count; i++) {
        if (strcmp(tags->tags[i], "non-critical") == 0) {
            return 1;
        }
    }
    return 0;
}

// Checks if a directory is configured for monitoring.
// Returns the index of the directory in the configuration array, or -1 if not found.
int is_configured_directory(const char *dir_path, DirectoryConfig *dirs, int dir_count) {
    for (int i = 0; i < dir_count; i++) {
        if (strcmp(dir_path, dirs[i].path) == 0) {
            return i;
        }
    }
    return -1;
}

// Adds a file to the tracked files list, computes its hash, logs details, and updates the database.
// The function also handles ignore patterns and tags associated with the file.
void add_tracked_file(const char *dir_path, const char *file_name, HashType hash_type, const char *db_path, 
                     const char *log_path, const char *json_log_path, int verbose, const char *event_type, 
                     IgnorePatterns *ignore_patterns, Tags *tags) {
    if (should_ignore(dir_path, file_name, ignore_patterns)) {
        if (verbose) {
            char msg[MSG_BUFFER_SIZE];
            snprintf(msg, sizeof(msg), "Ignoring file: %s/%s", dir_path, file_name);
            msg[sizeof(msg)-1] = '\0';
            log_event(log_path, msg, verbose);
        }
        return;
    }

    char full_path[PATH_BUFFER_SIZE];
    size_t dir_len = strlen(dir_path);
    size_t file_len = strlen(file_name);
    if (dir_len + file_len + 1 >= PATH_BUFFER_SIZE) {
        char msg[MSG_BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "Path too long for %s/%s", dir_path, file_name);
        msg[sizeof(msg)-1] = '\0';
        handle_error(msg, verbose);
        return;
    }
    // Use memcpy and manual concatenation to avoid snprintf truncation warning
    memcpy(full_path, dir_path, dir_len);
    full_path[dir_len] = '/';
    memcpy(full_path + dir_len + 1, file_name, file_len);
    full_path[dir_len + 1 + file_len] = '\0';
    
    tracked_files = realloc(tracked_files, (tracked_file_count + 1) * sizeof(FileInfo));
    if (!tracked_files) {
        handle_error("Memory allocation failed for tracked files", verbose);
        return;
    }
    
    FileInfo *file = &tracked_files[tracked_file_count];
    strncpy(file->path, full_path, PATH_BUFFER_SIZE - 1);
    file->path[PATH_BUFFER_SIZE - 1] = '\0';
    file->hash_type = hash_type;
    
    if (compute_file_hash(file->path, file->hash, file->hash_type, &file->size, &file->mtime) == 0) {
        get_file_details(file->path, file);
        if (!is_non_critical(tags)) {
            char msg[MSG_BUFFER_SIZE], details[1024];
            snprintf(msg, sizeof(msg), "%s for %s in directory %s", event_type, file_name, dir_path);
            snprintf(details, sizeof(details), "{\"hash\": \"%s\", \"size\": %ld, \"user\": \"%s\", \"group\": \"%s\", \"permissions\": %o, \"via_ssh\": %s}", 
                     file->hash, (long)file->size, file->user, file->group, file->permissions, file->via_ssh ? "true" : "false");
            log_event(log_path, msg, verbose);
            // Only send notification if event_type is not "InitialHash"
            if (strcmp(event_type, "InitialHash") != 0) {
                log_event_json(json_log_path, event_type, file->path, details, verbose);
            }
        }
        save_file_info(db_path, file->path, file->hash, file->size, file->mtime, verbose);
        tracked_file_count++;
    }
}

// Adds a directory to the inotify watch list, logs its creation, and handles temporary directories.
// The function also manages ignore patterns and tags associated with the directory.
void add_watched_dir(const char *dir_path, HashType hash_type, int fd, 
                     const char *log_path, const char *json_log_path, int verbose, 
                     IgnorePatterns *ignore_patterns, Tags *tags, int is_temporary) {
    if (!is_temporary && should_ignore(dir_path, "", ignore_patterns)) {
        if (verbose) {
            char msg[MSG_BUFFER_SIZE];
            snprintf(msg, sizeof(msg), "Ignoring directory: %s", dir_path);
            msg[sizeof(msg)-1] = '\0';
            log_event(log_path, msg, verbose);
        }
        return;
    }

    watched_dirs = realloc(watched_dirs, (watched_dir_count + 1) * sizeof(DirectoryConfig));
    watch_descriptors = realloc(watch_descriptors, (watched_dir_count + 1) * sizeof(int));
    if (!watched_dirs || !watch_descriptors) {
        handle_error("Memory allocation failed for watched directories", verbose);
        return;
    }

    DirectoryConfig *dir = &watched_dirs[watched_dir_count];
    strncpy(dir->path, dir_path, PATH_BUFFER_SIZE - 1);
    dir->path[PATH_BUFFER_SIZE - 1] = '\0';
    dir->hash_type = hash_type;
    dir->ignore_patterns = *ignore_patterns;
    dir->tags = *tags;
    
    get_file_details(dir_path, &dir->info);
    
    watch_descriptors[watched_dir_count] = inotify_add_watch(fd, dir_path, IN_MODIFY | IN_DELETE | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO | IN_DELETE_SELF);
    if (watch_descriptors[watched_dir_count] < 0) {
        char msg[MSG_BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "Failed to add watch for %s: %s", dir_path, strerror(errno));
        log_event(log_path, msg, verbose);
    } else {
        char msg[MSG_BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "Watching directory: %s (wd: %d)", dir_path, watch_descriptors[watched_dir_count]);
        log_event(log_path, msg, verbose);
        
        if (!is_non_critical(tags) && is_temporary) {
            char msg[MSG_BUFFER_SIZE], details[1024];
            snprintf(msg, sizeof(msg), "DirectoryCreated: %s", dir_path);
            snprintf(details, sizeof(details), "{\"user\": \"%s\", \"group\": \"%s\", \"permissions\": %o, \"via_ssh\": %s}", 
                     dir->info.user, dir->info.group, dir->info.permissions, dir->info.via_ssh ? "true" : "false");
            log_event(log_path, msg, verbose);
            log_event_json(json_log_path, "DirectoryCreated", dir_path, details, verbose);
        }
    }
    watched_dir_count++;
}

// Recursively scans a directory, adds files to tracking, and sets up watches for subdirectories.
// The function also handles ignore patterns and tags for the directory and its contents.
void scan_directory(const char *dir_path, HashType hash_type, const char *db_path, 
                   const char *log_path, const char *json_log_path, int verbose, int fd, 
                   IgnorePatterns *ignore_patterns, Tags *tags, DirectoryConfig *dirs, int dir_count) {
    int dir_index = is_configured_directory(dir_path, dirs, dir_count);
    if (dir_index < 0 && !is_configured_directory(dir_path, watched_dirs, watched_dir_count)) {
        if (verbose) {
            char msg[MSG_BUFFER_SIZE];
            snprintf(msg, sizeof(msg), "Skipping unconfigured directory: %s", dir_path);
            log_event(log_path, msg, verbose);
        }
        return;
    }

    if (is_configured_directory(dir_path, watched_dirs, watched_dir_count) < 0) {
        add_watched_dir(dir_path, hash_type, fd, log_path, json_log_path, verbose, ignore_patterns, tags, 0);
    }

    DIR *dir = opendir(dir_path);
    if (!dir) {
        char msg[MSG_BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "Failed to open directory %s: %s", dir_path, strerror(errno));
        log_event(log_path, msg, verbose);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_REG) {
            add_tracked_file(dir_path, entry->d_name, hash_type, db_path, log_path, json_log_path, verbose, "InitialHash", ignore_patterns, tags);
        } else if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char subdir_path[PATH_BUFFER_SIZE];
            size_t dir_len = strlen(dir_path);
            size_t name_len = strlen(entry->d_name);
            if (dir_len + name_len + 1 >= PATH_BUFFER_SIZE) {
                char msg[MSG_BUFFER_SIZE];
                snprintf(msg, sizeof(msg), "Subdirectory path too long for %s/%s", dir_path, entry->d_name);
                msg[sizeof(msg)-1] = '\0';
                handle_error(msg, verbose);
                continue;
            }
            memcpy(subdir_path, dir_path, dir_len);
            subdir_path[dir_len] = '/';
            memcpy(subdir_path + dir_len + 1, entry->d_name, name_len);
            subdir_path[dir_len + 1 + name_len] = '\0';
            scan_directory(subdir_path, hash_type, db_path, log_path, json_log_path, verbose, fd, ignore_patterns, tags, dirs, dir_count);
        }
    }
    closedir(dir);
}

// Main monitoring loop.
// Initializes inotify, scans configured directories, processes filesystem events, and triggers notifications and backups.
void monitor_files(Config *config, int verbose, int daemon_mode) {
    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) {
            handle_error("Failed to fork for daemon", verbose);
            exit(1);
        }
        if (pid > 0) {
            FILE *pid_file = fopen("fimon.pid", "w");
            if (pid_file) {
                fprintf(pid_file, "%d\n", pid);
                fclose(pid_file);
            }
            printf("Daemon started with PID %d\n", pid);
            exit(0);
        }
        setsid();
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        char err_msg[MSG_BUFFER_SIZE];
        snprintf(err_msg, sizeof(err_msg), "Failed to initialize inotify: %s", strerror(errno));
        handle_error(err_msg, verbose);
        exit(1);
    }

    if (init_database(config->db_path, verbose) != 0) {
        handle_error("Failed to initialize database", verbose);
        close(fd);
        exit(1);
    }

    watched_dirs = malloc(config->directory_count * sizeof(DirectoryConfig));
    watch_descriptors = malloc(config->directory_count * sizeof(int));
    if (!watched_dirs || !watch_descriptors) {
        handle_error("Memory allocation failed for watched directories", verbose);
        close(fd);
        exit(1);
    }
    watched_dir_count = 0;

    for (int i = 0; i < config->directory_count; i++) {
        add_watched_dir(config->directories[i].path, config->directories[i].hash_type, fd, config->log_path, config->json_log_path, verbose, 
                        &config->directories[i].ignore_patterns, &config->directories[i].tags, 0);
        scan_directory(config->directories[i].path, config->directories[i].hash_type, config->db_path, config->log_path, config->json_log_path, 
                       verbose, fd, &config->directories[i].ignore_patterns, &config->directories[i].tags, config->directories, config->directory_count);
    }

    time_t last_notification_check = time(NULL);
    time_t last_backup = 0; // <-- add this line

    char buffer[EVENT_BUF_LEN];
    while (1) {
        int length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                time_t current_time = time(NULL);
                if (config->notification_config.notification_enabled && current_time - last_notification_check >= config->notification_config.min_interval_sec) {
                    process_notifications(config);
                    last_notification_check = current_time;
                }
                // --- Backup scheduling inside monitoring loop ---
                if (config->backup_config.backup_enabled && config->backup_config.backup_interval_sec > 0) {
                    time_t now = time(NULL);
                    if (now - last_backup >= config->backup_config.backup_interval_sec) {
                        perform_backup(config, verbose);
                        last_backup = now;
                    }
                }
                // Sleep a bit to avoid busy loop
                usleep(100000);
                continue;
            }
            char err_msg[MSG_BUFFER_SIZE];
            snprintf(err_msg, sizeof(err_msg), "Error reading inotify events: %s", strerror(errno));
            handle_error(err_msg, verbose);
            usleep(100000);
            continue;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            char debug_msg[MSG_BUFFER_SIZE];
            snprintf(debug_msg, sizeof(debug_msg), "Received inotify event: wd=%d, mask=%u, name=%s", event->wd, event->mask, event->name);
            log_event(config->log_path, debug_msg, verbose);

            for (int j = 0; j < watched_dir_count; j++) {
                if (event->wd == watch_descriptors[j]) {
                    if (event->len) {
                        char full_path[PATH_BUFFER_SIZE];
                        size_t base_len = strlen(watched_dirs[j].path);
                        size_t name_len = strlen(event->name);
                        // Instead of using event->name directly, use a truncated safe_event_name
                        char safe_event_name[MAX_EVENT_NAME_LEN];
                        strncpy(safe_event_name, event->name, MAX_EVENT_NAME_LEN - 1);
                        safe_event_name[MAX_EVENT_NAME_LEN - 1] = '\0';
                        if (base_len + strlen(safe_event_name) + 1 >= PATH_BUFFER_SIZE) {
                            char msg[MSG_BUFFER_SIZE];
                            snprintf(msg, sizeof(msg), "Path too long for %s/%s", watched_dirs[j].path, safe_event_name);
                            msg[sizeof(msg)-1] = '\0';
                            handle_error(msg, verbose);
                            continue;
                        }
                        memcpy(full_path, watched_dirs[j].path, base_len);
                        full_path[base_len] = '/';
                        memcpy(full_path + base_len + 1, event->name, name_len);
                        full_path[base_len + 1 + name_len] = '\0';

                        if (event->mask & IN_MOVED_FROM) {
                            static char moved_from_path[PATH_BUFFER_SIZE] = {0};
                            strncpy(moved_from_path, full_path, PATH_BUFFER_SIZE-1);
                            moved_from_path[PATH_BUFFER_SIZE-1] = '\0';
                            static char moved_from_name[PATH_BUFFER_SIZE] = {0};
                            strncpy(moved_from_name, event->name, PATH_BUFFER_SIZE-1);
                            moved_from_name[PATH_BUFFER_SIZE-1] = '\0';
                            if (!should_ignore(watched_dirs[j].path, event->name, &watched_dirs[j].ignore_patterns) &&
                                !is_non_critical(&watched_dirs[j].tags)) {
                                char msg[MSG_BUFFER_SIZE];
                                snprintf(msg, sizeof(msg), "File moved from: %s", moved_from_path);
                                log_event(config->log_path, msg, verbose);
                                log_event_json(config->json_log_path, "FileMovedFrom", moved_from_path, "{}", verbose);
                            }
                        } else if (event->mask & IN_MOVED_TO) {
                            if (!should_ignore(watched_dirs[j].path, event->name, &watched_dirs[j].ignore_patterns) &&
                                !is_non_critical(&watched_dirs[j].tags)) {
                                char msg[MSG_BUFFER_SIZE];
                                snprintf(msg, sizeof(msg), "File moved/renamed to: %s", full_path);
                                log_event(config->log_path, msg, verbose);
                                log_event_json(config->json_log_path, "FileMovedTo", full_path, "{}", verbose);
                            }
                        }

                        if (event->mask & IN_ATTRIB) {
                            struct stat st;
                            if (stat(full_path, &st) == 0) {
                                char details[256];
                                snprintf(details, sizeof(details),
                                    "{\"permissions\": %o, \"uid\": %d, \"gid\": %d, \"mtime\": %ld}",
                                    st.st_mode & 0777, st.st_uid, st.st_gid, (long)st.st_mtime);
                                char msg[MSG_BUFFER_SIZE];
                                snprintf(msg, sizeof(msg), "File attributes changed: %s", full_path);
                                log_event(config->log_path, msg, verbose);
                                log_event_json(config->json_log_path, "FileAttribChanged", full_path, details, verbose);
                            }
                        }

                        if (event->mask & IN_CREATE) {
                            struct stat st;
                            if (stat(full_path, &st) == 0) {
                                if (S_ISREG(st.st_mode)) {
                                    if (!should_ignore(watched_dirs[j].path, event->name, &watched_dirs[j].ignore_patterns)) {
                                        add_tracked_file(watched_dirs[j].path, event->name, watched_dirs[j].hash_type, 
                                                        config->db_path, config->log_path, config->json_log_path, verbose, "FileCreated", 
                                                        &watched_dirs[j].ignore_patterns, &watched_dirs[j].tags);
                                    } else if (verbose) {
                                        char msg[MSG_BUFFER_SIZE];
                                        snprintf(msg, sizeof(msg), "Ignoring file: %s/%s", watched_dirs[j].path, event->name);
                                        msg[sizeof(msg)-1] = '\0';
                                        log_event(config->log_path, msg, verbose);
                                    }
                                } else if (S_ISDIR(st.st_mode)) {
                                    char debug_msg[MSG_BUFFER_SIZE];
                                    snprintf(debug_msg, sizeof(debug_msg), "Detected new directory: %s", full_path);
                                    log_event(config->log_path, debug_msg, verbose);
                                    int dir_index = is_configured_directory(full_path, config->directories, config->directory_count);
                                    IgnorePatterns empty_patterns = { .pattern_count = 0, .patterns = NULL };
                                    Tags empty_tags = { .tag_count = 0, .tags = NULL };
                                    if (dir_index >= 0) {
                                        add_watched_dir(full_path, config->directories[dir_index].hash_type, fd, 
                                                       config->log_path, config->json_log_path, verbose, &config->directories[dir_index].ignore_patterns, 
                                                       &config->directories[dir_index].tags, 0);
                                        scan_directory(full_path, config->directories[dir_index].hash_type, config->db_path, 
                                                     config->log_path, config->json_log_path, verbose, fd, &config->directories[dir_index].ignore_patterns, 
                                                     &config->directories[dir_index].tags, config->directories, config->directory_count);
                                    } else {
                                        add_watched_dir(full_path, HASH_SHA256, fd, config->log_path, config->json_log_path, verbose, 
                                                       &empty_patterns, &empty_tags, 1);
                                        scan_directory(full_path, HASH_SHA256, config->db_path, config->log_path, config->json_log_path, 
                                                     verbose, fd, &empty_patterns, &empty_tags, config->directories, config->directory_count);
                                    }
                                }
                            }
                        } else if (event->mask & (IN_MODIFY | IN_CLOSE_WRITE)) {
                            for (int k = 0; k < tracked_file_count; k++) {
                                if (strcmp(tracked_files[k].path, full_path) == 0) {
                                    if (!should_ignore(watched_dirs[j].path, event->name, &watched_dirs[j].ignore_patterns)) {
                                        char new_hash[MAX_HASH_LEN];
                                        off_t new_size;
                                        time_t new_mtime;
                                        if (compute_file_hash(full_path, new_hash, tracked_files[k].hash_type, &new_size, &new_mtime) == 0) {
                                            get_file_details(full_path, &tracked_files[k]);
                                            if (!is_non_critical(&watched_dirs[j].tags)) {
                                                char msg[MSG_BUFFER_SIZE], details[1024];
                                                int log_event_flag = 0;
                                                char safe_event_name[MAX_EVENT_NAME_LEN];
                                                strncpy(safe_event_name, event->name, MAX_EVENT_NAME_LEN - 1);
                                                safe_event_name[MAX_EVENT_NAME_LEN - 1] = '\0';
                                                if (compare_hashes(tracked_files[k].hash, new_hash) != 0) {
                                                    if (strlen(watched_dirs[j].path) + strlen(safe_event_name) + 19 >= MSG_BUFFER_SIZE) {
                                                        handle_error("Message too long for FileChanged event", verbose);
                                                        continue;
                                                    }
                                                    snprintf(msg, sizeof(msg), "File changed in %s: %s", watched_dirs[j].path, safe_event_name);
                                                    snprintf(details, sizeof(details), "{\"hash\": \"%s\", \"size\": %ld, \"user\": \"%s\", \"group\": \"%s\", \"permissions\": %o, \"via_ssh\": %s}", 
                                                             new_hash, (long)new_size, tracked_files[k].user, tracked_files[k].group, 
                                                             tracked_files[k].permissions, tracked_files[k].via_ssh ? "true" : "false");
                                                    log_event(config->log_path, msg, verbose);
                                                    log_event_json(config->json_log_path, "FileChanged", full_path, details, verbose);
                                                    log_event_flag = 1;
                                                } else if (tracked_files[k].size != new_size) {
                                                    if (strlen(watched_dirs[j].path) + strlen(safe_event_name) + 24 >= MSG_BUFFER_SIZE) {
                                                        handle_error("Message too long for FileSizeChanged event", verbose);
                                                        continue;
                                                    }
                                                    snprintf(msg, sizeof(msg), "File size changed in %s: %s", watched_dirs[j].path, safe_event_name);
                                                    snprintf(details, sizeof(details), "{\"hash\": \"%s\", \"size\": %ld, \"user\": \"%s\", \"group\": \"%s\", \"permissions\": %o, \"via_ssh\": %s}", 
                                                             new_hash, (long)new_size, tracked_files[k].user, tracked_files[k].group, 
                                                             tracked_files[k].permissions, tracked_files[k].via_ssh ? "true" : "false");
                                                    log_event(config->log_path, msg, verbose);
                                                    log_event_json(config->json_log_path, "FileSizeChanged", full_path, details, verbose);
                                                    log_event_flag = 1;
                                                } else if (tracked_files[k].mtime != new_mtime) {
                                                    if (strlen(watched_dirs[j].path) + strlen(safe_event_name) + 33 >= MSG_BUFFER_SIZE) {
                                                        handle_error("Message too long for FileMtimeChanged event", verbose);
                                                        continue;
                                                    }
                                                    snprintf(msg, sizeof(msg), "File modified time changed in %s: %s", watched_dirs[j].path, safe_event_name);
                                                    snprintf(details, sizeof(details), "{\"hash\": \"%s\", \"size\": %ld, \"user\": \"%s\", \"group\": \"%s\", \"permissions\": %o, \"via_ssh\": %s}", 
                                                             new_hash, (long)new_size, tracked_files[k].user, tracked_files[k].group, 
                                                             tracked_files[k].permissions, tracked_files[k].via_ssh ? "true" : "false");
                                                    log_event(config->log_path, msg, verbose);
                                                    log_event_json(config->json_log_path, "FileMtimeChanged", full_path, details, verbose);
                                                    log_event_flag = 1;
                                                }
                                                if (log_event_flag) {
                                                    compare_and_log_changes(config->db_path, full_path, new_hash, new_size, new_mtime, 
                                                                           config->log_path, config->json_log_path, verbose, "FileChanged");
                                                }
                                            }
                                            strncpy(tracked_files[k].hash, new_hash, MAX_HASH_LEN);
                                            tracked_files[k].size = new_size;
                                            tracked_files[k].mtime = new_mtime;
                                        }
                                    } else if (verbose) {
                                        char msg[MSG_BUFFER_SIZE];
                                        snprintf(msg, sizeof(msg), "Ignoring file: %s/%s", watched_dirs[j].path, event->name);
                                        msg[sizeof(msg)-1] = '\0';
                                        log_event(config->log_path, msg, verbose);
                                    }
                                    break;
                                }
                            }
                        } else if (event->mask & IN_DELETE) {
                            for (int k = 0; k < tracked_file_count; k++) {
                                if (strcmp(tracked_files[k].path, full_path) == 0) {
                                    if (!should_ignore(watched_dirs[j].path, event->name, &watched_dirs[j].ignore_patterns) && 
                                        !is_non_critical(&watched_dirs[j].tags)) {
                                        char msg[MSG_BUFFER_SIZE], details[1024];
                                        char safe_event_name[MAX_EVENT_NAME_LEN];
                                        strncpy(safe_event_name, event->name, MAX_EVENT_NAME_LEN - 1);
                                        safe_event_name[MAX_EVENT_NAME_LEN - 1] = '\0';
                                        if (strlen(watched_dirs[j].path) + strlen(safe_event_name) + 19 >= MSG_BUFFER_SIZE) {
                                            handle_error("Message too long for FileDeleted event", verbose);
                                            continue;
                                        }
                                        snprintf(msg, sizeof(msg), "File deleted in %s: %s", watched_dirs[j].path, safe_event_name);
                                        snprintf(details, sizeof(details), "{\"hash\": \"%s\", \"size\": %ld, \"user\": \"%s\", \"group\": \"%s\", \"permissions\": %o, \"via_ssh\": %s}", 
                                                 tracked_files[k].hash, (long)tracked_files[k].size, tracked_files[k].user, 
                                                 tracked_files[k].group, tracked_files[k].permissions, 
                                                 tracked_files[k].via_ssh ? "true" : "false");
                                        log_event(config->log_path, msg, verbose);
                                        log_event_json(config->json_log_path, "FileDeleted", full_path, details, verbose);
                                    }
                                    for (int m = k; m < tracked_file_count - 1; m++) {
                                        tracked_files[m] = tracked_files[m + 1];
                                    }
                                    tracked_file_count--;
                                    tracked_files = realloc(tracked_files, tracked_file_count * sizeof(FileInfo));
                                    break;
                                }
                            }
                        }
                    }
                    if (event->mask & IN_DELETE_SELF && event->wd == watch_descriptors[j]) {
                        if (!is_non_critical(&watched_dirs[j].tags)) {
                            char msg[MSG_BUFFER_SIZE], details[1024];
                            snprintf(msg, sizeof(msg), "Directory deleted: %s", watched_dirs[j].path);
                            snprintf(details, sizeof(details), "{\"user\": \"%s\", \"group\": \"%s\", \"permissions\": %o, \"via_ssh\": %s}", 
                                     watched_dirs[j].info.user, watched_dirs[j].info.group, watched_dirs[j].info.permissions, 
                                     watched_dirs[j].info.via_ssh ? "true" : "false");
                            log_event(config->log_path, msg, verbose);
                            log_event_json(config->json_log_path, "DirectoryDeleted", watched_dirs[j].path, details, verbose);
                        }
                        inotify_rm_watch(fd, watch_descriptors[j]);
                        for (int m = j; m < watched_dir_count - 1; m++) {
                            watched_dirs[m] = watched_dirs[m + 1];
                            watch_descriptors[m] = watch_descriptors[m + 1];
                        }
                        watched_dir_count--;
                        watched_dirs = realloc(watched_dirs, watched_dir_count * sizeof(DirectoryConfig));
                        watch_descriptors = realloc(watch_descriptors, watched_dir_count * sizeof(int));
                        break;
                    }
                }
            }
            i += EVENT_SIZE + event->len;
        }

        time_t current_time = time(NULL);
        if (config->notification_config.notification_enabled && current_time - last_notification_check >= config->notification_config.min_interval_sec) {
            process_notifications(config);
            last_notification_check = current_time;
        }
    }

    free(tracked_files);
    free(watched_dirs);
    free(watch_descriptors);
    close(fd);
}