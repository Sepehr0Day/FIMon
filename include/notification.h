// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: notification.h
// Description: Notification interface header for FIMon, providing backup file sending interface.

#ifdef __cplusplus
extern "C" {
#endif

int send_file(const NotificationConfig *notif_config, const char *subject, const char *body_html, const char *filepath);

#ifdef __cplusplus
}
#endif
