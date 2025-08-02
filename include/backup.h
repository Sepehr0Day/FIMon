// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: backup.h
// Description: Declares backup function for FIMon, supporting backup creation and notification.

#ifndef BACKUP_H
#define BACKUP_H

#include "config.h"

// Performs backup and sends via email or telegram as configured.
int perform_backup(const Config *config, int verbose);

#endif
