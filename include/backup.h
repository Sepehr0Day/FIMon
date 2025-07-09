// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: backup.h
// Description: Declares backup function for FIMon.

#ifndef BACKUP_H
#define BACKUP_H

#include "config.h"

// Performs backup and sends via email if enabled.
int perform_backup(const Config *config, int verbose);

#endif
