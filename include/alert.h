// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.0 - Date: 05/07/2025
// License: CC BY-NC 4.0
// File: alert.h
// Description: Declares functions for logging filesystem events in text and JSON formats.

#ifndef ALERT_H
#define ALERT_H

#include <cJSON.h>
#include "types.h"

// Logs a text-based event with a timestamp to a specified log file and prints to stdout if verbose mode is enabled.
void log_event(const char *log_path, const char *message, int verbose);

// Logs a JSON-formatted event to a file, appends to a notification queue, and writes detailed logs to a fixed integrity log file.
void log_event_json(const char *json_log_path, const char *event_type, const char *path, 
                   const char *details, int verbose);
#endif