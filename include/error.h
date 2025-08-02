// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.2.0 - Date: 2025/08/02
// License: CC BY-NC 4.0
// File: error.h
// Description: Declares error handling function for FIMon.

#ifndef ERROR_H
#define ERROR_H

// Logs an error message to stderr if verbose mode is enabled.
void handle_error(const char *message, int verbose);

#endif