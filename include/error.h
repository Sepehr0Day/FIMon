// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: error.h
// Description: Declares error handling function.

#ifndef ERROR_H
#define ERROR_H

// Logs an error message to stderr if verbose mode is enabled.
void handle_error(const char *message, int verbose);

#endif