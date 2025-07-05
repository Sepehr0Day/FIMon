// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.0 - Date: 05/07/2025
// License: CC BY-NC 4.0
// File: error.c
// Description: Provides error handling functionality for FIMon by logging error messages to stderr when verbose mode is enabled.

#include <stdio.h>
#include <stdlib.h>
#include "error.h"

// Logs an error message to stderr if verbose mode is enabled.
void handle_error(const char *message, int verbose) {
    if (verbose) {
        fprintf(stderr, "ERROR: %s\n", message);
    }
}