// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: error.c
// Description: Handles error reporting for FIMon, printing messages to stderr if verbose is enabled.

#include <stdio.h>
#include <stdlib.h>
#include "error.h"

// Print error message if verbose is enabled.
void handle_error(const char *message, int verbose) {
    if (verbose) {
        fprintf(stderr, "ERROR: %s\n", message);
    }
}