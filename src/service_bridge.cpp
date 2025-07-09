// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: service_bridge.cpp
// Description: C bridge for running FIMon as a service.

#include "service.cpp"

extern "C" void run_as_service(const char *config_path, int daemon_mode) { // Bridge function for service.
    ServiceManager::installAndStart(config_path, daemon_mode != 0);
}
