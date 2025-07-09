// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.1.0 - Date: 09/07/2025
// License: CC BY-NC 4.0
// File: service.cpp
// Description: Implements systemd service management for FIMon.

#include <fstream>
#include <iostream>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

class ServiceManager {
public:
    // Returns the path to the systemd service file.
    static std::string getServiceFilePath() {
        return "/etc/systemd/system/fimon.service";
    }
    // Returns the executable path.
    static std::string getExecPath() {
        char buf[4096];
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            return std::string(buf);
        }
        return "/usr/local/bin/fimon";
    }
    // Creates the systemd service file.
    static bool createServiceFile(const std::string& configPath, bool daemonMode) {
        std::ofstream ofs(getServiceFilePath());
        if (!ofs) return false;
        ofs << "[Unit]\n";
        ofs << "Description=FIMon - File Integrity Monitor Daemon\n";
        ofs << "After=network.target\n\n";
        ofs << "[Service]\n";
        ofs << "Type=simple\n";
        ofs << "ExecStart=" << getExecPath()
            << " --config " << configPath
            << (daemonMode ? " --daemon" : "")
            << "\n";
        ofs << "Restart=on-failure\n";
        ofs << "User=root\n";
        ofs << "Group=root\n\n";
        ofs << "[Install]\n";
        ofs << "WantedBy=multi-user.target\n";
        ofs.close();
        return true;
    }
    // Enables the systemd service.
    static bool enableService() {
        return system("systemctl enable fimon.service") == 0;
    }
    // Starts the systemd service.
    static bool startService() {
        return system("systemctl restart fimon.service") == 0;
    }
    // Disables the systemd service.
    static bool disableService() {
        return system("systemctl disable fimon.service") == 0;
    }
    // Removes the systemd service file.
    static bool removeServiceFile() {
        return system(("rm -f " + getServiceFilePath()).c_str()) == 0;
    }
    // Installs and starts the systemd service.
    static void installAndStart(const std::string& configPath, bool daemonMode) {
        if (!createServiceFile(configPath, daemonMode)) {
            std::cerr << "Failed to create systemd service file.\n";
            exit(1);
        }
        #if defined(__GNUC__) || defined(__clang__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wunused-result"
        #endif
        system("systemctl daemon-reload");
        #if defined(__GNUC__) || defined(__clang__)
        #pragma GCC diagnostic pop
        #endif
        if (!enableService()) {
            std::cerr << "Failed to enable systemd service.\n";
            exit(1);
        }
        if (!startService()) {
            std::cerr << "Failed to start systemd service.\n";
            exit(1);
        }
        std::cout << "FIMon systemd service installed and started.\n";
        exit(0);
    }
};
