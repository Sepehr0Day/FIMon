# FIMon - File Integrity Monitor 🛡️

FIMon is a lightweight, robust file integrity monitoring system designed to detect changes in specified directories by tracking file hashes, sizes, modification times, ownership, and permissions. It supports MD5, SHA1, and SHA256 hashing algorithms, logs events in both text and JSON formats, and provides email and Telegram notifications for detected changes. The system uses SQLite for persistent storage, supports configurable ignore patterns and tags for flexible monitoring, and can run as a systemd service for continuous operation. 🚀

## Features of FIMon

- **Real-time Monitoring**: Monitors filesystem changes using inotify for immediate detection.
- **Multiple Hash Algorithms**: Supports MD5, SHA1, and SHA256 for file integrity checks.
- **Comprehensive Logging**: Logs events to text and JSON files, with detailed metadata (hash, size, mtime, user, group, permissions).
- **Email Notifications**: Sends formatted HTML email alerts with event summaries and detailed tables.
- **Telegram Notifications**: Supports Telegram alerts with proxy and SSL configuration options.
- **SQLite Database**: Stores file metadata persistently for comparison and change tracking.
- **Configurable Ignore Patterns**: Excludes files or directories based on glob patterns (e.g., `.git/*`, `*.log`).
- **Directory Tagging**: Tags directories (e.g., `critical`, `non-critical`) to customize monitoring behavior.
- **Daemon Mode**: Runs continuously as a background process or systemd service.
- **Secure Configuration**: Enforces strict file permissions for logs, database, and configuration files.
- **Event Archiving**: Archives processed events to a JSON file for historical reference.
- **Database Backup**: Creates snapshot backups of the SQLite database.
- **Log Rotation & Tamper Detection**: Automatically rotates log files when they reach 1MB and generates a digital signature (`.sig` file) for tamper detection. Health checks will warn if logs are missing or tampered.
- **Health Check & Status Reporting**: Use `--check` to perform a full health check (permissions, disk space, signature, etc.) and `--status` to print current monitoring status and runtime info.
- **Static Build Support**: Builds a static binary using Docker for portability. 🐳

## Quick Use 🚀
- Download the pre-built static binary from:  
  [fimon-v1.2.0-linux-x86_64-static.zip](https://github.com/Sepehr0Day/FIMon/releases/download/v1.2.0/fimon-v1.2.0-linux-x86_64-static.zip)
- Unzip the downloaded file:
  ```bash
  unzip fimon-v1.2.0-linux-x86_64-static.zip
  ```
- Run the binary:
  ```bash
  ./fimon-v1.2.0-linux-x86_64-static --config config.json
  ```
  (Ensure a `config.json` file is present as per the Configuration section below.)

## Installation 🛠️

### Prerequisites 📋
- C/C++ compiler (`gcc`, `g++`)
- SQLite3 library (`libsqlite3-dev` or `sqlite-devel`)
- OpenSSL library (`libssl-dev` or `openssl-devel`)
- cJSON library (`libcjson-dev` or `cjson-devel`)
- libcurl library (`libcurl4-openssl-dev` or `libcurl-devel`)
- Linux-based system 🐧
- Optional: Docker for static builds

### Build Instructions 🔨
1. Clone the repository:
   ```bash
   git clone https://github.com/Sepehr0Day/FIMon.git
   cd FIMon
   ```
2. Install dependencies using the provided `Makefile`:
   ```bash
   make install-deps
   ```
   This command detects your system (Ubuntu/Debian or CentOS/RedHat) and installs required packages:
   - For Ubuntu/Debian: `build-essential`, `libssl-dev`, `libcjson-dev`, `libsqlite3-dev`, `libcurl4-openssl-dev`
   - For CentOS/RedHat: `gcc`, `make`, `openssl-devel`, `cjson-devel`, `sqlite-devel`, `libcurl-devel`
3. Build the project:
   - For a release build (optimized):
     ```bash
     make release
     ```
   - For a debug build (with debugging symbols):
     ```bash
     make debug
     ```
   - For a static build using Docker:
     ```bash
     make build-static
     ```
4. The compiled binary will be placed in the `bin/` directory as `fimon-v1.2.0-linux-x64` (or `bin/static/` for static builds). 🎉

### Cleaning Build Artifacts 🧹
To remove generated object files, binaries, and other artifacts:
```bash
make clean
```

## Configuration ⚙️
Create a JSON configuration file (e.g., `config.json`) with the following structure:

```json
{
  "directories": [
    {
      "path": "/path/to/monitor",
      "hash_type": "sha256",
      "ignore_patterns": [".git/*", "*.log"],
      "tags": ["critical", "production"]
    }
  ],
  "log_path": "/var/log/fimon.log",
  "json_log_path": "/var/log/fimon.json",
  "db_path": "/var/fimon/fimon.db",
  "notification": true,
  "notification_settings": {
    "email": {
      "enabled": true,
      "smtp": {
        "host": "smtp.example.com",
        "port": 587,
        "username": "user@example.com",
        "password": "yourpassword",
        "use_tls": true
      },
      "recipient": ["admin@example.com", "user@example.com"]
    },
    "telegram": {
      "enabled": true,
      "bot_token": "your_bot_token",
      "chat_id": ["chat_id_1", "chat_id_2"],
      "SSL": true,
      "proxy": {
        "enabled": true,
        "type": "http",
        "host": "127.0.0.1",
        "port": 2300,
        "username": "proxy_user",
        "password": "proxy_password"
      }
    },
    "min_interval_sec": 300,
    "min_events": 1,
    "queue_path": "/var/fimon/queue.json",
    "archive_path": "/var/fimon/archive.json"
  },
  "backup": {
    "enabled": true,
    "interval_sec": 3600,
    "paths": ["/path/to/monitor"],
    "notification": {
      "telegram": {
        "enabled": true,
        "chat_id": ["chat_id_1"]
      }
    }
  }
}
```
Ensure the configuration file and logs have secure permissions (`chmod 600`).

## Backup & Scheduled Delivery 📦

FIMon can periodically create zipped backups of monitored files or folders and deliver them via email or Telegram.

### Backup Configuration Example

Add a `backup` section to your config:

```json
  "backup": {
    "enabled": true,
    "interval_sec": 3600,
    "paths": ["/path/to/monitor"],
    "notification": {
      "telegram": {
        "enabled": true,
        "chat_id": ["chat_id_1"]
      }
    }
  }
```

- `enabled`: Enable or disable scheduled backup.
- `interval_sec`: How often to perform backup (in seconds).
- `paths`: List of files or folders to backup (zipped together).
- `method`: `"telegram"` (delivery method).
- `recipients`: List of email addresses or Telegram chat IDs.

Backups are zipped and sent as attachments via the chosen method.

## Wiki 📚
For detailed documentation, including architecture, configuration guides, troubleshooting, and development instructions, visit the [FIMon Wiki](https://github.com/Sepehr0Day/FIMon/wiki).

## Usage 🚀
Run FIMon with the following command:
```bash
./fimon-v1.2.0-linux-x86_64-static --config <path> [--verbose] [--daemon] [--run-as-service] [--check] [--status]
```
- `--config <path>`: Path to the configuration file (required). 📄
- `--verbose`: Enable verbose logging to stdout. 🗣️
- `--daemon`: Run in daemon mode for continuous monitoring. 🔄
- `--run-as-service`: Install and start FIMon as a systemd service. 🛠️
-  `--check`: Perform health check ✅
-  `--status`: Print FIMon status 📈

### Running as a Systemd Service
To run FIMon as a systemd service:
```bash
./fimon-v1.2.0-linux-x86_64-static --config config.json --run-as-service
```
This creates and enables a systemd service file at `/etc/systemd/system/fimon.service` and starts the service.

## License 📜
FIMon is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0). See the [LICENSE](LICENSE) file for details.

## Contributing 🤝
Contributions are welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute to this project.

## Security 🔐
For security-related issues, please refer to the [SECURITY.md](SECURITY.md) file for instructions on reporting vulnerabilities.

## Contact 📬

For questions or support, open an issue on the [GitHub repository](https://github.com/Sepehr0Day/FIMon). 🌟
