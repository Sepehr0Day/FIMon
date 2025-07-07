# FIMon - File Integrity Monitor 🛡️

FIMon is a lightweight file integrity monitoring system designed to detect changes in specified directories by tracking file hashes, sizes, and modification times. It supports MD5, SHA1, and SHA256 hashing algorithms, logs events in both text and JSON formats, and provides email notifications for detected changes. The system uses SQLite for persistent storage and supports configurable ignore patterns and tags for flexible monitoring. 🚀

## Features ✨
- Monitors filesystem changes in real-time or on-demand. 🕒
- Supports multiple hash algorithms (MD5, SHA1, SHA256). 🔒
- Logs events to text and JSON files. 📝
- Sends email notifications for detected changes (configurable). 📧
- Stores file metadata in a SQLite database. 🗄️
- Configurable ignore patterns and tags for directories. ⚙️
- Supports daemon mode for continuous monitoring. 🔄

## Installation 🛠️

### Prerequisites 📋
- C compiler (e.g., `gcc`)
- SQLite3 library (`libsqlite3-dev` or `sqlite-devel`)
- OpenSSL library (`libssl-dev` or `openssl-devel`)
- cJSON library (`libcjson-dev` or `cjson-devel`)
- libcurl library (`libcurl4-openssl-dev` or `libcurl-devel`)
- Linux-based system (Ubuntu/Debian or CentOS/RedHat) 🐧

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
   This command detects your system (Ubuntu/Debian or CentOS/RedHat) and installs the required packages:
   - For Ubuntu/Debian: `build-essential`, `libssl-dev`, `libcjson-dev`, `libsqlite3-dev`, `libcurl4-openssl-dev`
   - For CentOS/RedHat: `gcc`, `make`, `openssl-devel`, `cjson-devel`, `sqlite-devel`, `libcurl-devel`
3. Build the project:
   - To build the default release version:
     ```bash
     make
     ```
4. The compiled binary will be placed in the `bin/` directory as `bin/FIMon`. 🎉

### Cleaning Build Artifacts 🧹
To remove generated object files, binaries, and other artifacts (e.g., `logs/integrity.db`, `*.pid`):
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
  "smtp": {
    "host": "smtp.example.com",
    "port": 587,
    "username": "user@example.com",
    "password": "yourpassword"
  },
  "recipient": "admin@example.com",
  "min_interval_sec": 3600,
  "min_events": 1,
  "queue_path": "/var/fimon/queue.json",
  "archive_path": "/var/fimon/archive.json"
}
```

## Usage 🚀
Run FIMon with the following command:
```bash
./bin/FIMon --config config.json [--verbose] [--daemon]
```
- `--config <path>`: Path to the configuration file (required). 📄
- `--verbose`: Enable verbose logging. 🗣️
- `--daemon`: Run in daemon mode for continuous monitoring. 🔄

## Future Improvements 📅
- Add systemd service file for easy daemon setup. 🛠️
- Add terminal-friendly live log viewer. 📈
- Support sending alerts to Telegram. 📱
- Auto-backup files before changes (optional). 💾
- Improve CLI: add `--check` and `--status` options. 🖥️
- Write basic unit tests for hashing and config. ✅
- Log signature (hash) to detect tampering. 🔍
- Better error messages and logging clarity. 📣

## Wiki 📚
For detailed documentation, including architecture, configuration guides, troubleshooting, and development instructions, visit the [FIMon Wiki](https://github.com/Sepehr0Day/FIMon/wiki).

## License 📜
FIMon is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0). See the [LICENSE](LICENSE) file for details.

## Contributing 🤝
Contributions are welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute to this project.

## Contact 📬
For questions or support, open an issue on the [GitHub repository](https://github.com/Sepehr0Day/FIMon). 🌟
