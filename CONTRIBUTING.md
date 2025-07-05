// Project: FIMon (File Integrity Monitor)
// GitHub: https://github.com/Sepehr0Day/FIMon
// Version: 1.0 - Date: 05/07/2025
// License: CC BY-NC 4.0
// File: CONTRIBUTING.md
// Description: Outlines guidelines for contributing to the FIMon project, including how to submit issues, pull requests, and coding standards.

# Contributing to FIMon

Thank you for your interest in contributing to FIMon! This document outlines the guidelines for contributing to the project. Please read through carefully to ensure a smooth collaboration process.

## How to Contribute

### Reporting Issues
- Check the [GitHub Issues](https://github.com/Sepehr0Day/FIMon/issues) page to ensure the issue hasn't already been reported.
- Open a new issue with a clear title and detailed description, including steps to reproduce, expected behavior, and actual behavior.
- Include relevant logs or screenshots if applicable.

### Submitting Pull Requests
1. Fork the repository and create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes, ensuring they adhere to the coding standards below.
3. Test your changes thoroughly.
4. Commit your changes with a descriptive commit message:
   ```bash
   git commit -m "Add feature: description of changes"
   ```
5. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
6. Open a pull request against the `main` branch of the repository, providing a clear description of your changes and referencing any related issues.

## Coding Standards
- Use C99 standard for all C code.
- Follow consistent naming conventions (e.g., `camelCase` for variables, `UPPER_CASE` for constants).
- Include brief comments above each function describing its purpose.
- Ensure proper error handling and memory management.
- Format code using a consistent style (e.g., 4-space indentation, no tabs).
- Avoid hardcoding paths or values; use configuration files where possible.

## Development Setup
- Install dependencies: `libsqlite3-dev`, `libssl-dev`, `libcurl4-openssl-dev`, and `cJSON`.
- Build the project using the provided `Makefile`.
- Test changes in a Linux environment.

## Code of Conduct
- Be respectful and inclusive in all interactions.
- Avoid offensive language or behavior.
- Collaborate constructively and provide feedback politely.

## Security Contributions
If you discover a security vulnerability, please follow the guidelines in the [SECURITY.md](SECURITY.md) file to report it responsibly.

## Questions
For any questions, feel free to open an issue or contact the maintainers via the [GitHub repository](https://github.com/Sepehr0Day/FIMon).