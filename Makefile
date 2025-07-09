# Project: FIMon (File Integrity Monitor)
# GitHub: https://github.com/Sepehr0Day/FIMon
# Version: 1.1.0 - Date: 09/07/2025
# License: CC BY-NC 4.0
# File: Makefile
# Description: Build system for FIMon.

# === Project Configuration ===
VERSION = 1.1.0
TARGET = FIMon
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -Iinclude -g
CXXFLAGS = -Wall -Wextra -Iinclude -g
RELEASE_FLAGS = -O2
DEBUG_FLAGS = -O0
LDFLAGS = -lssl -lcrypto -lsqlite3 -lcurl

# === Directory Layout ===
SRCDIR = src
OBJDIR = obj
BINDIR = bin
INCLUDEDIR = include

# === Source Files ===
SOURCES = $(wildcard $(SRCDIR)/*.c)
CXXSOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
CXXOBJECTS = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(CXXSOURCES))

# === Default Target ===
all: release

# === Release Build ===
release: CFLAGS += $(RELEASE_FLAGS)
release: CXXFLAGS += $(RELEASE_FLAGS)
release: $(BINDIR)/fimon-v$(VERSION)-linux-$(shell uname -m | sed 's/x86_64/x64/;s/i.86/x86/')

# === Debug Build ===
debug: CFLAGS += $(DEBUG_FLAGS)
debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: $(BINDIR)/fimon-v$(VERSION)-linux-$(shell uname -m | sed 's/x86_64/x64/;s/i.86/x86/')

# === Linking ===
$(BINDIR)/fimon-v$(VERSION)-linux-$(shell uname -m | sed 's/x86_64/x64/;s/i.86/x86/'): $(OBJECTS) $(CXXOBJECTS) | $(BINDIR)
	$(CXX) $(OBJECTS) $(CXXOBJECTS) -o $@ $(LDFLAGS)

# === Object Compilation ===
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# === Directory Creation ===
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# === Clean Build ===
clean:
	rm -rf $(OBJDIR) $(BINDIR) 

# === Dependency Installer (Ubuntu / CentOS) ===
install-deps:
	@echo "Detecting system and installing dependencies..."
	@if [ -f /etc/debian_version ]; then \
		echo "Detected Ubuntu/Debian"; \
		sudo apt update && sudo apt install -y build-essential libssl-dev libcjson-dev libsqlite3-dev libcurl4-openssl-dev; \
	elif [ -f /etc/redhat-release ]; then \
		echo "Detected CentOS/RedHat"; \
		sudo yum install -y gcc make openssl-devel cjson-devel sqlite-devel libcurl-devel; \
	else \
		echo "Unsupported system. Please install dependencies manually."; \
	fi

# === Static Build (Docker) ===
build-static:
	docker build -t fimon:latest .
	docker rm -f fimon-tmp 2>/dev/null || true
	docker create --name fimon-tmp fimon:latest
	mkdir -p $(BINDIR)/static
	docker cp fimon-tmp:/app/bin/fimon-v$(VERSION)-linux-x86_64-static $(BINDIR)/static/fimon-v$(VERSION)-linux-x86_64-static
	docker rm fimon-tmp
	$(MAKE) release
	cd $(BINDIR)/static && zip fimon-v$(VERSION)-linux-x86_64-static.zip fimon-v$(VERSION)-linux-x86_64-static

.PHONY: all release debug clean install-deps build-static
