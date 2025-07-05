# === Project Configuration ===
TARGET = FIMon
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g
RELEASE_FLAGS = -O2
DEBUG_FLAGS = -O0
LDFLAGS = -lssl -lcrypto -lcjson -lsqlite3 -lcurl

# === Directory Layout ===
SRCDIR = src
OBJDIR = obj
BINDIR = bin
INCLUDEDIR = include

# === Source Files ===
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

# === Default Target ===
all: release

# === Release Build ===
release: CFLAGS += $(RELEASE_FLAGS)
release: $(BINDIR)/$(TARGET)

# === Debug Build ===
debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(BINDIR)/$(TARGET)

# === Linking ===
$(BINDIR)/$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# === Object Compilation ===
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# === Directory Creation ===
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# === Clean Build ===
clean:
	rm -rf $(OBJDIR) $(BINDIR) logs/integrity.db *.pid

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

.PHONY: all release debug clean install-deps
