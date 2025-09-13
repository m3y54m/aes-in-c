# Compiler and flags
# Use gcc by default (use `make CC=clang` or edit this file to override)
CC := gcc
STD ?= -std=c17
CFLAGS ?= $(STD) -Wall -Wextra -Wpedantic -Wshadow -Wconversion -g
LDFLAGS ?=

# Project layout
SOURCE_DIR ?= src
BUILD_DIR ?= build
TARGET ?= $(BUILD_DIR)/aes

# Platform-specific command snippets (avoid shell conditionals in recipes)
ifeq ($(OS),Windows_NT)
RM_CMD = if exist "$(BUILD_DIR)" rmdir /S /Q "$(BUILD_DIR)"
MKDIR_CMD = if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
else
RM_CMD = rm -rf $(BUILD_DIR)
MKDIR_CMD = mkdir -p $(BUILD_DIR)
endif

# Sources and objects
SRCS := $(wildcard $(SOURCE_DIR)/*.c)
OBJS := $(patsubst $(SOURCE_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all help clean release debug

all: $(TARGET)

# Ensure build directory exists
$(BUILD_DIR):
	$(MKDIR_CMD)

# Compile C files to object files placed in $(BUILD_DIR)
$(BUILD_DIR)/%.o: $(SOURCE_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

release: CFLAGS = $(STD) -O2 -Wall -Wextra
release: clean all

debug: CFLAGS = $(STD) -g -O0 -Wall -Wextra -Wpedantic
debug: clean all

clean:
	$(RM_CMD)

help:
	@echo "Usage: make [target] [VARIABLE=value]"
	@echo
	@echo "Targets:"
	@echo "  all (default)    Build the program"
	@echo "  release          Build with optimizations"
	@echo "  debug            Build with debug flags"
	@echo "  clean            Remove build artifacts"
	@echo "  help             Show this help" 
	@echo
	@echo "Common variables (can be overridden):"
	@echo "  CC=$(CC)"
	@echo "  CFLAGS=$(CFLAGS)"
	@echo "  STD=$(STD)"
	@echo "  BUILD_DIR=$(BUILD_DIR)"
	@echo
	@echo "Example: make release CC=clang CFLAGS='-O3 -march=native'"