# General

default: all

# REMEMBER TO MAKE CLEAN AFTER CHANGE ME!
STAGE  := week13
STAGES := week13 week14 week15

ifeq ($(filter $(STAGES), $(STAGE)), ) # STAGE must be valid
$(error Invalid STAGE. Supported: $(STAGES))
endif

CC = gcc
CFLAGS = -O1 -std=c11 -Wall -I./include -I./external/include
LDFLAGS = -L./external/lib -lnanomsg -lpthread -lcrypto

SRC_DIR = src
INC_DIR = include
EXT_DIR = external
BUILD_DIR = build
CONFIG_DIR = config

SRC_FILES = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(EXT_DIR)/$(SRC_DIR)/*.c)
TARGET = $(BUILD_DIR)/main

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	cp -r $(CONFIG_DIR)/ $(BUILD_DIR)/$(CONFIG_DIR)

$(TARGET): $(SRC_FILES)
	$(CC) $(CFLAGS) $(SRC_FILES) -o $(TARGET) $(LDFLAGS)

grade:
	grade/grade-$(STAGE)

auth:
	python3 ok --insecure --authenticate

submit:
	python3 ok --insecure --config okconfig/$(STAGE).ok --submit

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean grade auth submit