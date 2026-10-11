# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Maciej Gojny, GG Advanced IT Security UG
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Werror
# Shared oracle/encode headers (framework/oracle, framework/encode).
INC     := -I../../framework/oracle -I../../framework/encode
LDFLAGS ?=

.PHONY: all clean

all: spectre-v1-oneshot

spectre-v1-oneshot: spectre-v1-oneshot.c ../../framework/oracle/oracle.h ../../framework/encode/encode.h
	$(CC) $(CFLAGS) $(INC) -o $@ $< $(LDFLAGS)

clean:
	rm -f spectre-v1-oneshot
