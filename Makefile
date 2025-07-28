SHELL := /bin/bash

# Loads env vars from .env if present
ifneq (,$(wildcard .env))
    include .env
    export
endif

DEMO_DIR = demo_app
DEMO_MAIN = $(DEMO_DIR)/main.go
DEMO_BIN = oidc-demo

# OIDC Provider Selection: "kc" or "entra" (default: kc)
OIDC_PROVIDER ?= kc

.PHONY: all setup build clean demo

all: build

setup:
	echo "# OIDC demo .env template" > .env.tmp
	echo "OIDC_PROVIDER=kc" >> .env.tmp
	echo "KC_ENDPOINT=http://localhost:8080" >> .env.tmp
	echo "ENTRA_TENANT_ID=your-tenant-id" >> .env.tmp
	echo "ENTRA_CLIENT_ID=your-client-id" >> .env.tmp
	echo "ENTRA_CLIENT_SECRET=your-client-secret" >> .env.tmp
	mv .env.tmp .env
	echo "Edit .env to match your environment."

build:
	@echo "Building demo..."
	go build -o $(DEMO_DIR)/$(DEMO_BIN) $(DEMO_MAIN)

clean:
	rm -f $(DEMO_DIR)/$(DEMO_BIN)

demo: build
	@echo "Running demo app using .env config (OIDC_PROVIDER=$(OIDC_PROVIDER))..."
	set -o allexport; source .env 2>/dev/null || true; $(DEMO_DIR)/$(DEMO_BIN)
