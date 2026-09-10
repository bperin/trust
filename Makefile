SKILLS_HOME ?= $(HOME)/.agents/skills
VENDORED_SKILLS_DIR := .agents/skills
REQUIRED_SKILLS := \
  go-systems-programmer \
  go-security-expert \
  go-memory-oom-guard \
  go-code-review \
  golang-security \
  golang-testing \
  golang-code-style \
  golang-error-handling \
  golang-concurrency \
  golang-performance \
  wycheproof \
  implementing-digital-signatures-with-ed25519 \
  ethereum

.PHONY: all skills build build-all test vet

all: skills build

skills:
	@mkdir -p $(VENDORED_SKILLS_DIR)
	@for skill in $(REQUIRED_SKILLS); do \
	  if [ ! -d "$(SKILLS_HOME)/$$skill" ]; then \
	    echo "missing skill: $(SKILLS_HOME)/$$skill"; \
	    exit 1; \
	  fi; \
	  rm -rf "$(VENDORED_SKILLS_DIR)/$$skill"; \
	  cp -R "$(SKILLS_HOME)/$$skill" "$(VENDORED_SKILLS_DIR)/$$skill"; \
	  echo "vendored $$skill"; \
	done

build:
	cd trust && go build ./...
	cd auth && go build ./...
	cd chain && go build ./...

build-all: skills build

test:
	cd trust && go test ./...
	cd auth && go test ./...
	cd chain && go test ./...

vet:
	cd trust && go vet ./...
	cd auth && go vet ./...
	cd chain && go vet ./...
