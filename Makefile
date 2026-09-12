SKILLS_HOME ?= $(HOME)/.agents/skills
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

.PHONY: all build build-all test vet check-skills

all: build

build:
	cd trust && go build ./...
	cd auth && go build ./...
	cd chain && go build ./...

build-all: build

test:
	cd trust && go test ./...
	cd auth && go test ./...
	cd chain && go test ./...

vet:
	cd trust && go vet ./...
	cd auth && go vet ./...
	cd chain && go vet ./...

check-skills:
	@for skill in $(REQUIRED_SKILLS); do \
	  if [ ! -d "$(SKILLS_HOME)/$$skill" ]; then \
	    echo "missing skill: $(SKILLS_HOME)/$$skill"; \
	    exit 1; \
	  fi; \
	  echo "found $$skill"; \
	done
