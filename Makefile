# use GNU standard variable names: https://www.gnu.org/prep/standards/html_node/Directory-Variables.html
DESTDIR :=
prefix := /usr/local
exec_prefix := $(prefix)
bindir := $(exec_prefix)/bin

.PHONY: all
all: target

target: cmd/*/*.go */*.go */*/*.go
	env GOBIN=$(PWD)/target go install ./cmd/...
	touch target

# copy them to /usr/local/bin - normally run with sudo
.PHONY: install
install: all
	cp -t "$(DESTDIR)${bindir}" target/*

.PHONY: clean
clean:
	git clean -xfd

.PHONY: test

test:
	go test ./...
