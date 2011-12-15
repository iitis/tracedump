CC ?= gcc
AR ?= ar
ME ?= $(shell basename `pwd`)
PWD ?= $(shell pwd)

CFLAGS += -std=gnu99 -g -Wall -pedantic -fPIC -Dinline='inline __attribute__ ((gnu_inline))' $(CFLAGS_ADD)
LDFLAGS += -Wall -pedantic $(LDFLAGS_ADD)

ifneq (,$(shell ls ~/local 2>/dev/null))
CFLAGS += -I$(shell echo ~)/local/include
LDFLAGS += -L$(shell echo ~)/local/lib
PCPATH = $(shell echo ~)/local/lib/pkgconfig
endif

ifneq (,$(CFLAGS_PKGS))
CFLAGS += $(shell PKG_CONFIG_PATH=$(PCPATH) pkg-config $(CFLAGS_PKGS) --cflags)
LDFLAGS += $(shell PKG_CONFIG_PATH=$(PCPATH) pkg-config $(CFLAGS_PKGS) --libs)
endif

# for make install
PREFIX ?= /usr
PKGDST = $(DESTDIR)$(PREFIX)

# for make version.h
GITVER = $(shell git describe 2>/dev/null)
TARVER = $(shell cat VERSION 2>/dev/null)
ifneq (,$(GITVER))
VERSION ?= $(GITVER)
else
VERSION ?= $(TARVER)
endif

default: all
all: version.h $(TARGETS)

clean-std:
	-rm -f *.o $(TARGETS) *.core core version.h

.SUFFIXES: .c

.c.o:
	$(CC) $(CFLAGS) -c $<

doc:
	-rm -fr doc
	mkdir -p doc
	doxygen doxygen.conf

version.h:
	@echo '#define VERSION "$(VERSION)"' >$@

install-std: all
	install -m 755 -d $(PKGDST)/include/$(ME)
	install -m 644 *.h $(PKGDST)/include/$(ME)
	install -m 755 -d $(PKGDST)/lib
	for i in $(TARGETS); do \
		[ "$${i##*.}" = "so" ] && install -m 755 $$i $(PKGDST)/lib; \
		[ "$${i##*.}" = "a" ]  && install -m 644 $$i $(PKGDST)/lib; \
	done || true
	install -m 755 -d $(PKGDST)/bin
	for i in $(TARGETS); do test "$${i##*.}" = "$$i" && install -m 755 $$i $(PKGDST)/bin; done || true

install-lns: all
	mkdir -m 755 -p $(PKGDST)/include/$(ME)
	mkdir -m 755 -p $(PKGDST)/lib/$(ME)
	-sh -c "ln -s $(PWD)/*.h $(PKGDST)/include/$(ME)/"
	for i in $(TARGETS); do \
		[ "$${i##*.}" = "so" ] && ln -s $(PWD)/$$i $(PKGDST)/lib/; \
		[ "$${i##*.}" = "a" ]  && ln -s $(PWD)/$$i $(PKGDST)/lib/; \
	done || true
	mkdir -m 755 -p $(PKGDST)/bin
	for i in $(TARGETS); do \
		[ "$${i##*.}" = "$$i" ] && ln -s $(PWD)/$$i $(PKGDST)/bin/;\
	done || true

.PHONY: version.h doc
