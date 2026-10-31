# DRLB TCP load balancer
#
# make            build drlb_server
# make asan       build drlb_server_asan with AddressSanitizer for testing
# make test       run the regression tests
# make install    install into DESTDIR (default /), used by the RPM build
#
# OpenSSL headers from openssl-devel are required.

CXX      ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -pthread
LDFLAGS  ?=
LDLIBS   += -lssl -lcrypto -pthread

# GCC 8 (RHEL 8) keeps std::filesystem in a separate library
GCC_MAJOR := $(shell $(CXX) -dumpversion 2>/dev/null | cut -d. -f1)
ifeq ($(GCC_MAJOR),8)
LDLIBS   += -lstdc++fs
endif

PREFIX   ?= /usr
SBINDIR  ?= $(PREFIX)/sbin
DESTDIR  ?=

SRCS = $(wildcard src/*.cpp)
OBJS = $(SRCS:src/%.cpp=build/%.o)
ASAN_OBJS = $(SRCS:src/%.cpp=build/asan/%.o)

all: drlb_server

drlb_server: $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.cpp src/drlb.h | build
	$(CXX) $(CXXFLAGS) -c -o $@ $<

asan: drlb_server_asan

drlb_server_asan: $(ASAN_OBJS)
	$(CXX) $(CXXFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/asan/%.o: src/%.cpp src/drlb.h | build/asan
	$(CXX) $(CXXFLAGS) -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -c -o $@ $<

build build/asan:
	mkdir -p $@

test: drlb_server
	python3 tests/drlb_tests.py $(CURDIR)/drlb_server
	python3 tests/ssl_bridge_tests.py $(CURDIR)/drlb_server
	python3 tests/compat_tests.py $(CURDIR)/drlb_server

install: drlb_server
	install -D -m 0755 drlb_server $(DESTDIR)$(SBINDIR)/drlb_server
	ln -sf drlb_server $(DESTDIR)$(SBINDIR)/drlb_ssl_server

clean:
	rm -rf build drlb_server drlb_server_asan

.PHONY: all asan test install clean
