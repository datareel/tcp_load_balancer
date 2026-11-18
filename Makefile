# DRLB TCP load balancer
#
# make            build drlb_server
# make asan       build drlb_server_asan with AddressSanitizer for testing
# make test       run the regression tests (PYTHON=python3.11 on RHEL 8)
# make install    install into DESTDIR (default /), used by the RPM build
#
# OpenSSL 3.5 or later (openssl-devel) is required. Older headers stop
# the build (src/tls.cpp) and an older library stops the program at start.
#
# OPENSSL_PREFIX=/path  build against an OpenSSL 3.5 install that is not
#                       the system one (adds -I, -L and a matching rpath).
#                       RHEL 8 builds normally use the RHEL 8.10 system
#                       OpenSSL 3.5 and leave this unset.
# make openssl-check    print the OpenSSL headers version used

CXX      ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -pthread
LDFLAGS  ?=
LDLIBS   += -lssl -lcrypto -pthread

OPENSSL_PREFIX ?=
ifneq ($(OPENSSL_PREFIX),)
OPENSSL_LIBDIR := $(firstword $(wildcard $(OPENSSL_PREFIX)/lib64 $(OPENSSL_PREFIX)/lib))
ifeq ($(OPENSSL_LIBDIR),)
$(error OPENSSL_PREFIX=$(OPENSSL_PREFIX) has no lib64 or lib directory)
endif
CXXFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS  += -L$(OPENSSL_LIBDIR) -Wl,-rpath,$(OPENSSL_LIBDIR)
endif

# GCC 8 (RHEL 8) keeps std::filesystem in a separate library
GCC_MAJOR := $(shell $(CXX) -dumpversion 2>/dev/null | cut -d. -f1)
ifeq ($(GCC_MAJOR),8)
LDLIBS   += -lstdc++fs
endif

PYTHON   ?= python3
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
	$(PYTHON) tests/drlb_tests.py $(CURDIR)/drlb_server
	$(PYTHON) tests/ssl_bridge_tests.py $(CURDIR)/drlb_server
	$(PYTHON) tests/compat_tests.py $(CURDIR)/drlb_server
	$(PYTHON) tests/pqc_tests.py $(CURDIR)/drlb_server

# Print the OpenSSL version of the headers the build uses; fails below 3.5
openssl-check:
	@printf '#include <openssl/opensslv.h>\n#if OPENSSL_VERSION_NUMBER < 0x30500000L\n#error OpenSSL headers older than 3.5\n#endif\nOPENSSL_VERSION_TEXT\n' | \
	  $(CXX) $(filter -I%,$(CXXFLAGS)) -E -P -x c++ - | tail -1

install: drlb_server
	install -D -m 0755 drlb_server $(DESTDIR)$(SBINDIR)/drlb_server
	ln -sf drlb_server $(DESTDIR)$(SBINDIR)/drlb_ssl_server

clean:
	rm -rf build drlb_server drlb_server_asan

.PHONY: all asan test install clean openssl-check
