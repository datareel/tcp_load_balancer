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
# RHEL 8 has two packages, like DRCM 1.49:
#   drlb_server            make FIPS_BUILD=1: the RHEL 8 system OpenSSL
#                          1.1.1 (FIPS 140 validated by Red Hat), classic
#                          TLS, groups from the system crypto policy
#   drlb_server-openssl35  make OPENSSL_PREFIX=/opt/openssl-3.5 OPENSSL_STATIC=1:
#                          OpenSSL 3.5 built in statically
#                          (build/build_openssl35.sh), post-quantum TLS
#
# FIPS_BUILD=1          allow the system OpenSSL 1.1.1 (RHEL 8 FIPS build
#                       only); every other build needs OpenSSL 3.5.
# OPENSSL_PREFIX=/path  build against an OpenSSL 3.5 install that is not
#                       the system one: with OPENSSL_STATIC=1 link its
#                       libssl.a and libcrypto.a (no rpath, nothing to
#                       install on the hosts), else -L and an rpath.
# OPENSSL_PKG=name      build against a pkg-config package, for example
#                       the EPEL openssl3-devel on RHEL 8 (optional; not
#                       a shipped package).
# make openssl-check    print the OpenSSL headers version used

CXX      ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++17 -Wall -Wextra -pthread
LDFLAGS  ?=
OPENSSL_PKG ?=
OPENSSL_PREFIX ?=
OPENSSL_STATIC ?= 0
FIPS_BUILD ?= 0
OPENSSL_FLAVOR := system

ifeq ($(FIPS_BUILD),1)
CXXFLAGS += -DDRLB_FIPS_BUILD
endif

ifneq ($(OPENSSL_PKG),)
ifneq ($(shell pkg-config --exists $(OPENSSL_PKG) && echo yes),yes)
$(error pkg-config package $(OPENSSL_PKG) not found, install its -devel package)
endif
CXXFLAGS += $(shell pkg-config --cflags $(OPENSSL_PKG))
LDFLAGS  += $(shell pkg-config --libs-only-L $(OPENSSL_PKG))
OPENSSL_FLAVOR := custom
endif

ifneq ($(OPENSSL_PREFIX),)
OPENSSL_LIBDIR := $(firstword $(wildcard $(OPENSSL_PREFIX)/lib64 $(OPENSSL_PREFIX)/lib))
ifeq ($(OPENSSL_LIBDIR),)
$(error OPENSSL_PREFIX=$(OPENSSL_PREFIX) has no lib64 or lib directory)
endif
CXXFLAGS += -I$(OPENSSL_PREFIX)/include
ifeq ($(OPENSSL_STATIC),1)
LDLIBS   += $(OPENSSL_LIBDIR)/libssl.a $(OPENSSL_LIBDIR)/libcrypto.a -ldl -pthread
OPENSSL_FLAVOR := static
else
LDFLAGS  += -L$(OPENSSL_LIBDIR) -Wl,-rpath,$(OPENSSL_LIBDIR)
OPENSSL_FLAVOR := custom
endif
endif
ifneq ($(OPENSSL_FLAVOR),static)
LDLIBS   += -lssl -lcrypto -pthread
endif
CXXFLAGS += -DDRLB_OPENSSL_FLAVOR='"$(OPENSSL_FLAVOR)"'

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
	$(PYTHON) tests/mux_tests.py $(CURDIR)/drlb_server

# Print the OpenSSL version of the headers the build uses; fails below 3.5
openssl-check:
	@printf '#include <openssl/opensslv.h>\n#if OPENSSL_VERSION_NUMBER < $(if $(filter 1,$(FIPS_BUILD)),0x10101000L,0x30500000L)\n#error OpenSSL headers too old\n#endif\nOPENSSL_VERSION_TEXT\n' | \
	  $(CXX) $(filter -I%,$(CXXFLAGS)) -E -P -x c++ - | tail -1

install: drlb_server
	install -D -m 0755 drlb_server $(DESTDIR)$(SBINDIR)/drlb_server
	ln -sf drlb_server $(DESTDIR)$(SBINDIR)/drlb_ssl_server

clean:
	rm -rf build drlb_server drlb_server_asan

.PHONY: all asan test install clean openssl-check
