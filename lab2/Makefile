CXX := c++
# pkg-config в PATH может указать на x86_64 OpenSSL из /usr/local.
# На Apple Silicon берём arm64-сборку Homebrew, если она установлена.
OPENSSL_PREFIX := $(shell if [ "$$(uname -m)" = arm64 ] && [ -d /opt/homebrew/opt/openssl@3 ]; then echo /opt/homebrew/opt/openssl@3; else dirname $$(dirname $$(pkg-config --variable=libdir libcrypto)); fi)
OPENSSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
OPENSSL_LIBS := -L$(OPENSSL_PREFIX)/lib -lcrypto
OPENSSL_LIBDIR := $(OPENSSL_PREFIX)/lib

CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Iinclude $(OPENSSL_CFLAGS)
LDFLAGS := $(OPENSSL_LIBS) -Wl,-rpath,$(OPENSSL_LIBDIR)

SRCS := src/sha256.cpp src/rsa_math.cpp src/rsa_core.cpp src/oaep.cpp src/main.cpp

.PHONY: all clean run

all: lab2

lab2: $(SRCS) include/sha256.hpp include/rsa_math.hpp include/rsa_core.hpp include/oaep.hpp
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(LDFLAGS)

run: lab2
	./lab2

clean:
	rm -f lab2
