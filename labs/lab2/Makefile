CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
LDLIBS   ?= -lgmp
SRC      := src/sha512.cpp src/random.cpp src/numtheory.cpp src/rsa_core.cpp src/oaep.cpp

all: demo tests bench_crt
demo:  $(SRC) src/main.cpp   ; $(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)
tests: $(SRC) tests/tests.cpp ; $(CXX) $(CXXFLAGS) -Isrc $^ -o $@ $(LDLIBS)
bench_crt: $(SRC) tests/bench_crt.cpp ; $(CXX) $(CXXFLAGS) -Isrc $^ -o $@ $(LDLIBS)
check: tests ; ./tests
clean: ; rm -f demo tests bench_crt key.conf ct.bin
