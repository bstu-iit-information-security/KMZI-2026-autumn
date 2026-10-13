CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -I.
LDLIBS   ?= -lcrypto -lbcrypt

SRC := common.cpp number_theory.cpp rsa_core.cpp oaep.cpp main.cpp
OBJ := $(SRC:.cpp=.o)
BIN := rsa_oaep_lab

all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

run: $(BIN)
	@mkdir -p reports
	./$(BIN)

clean:
	rm -f $(OBJ) $(BIN)
	rm -rf reports