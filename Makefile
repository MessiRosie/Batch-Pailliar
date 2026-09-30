GMP_INC ?= /opt/homebrew/include
GMP_LIB ?= /opt/homebrew/lib
CXX ?= g++
CXXFLAGS := -std=c++17 -O3 -fPIC -Wall -Wextra

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LIB := src/paillier_crypto/libpaillier.dylib
	SOFLAGS := -dynamiclib
else
	LIB := src/paillier_crypto/libpaillier.so
	SOFLAGS := -shared
endif

all: $(LIB)

$(LIB): src/cpp/paillier.cpp src/cpp/api.cpp src/cpp/paillier.h
	mkdir -p src/paillier_crypto
	$(CXX) $(CXXFLAGS) $(SOFLAGS) -I$(GMP_INC) src/cpp/paillier.cpp src/cpp/api.cpp -L$(GMP_LIB) -lgmp -o $(LIB)

clean:
	rm -f src/paillier_crypto/libpaillier.dylib src/paillier_crypto/libpaillier.so

.PHONY: all clean
