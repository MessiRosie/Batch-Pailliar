GMP_INC ?= /opt/homebrew/include
GMP_LIB ?= /opt/homebrew/lib
CXX ?= g++
CXXFLAGS := -std=c++17 -O3 -fPIC -Wall -Wextra

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LIB := src/batch_paillier/libpaillier.dylib
	SOFLAGS := -dynamiclib
else
	LIB := src/batch_paillier/libpaillier.so
	SOFLAGS := -shared
endif

all: $(LIB)

$(LIB): src/cpp/paillier.cpp src/cpp/api.cpp src/cpp/paillier.h
	mkdir -p src/batch_paillier
	$(CXX) $(CXXFLAGS) $(SOFLAGS) -I$(GMP_INC) src/cpp/paillier.cpp src/cpp/api.cpp -L$(GMP_LIB) -lgmp -o $(LIB)

clean:
	rm -f src/batch_paillier/libpaillier.dylib src/batch_paillier/libpaillier.so

.PHONY: all clean
