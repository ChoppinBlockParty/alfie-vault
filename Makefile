CXX ?= g++
CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -Wpedantic -Ithird_party/libssl-dev/usr/include -Ithird_party/libssl-dev/usr/include/x86_64-linux-gnu -Ithird_party/argon2/usr/include
LDFLAGS := -Lthird_party/argon2/usr/lib/x86_64-linux-gnu -Wl,-rpath,$(CURDIR)/third_party/argon2/usr/lib/x86_64-linux-gnu -largon2 -l:libcrypto.so.3

all: alfie-vault tests/test_vault

alfie-vault: src/main.cpp src/vault.cpp src/vault.hpp
	$(CXX) $(CXXFLAGS) src/main.cpp src/vault.cpp -o $@ $(LDFLAGS)

tests/test_vault: tests/test_vault.cpp src/vault.cpp src/vault.hpp
	$(CXX) $(CXXFLAGS) tests/test_vault.cpp src/vault.cpp -o tests/test_vault $(LDFLAGS)

test: tests/test_vault
	./tests/test_vault

clean:
	rm -f alfie-vault tests/test_vault

.PHONY: all test clean
