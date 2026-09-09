CXX ?= g++
CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -Wpedantic -Ithird_party/libssl-dev/usr/include -Ithird_party/libssl-dev/usr/include/x86_64-linux-gnu -Ithird_party/argon2/usr/include
LDFLAGS := -Lthird_party/argon2/usr/lib/x86_64-linux-gnu -Wl,-rpath,$(CURDIR)/third_party/argon2/usr/lib/x86_64-linux-gnu -largon2 -l:libcrypto.so.3
CPP_SOURCES := $(wildcard src/*.cpp src/*.hpp tests/*.cpp)

all: alfie-vault tests/test_vault tests/test_ipc_crypto tests/test_ipc_transport tests/test_http_unlock

alfie-vault: src/main.cpp src/vault.cpp src/vault.hpp src/http_unlock.cpp src/http_unlock.hpp
	$(CXX) $(CXXFLAGS) src/main.cpp src/vault.cpp src/http_unlock.cpp -o $@ $(LDFLAGS)

tests/test_vault: tests/test_vault.cpp src/vault.cpp src/vault.hpp
	$(CXX) $(CXXFLAGS) tests/test_vault.cpp src/vault.cpp -o tests/test_vault $(LDFLAGS)

tests/test_ipc_crypto: tests/test_ipc_crypto.cpp src/ipc_crypto.cpp src/ipc_crypto.hpp src/vault.cpp src/vault.hpp
	$(CXX) $(CXXFLAGS) tests/test_ipc_crypto.cpp src/ipc_crypto.cpp src/vault.cpp -o tests/test_ipc_crypto $(LDFLAGS)

tests/test_ipc_transport: tests/test_ipc_transport.cpp src/ipc_transport.cpp src/ipc_transport.hpp
	$(CXX) $(CXXFLAGS) tests/test_ipc_transport.cpp src/ipc_transport.cpp -o tests/test_ipc_transport $(LDFLAGS)

tests/test_http_unlock: tests/test_http_unlock.cpp src/http_unlock.cpp src/http_unlock.hpp src/vault.cpp src/vault.hpp
	$(CXX) $(CXXFLAGS) tests/test_http_unlock.cpp src/http_unlock.cpp src/vault.cpp -o tests/test_http_unlock $(LDFLAGS)

test: tests/test_vault tests/test_ipc_crypto tests/test_ipc_transport tests/test_http_unlock
	./tests/test_vault
	./tests/test_ipc_crypto
	./tests/test_ipc_transport
	./tests/test_http_unlock

clean:
	rm -f alfie-vault tests/test_vault tests/test_ipc_crypto tests/test_ipc_transport tests/test_http_unlock

format:
	@command -v clang-format >/dev/null || { echo "clang-format missing; install clang-format"; exit 1; }
	clang-format -i $(CPP_SOURCES)

format-check:
	@command -v clang-format >/dev/null || { echo "clang-format missing; install clang-format"; exit 1; }
	clang-format --dry-run --Werror $(CPP_SOURCES)

tidy:
	@command -v clang-tidy >/dev/null || { echo "clang-tidy missing; install clang-tidy"; exit 1; }
	clang-tidy src/*.cpp tests/*.cpp -- $(CXXFLAGS)

.PHONY: all test clean format format-check tidy
