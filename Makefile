NINJA ?= $(if $(wildcard $(CURDIR)/third_party/ninja/usr/bin/ninja),$(CURDIR)/third_party/ninja/usr/bin/ninja,ninja)
BUILD_DIR := build

.PHONY: configure all test clean format format-check naming-check llvm-check style-check tidy

configure:
	cmake -S . -B $(BUILD_DIR) -G Ninja -DCMAKE_MAKE_PROGRAM=$(NINJA)

all: configure
	cmake --build $(BUILD_DIR)

test: all
	ctest --test-dir $(BUILD_DIR) --output-on-failure

format: configure
	cmake --build $(BUILD_DIR) --target format

format-check: configure
	cmake --build $(BUILD_DIR) --target format-check

naming-check: configure
	cmake --build $(BUILD_DIR) --target naming-check

llvm-check: configure
	cmake --build $(BUILD_DIR) --target llvm-check

style-check: configure
	cmake --build $(BUILD_DIR) --target style-check

tidy: configure
	cmake --build $(BUILD_DIR) --target tidy

clean:
	rm -rf $(BUILD_DIR)
