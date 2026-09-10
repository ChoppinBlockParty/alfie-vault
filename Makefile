NINJA := $(CURDIR)/third_party/ninja/usr/bin/ninja
BUILD_DIR := build

.PHONY: configure all test clean format format-check tidy

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

tidy: configure
	cmake --build $(BUILD_DIR) --target tidy

clean:
	rm -rf $(BUILD_DIR)
