# Build

Primary build system: CMake with Ninja.

Local tools installed in-repo because this environment has no root `apt install` permission:

- Ninja: `third_party/ninja/usr/bin/ninja`
- clang-format/clang-tidy: `third_party/clang-tools/usr/bin/`

## Configure/build/test

```bash
cmake -S . -B build -G Ninja -DCMAKE_MAKE_PROGRAM=$PWD/third_party/ninja/usr/bin/ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

## Formatting/tidy

```bash
cmake --build build --target format
cmake --build build --target format-check
cmake --build build --target tidy
```
