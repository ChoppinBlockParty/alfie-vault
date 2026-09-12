# Build

Primary build system: CMake with Ninja.

Build helpers prefer vendored tools and otherwise discover them on PATH:

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
cmake --build build --target naming-check
cmake --build build --target tidy
```

Formatting follows the LLVM preset in `.clang-format`: 80 columns and right-aligned
pointers (`Type *Pointer`). Naming follows the
[LLVM/Clang coding standards](https://llvm.org/docs/CodingStandards.html#name-types-functions-variables-and-enumerators-properly):
`lowerCamelCase` functions; `UpperCamelCase` types, variables, constants, and members.
Private members have no trailing underscore. Standard-library protocol names such as
`value_type` keep their required spelling. Naming violations fail `make naming-check`
and `make tidy`.

Use `make format`, `make format-check`, and `make naming-check` for the same targets.
Install clang-format and clang-tidy locally or set `CLANG_FORMAT` and `CLANG_TIDY`
when configuring CMake to select explicit executable paths. Ninja can be selected
with `make NINJA=/path/to/ninja`.
