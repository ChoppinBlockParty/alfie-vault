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

## Tests

The C++ tests are [Catch2](https://github.com/catchorg/Catch2) v3, vendored as the
amalgamated release distribution in `third_party/catch2/` (two files, checked in) so
that building the tests needs neither a network nor a package manager. That
translation unit carries `main()`, which is why the test binaries define none.

CTest registers one entry per binary, so `ctest -R vault` still selects a whole file.
Each binary also takes Catch2's own selectors:

```bash
./build/test_vault --list-tests             # the cases in this binary
./build/test_vault "[record]"               # one tag
./build/test_corruption "Appended bytes are rejected"   # one case
./build/test_http_unlock --success          # show passing assertions too
```

To move to a newer Catch2, replace the two files from the release assets of the
[Catch2 release page](https://github.com/catchorg/Catch2/releases) and rebuild;
nothing else in the build refers to a version.

## Linux build

`accept4(2)`, `SO_PEERCRED` and the `MADV_DONTDUMP` calls sit inside
`#ifdef __linux__`. A macOS build never compiles them, and neither does clang-tidy,
which analyses the same branch the compiler took. That is not a hypothetical gap: a
rename applied by clang-tidy's fixer once left all five of those sites referring to
identifiers that no longer existed, and everything on macOS stayed green.

```bash
make linux-test
```

builds the image in `docker/Dockerfile.linux-build` (Ubuntu with system OpenSSL and
Argon2) and runs the configure, build and `ctest` inside it, with the repository
mounted read-only at `/src` and the build tree at `/build`, so the host's `build/`
is untouched. Run it before any change that touches platform-conditional code.

The image uses the distribution's OpenSSL and Argon2 rather than the vendored
`third_party/` copies, which are x86_64 binaries; CMake selects the vendored path
only on x86_64 Linux.

## Templates

`templates/*.mustache` are embedded into the binary at build time by
`scripts/embed_templates.cmake`, which writes `build/generated/templates.h`. The step is
plain CMake, so building the library needs no extra interpreter, and it runs again
whenever a template or the script changes. Editing a template and rebuilding is the only
way to change a page: nothing reads the templates from disk at runtime.

## Formatting/tidy

```bash
cmake --build build --target format
cmake --build build --target format-check
cmake --build build --target naming-check
cmake --build build --target tidy
```

Formatting follows the LLVM preset in `.clang-format`: 80 columns and right-aligned
pointers (`Type *pointer`). Naming follows the
[LLVM/Clang coding standards](https://llvm.org/docs/CodingStandards.html#name-types-functions-variables-and-enumerators-properly)
for types and functions, with one deliberate departure for values:

| Kind | Style | Example |
| --- | --- | --- |
| Namespace | `lower_case` | `alfie` |
| Class, struct, enum, type alias | `UpperCamelCase` | `ChunkVault`, `UnlockMode` |
| Enum constant | `UpperCamelCase` | `UnlockMode::Store` |
| Function, method | `lowerCamelCase` | `deriveKeys`, `findLiveToken` |
| Variable, parameter, public member | `lowerCamelCase` | `recordKey`, `domain` |
| Private, protected member | `lowerCamelCase` + `_` | `root_`, `vault_` |
| Compile-time constant | `k` + `UpperCamelCase` | `kNonceLen` |
| Template parameter | `UpperCamelCase` | `T` |

LLVM proper spells variables and members `UpperCamelCase` with no member suffix; this
project uses `lowerCamelCase` with a trailing underscore on private and protected
members so that a member is distinguishable from a local at the point of use. `const`
parameters and `const` locals are ordinary variables, not `k` constants -- only
`constexpr`, `static const` and class constants take the prefix. Standard-library
protocol names such as `value_type` keep their required spelling. Naming violations
fail `make naming-check` and `make tidy`.

Use `make format`, `make format-check`, and `make naming-check` for the same targets.
Install clang-format and clang-tidy locally or set `CLANG_FORMAT` and `CLANG_TIDY`
when configuring CMake to select explicit executable paths. Ninja can be selected
with `make NINJA=/path/to/ninja`.
