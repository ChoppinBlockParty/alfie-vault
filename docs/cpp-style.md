# C++ style

Project build uses CMake with Ninja.

Formatting/tidying policy:

- clang-format config: `.clang-format` — the LLVM preset (80 columns, right-aligned
  pointers), C++20.
- clang-tidy config: `.clang-tidy` — LLVM checks plus `bugprone-*`, `performance-*`,
  `portability-*` and `readability-*`, with `readability-identifier-naming` as the
  authority on names.
- base style: LLVM/Clang, with `lowerCamelCase` values instead of LLVM's
  `UpperCamelCase` ones.

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

`const` parameters and `const` locals are ordinary variables, not `k` constants: only
`constexpr`, `static const` and class constants take the prefix. Standard-library
protocol names such as `value_type` keep their required spelling and are exempted in
`.clang-tidy`.

Beyond names, the LLVM source conventions this project enforces are `.h` for
self-contained headers with `#ifndef FILE_H` guards (no `#pragma once`), no
`using namespace` in a header, no `<iostream>` in library sources, and out-of-line
definitions qualified rather than reopened inside `namespace alfie`.
`scripts/check_cpp_style.py` checks the ones that depend on this repository's include
layout, since `llvm-header-guard` assumes an LLVM checkout.

Commands:

```bash
cmake --build build --target format        # clang-format -i
cmake --build build --target format-check  # fails on unformatted code
cmake --build build --target naming-check  # readability-identifier-naming only
cmake --build build --target llvm-check    # LLVM checks + the local style script
cmake --build build --target style-check   # format-check + llvm-check
cmake --build build --target tidy          # the full .clang-tidy set
```

`make format`, `make format-check`, `make naming-check`, `make llvm-check`,
`make style-check` and `make tidy` wrap the same targets.

Current environment note: on the original Linux box `clang-format` and `clang-tidy` are
installed under `third_party/clang-tools` (gitignored) because it has no root
package-install permission; CMake prefers those and otherwise falls back to PATH.
