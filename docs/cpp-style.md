# C++ style

Project build uses CMake with Ninja.

Formatting/tidying policy:

- clang-format config: `.clang-format`
- clang-tidy config: `.clang-tidy`
- base style: Google-style C++ with project naming
- functions/variables: `lower_case`
- classes/structs: `CamelCase`
- private members: trailing `_`

Commands:

```bash
cmake --build build --target format-check
cmake --build build --target format
cmake --build build --target tidy
```

Current environment note: `clang-format` and `clang-tidy` are installed locally under `third_party/clang-tools` because this box has no root package-install permission.
