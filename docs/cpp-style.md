# C++ style

Project build stays on Make.

Formatting/tidying policy:

- clang-format config: `.clang-format`
- clang-tidy config: `.clang-tidy`
- base style: Google-style C++ with project naming
- functions/variables: `lower_case`
- classes/structs: `CamelCase`
- private members: trailing `_`

Commands:

```bash
make format-check
make format
make tidy
```

Current environment note: `clang-format` and `clang-tidy` are not installed on this box yet. The Make targets are ready and fail with a clear install message when the tools are missing.
