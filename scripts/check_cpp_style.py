#!/usr/bin/env python3
"""Check LLVM source conventions that need this repository's include layout."""

import re
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    errors = []
    for path in sorted((root / "src").glob("*.hpp")):
        errors.append(f"{path.relative_to(root)}: use .h for self-contained headers")
    for path in sorted((root / "src").glob("*.h")):
        text = path.read_text()
        guard = path.name.upper().replace(".", "_")
        opening = rf"^#ifndef {guard}\n#define {guard}$"
        if not re.search(opening, text, re.MULTILINE):
            errors.append(f"{path.relative_to(root)}: expected guard {guard}")
        if not text.rstrip().endswith(f"#endif // {guard}"):
            errors.append(f"{path.relative_to(root)}: missing closing guard comment")
        if re.search(r"^\s*using namespace\s", text, re.MULTILINE):
            errors.append(f"{path.relative_to(root)}: namespace directive in header")
    for path in sorted((root / "src").glob("*.cpp")):
        text = path.read_text()
        if path.name != "main.cpp" and re.search(
            r"^\s*#\s*include\s*<iostream>", text, re.MULTILINE
        ):
            errors.append(f"{path.relative_to(root)}: iostream in library source")
        if re.search(r"^\s*namespace alfie\s*\{", text, re.MULTILINE):
            errors.append(f"{path.relative_to(root)}: qualify out-of-line definitions")
    # Mustache escapes {{value}} but not {{{value}}} or {{&value}}. These
    # templates render the page that collects the vault login and master
    # password, so an unescaped interpolation there is an injection point into
    # exactly the page that must not have one. There is no current need for raw
    # HTML in a value, so the safe form is the only form allowed.
    for path in sorted((root / "templates").glob("*.mustache")):
        text = path.read_text()
        for marker, name in (("{{{", "triple-brace"), ("{{&", "ampersand")):
            if marker in text:
                errors.append(
                    f"{path.relative_to(root)}: {name} interpolation bypasses "
                    "HTML escaping"
                )
    for folder in ("src", "tests"):
        for path in sorted((root / folder).glob("*")):
            if path.suffix not in (".h", ".cpp"):
                continue
            text = path.read_text()
            if re.search(r"^\s*using namespace std\s*;", text, re.MULTILINE):
                errors.append(f"{path.relative_to(root)}: qualify standard names")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Repository LLVM source conventions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
