"""Surgically switch App guard membership routes back to native router commands.

The deployed BE72/BE50 Hub images differ from the checkout, so only replace the
two route return statements. The caller must back up hub.py before invoking it.
"""

from pathlib import Path
import re
import sys


def patch(source: str) -> str:
    for action in ("add_device", "remove_device"):
        pattern = re.compile(
            r'(?m)^    return _child_guard_official_membership\("'
            + action
            + r'", (\{[^\n]*(?:\n[^\n]*)*?\})\)$'
        )

        def replace(match: re.Match[str]) -> str:
            operation = match.group(1)
            return (
                f"    operation = {operation}\n"
                '    if request.args.get("sync") == "official":\n'
                f'        return _child_guard_official_membership("{action}", operation)\n'
                f'    return _child_guard_execute("{action}", operation)'
            )

        source, count = pattern.subn(replace, source)
        if count != 1:
            raise RuntimeError(f"expected one {action} official route, found {count}")
    return source


def main() -> None:
    target = Path(sys.argv[1])
    original = target.read_text(encoding="utf-8")
    updated = patch(original)
    compile(updated, str(target), "exec")
    target.write_text(updated, encoding="utf-8")
    print(f"patched and syntax-checked {target}")


if __name__ == "__main__":
    main()
