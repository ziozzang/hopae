#!/usr/bin/env python3
"""Gateway adapter boundary lint (docs/adr/0013).

Fails if a gateway-specific header prefix appears anywhere in src/ outside
src/gateway/. Comments and strings count. Standard library only.
"""
import pathlib
import sys

FORBIDDEN = ("x-original-", "x-forwarded-", "x-hangang")
ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
ALLOWED = SRC / "gateway"


def main() -> int:
    bad = []
    if SRC.is_dir():
        for path in sorted(SRC.rglob("*")):
            if not path.is_file() or ALLOWED in path.parents:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                low = line.lower()
                for needle in FORBIDDEN:
                    if needle in low:
                        bad.append(f"{path.relative_to(ROOT)}:{n}: contains '{needle}'")
    for b in bad:
        print(b, file=sys.stderr)
    if bad:
        print(f"check-boundary: {len(bad)} violation(s); gateway wire names belong in src/gateway/", file=sys.stderr)
        return 1
    print("check-boundary: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
