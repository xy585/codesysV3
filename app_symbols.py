#!/usr/bin/env python3
"""
List the symbol names inside the application the runtime is currently running.

Run this after downloading from the IDE to confirm your variables actually
reached the runtime.  If a name is missing here, CmpIecVarAccess cannot
resolve it and reads will return status 0x14.

Usage:  python app_symbols.py [path-to-Application.app]
"""

import os
import re
import sys

DEFAULT = (r"C:\ProgramData\CODESYS\CODESYSControlWinV3\1DCA8F9"
           r"\PlcLogic\Application\Application.app")

# noise that comes from the runtime/library images rather than the user program
LIBRARY_HINT = re.compile(r"^[A-Z][A-Z0-9_]*__[A-Z0-9_]+$|^IOMGR|^SYS|^CM|^CODEM")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    if not os.path.exists(path):
        print(f"not found: {path}")
        return 1
    st = os.stat(path)
    import datetime
    print(f"{path}")
    print(f"  size = {st.st_size} bytes")
    print(f"  modified = {datetime.datetime.fromtimestamp(st.st_mtime)}\n")

    data = open(path, "rb").read()
    names = []
    for m in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]{2,40}\x00", data):
        s = m.group()[:-1].decode("latin-1")
        if not LIBRARY_HINT.match(s):
            names.append((m.start(), s))

    print("names in the application image (POU / type / variable names):")
    seen = set()
    for off, s in names:
        if s in seen:
            continue
        seen.add(s)
        print(f"  0x{off:05x}  {s}")

    print(f"\n{len(seen)} distinct name(s).")
    print("If your variable is not listed, the IDE has not downloaded it yet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
