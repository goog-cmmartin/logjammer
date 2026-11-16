#!/usr/bin/env python3
"""Lists time template tags in schema guides that LogJammer cannot fill. No model calls.

Usage:
  python scripts/check_guides.py                 # checks ./guides and ~/.logjammer/guides
  python scripts/check_guides.py path/to/guides  # checks the given directory or file

Exits 1 when any guide has an unsupported tag.
"""

from pathlib import Path
import sys

from logjammer.templates import find_unsupported_guide_tags


def main(argv):
  targets = [Path(a) for a in argv] or [
      Path(__file__).resolve().parent.parent / "guides",
      Path.home() / ".logjammer" / "guides",
  ]
  files = []
  for target in targets:
    if target.is_dir():
      files.extend(sorted(target.glob("*.txt")))
    elif target.is_file():
      files.append(target)
  failures = 0
  for path in files:
    unsupported = find_unsupported_guide_tags(path.read_text(encoding="utf-8", errors="ignore"))
    if unsupported:
      failures += 1
      print(f"{path}: {len(unsupported)} unsupported tag(s)")
      for tag in unsupported:
        print(f"    {tag}")
  print(f"Checked {len(files)} guide(s). {failures} with unsupported tags.")
  return 1 if failures else 0


if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))
