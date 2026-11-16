"""Checks every bundled schema guide for time template tags the template engine cannot fill.

A guide teaches the scenario generator which tags to write. A tag that the engine does not
know is copied into generated logs as a literal placeholder, and parsers often accept the
line anyway, so the fault is easy to miss. This test needs no model call.
"""

from pathlib import Path
import unittest

from logjammer.templates import find_unsupported_guide_tags

GUIDES_DIR = Path(__file__).resolve().parent.parent / "guides"


class BundledGuidesTest(unittest.TestCase):

  def test_guides_directory_has_guides(self):
    self.assertTrue(sorted(GUIDES_DIR.glob("*.txt")), f"no guides found in {GUIDES_DIR}")

  def test_every_guide_uses_only_supported_time_tags(self):
    for path in sorted(GUIDES_DIR.glob("*.txt")):
      with self.subTest(guide=path.name):
        unsupported = find_unsupported_guide_tags(path.read_text(encoding="utf-8", errors="ignore"))
        self.assertEqual(unsupported, [], f"{path.name} uses tags that cannot be filled")


if __name__ == "__main__":
  unittest.main()
