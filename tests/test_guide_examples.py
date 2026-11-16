"""Unit tests for extracting example log records from schema guides."""

from datetime import datetime, timezone
from pathlib import Path
import unittest

from logjammer.guide_examples import block_to_logs, example_blocks, extract_example_logs
from logjammer.templates import TimeTemplateService

GUIDES_DIR = Path(__file__).resolve().parent.parent / "guides"

GUIDE = """# Demo guide

## 3. Schema
```text
not an example, this block is outside the examples section
```

## 5. Concrete Valid Examples

### Example 1: two syslog lines
```text
<14>##$SyslogTime-0d0h2m0s$## host1 app: first
<14>##$SyslogTime-0d0h1m0s$## host1 app: second
```

### Example 2: pretty-printed JSON
```json
{
  "time": "##$TimeStamp-0d0h5m0s$##",
  "epoch": ##$Epoch-0d0h5m0s$##
}
```

## 6. Pitfalls
```text
also outside the examples section
```
"""


class GuideExamplesTest(unittest.TestCase):

  def test_only_blocks_in_the_examples_section_are_returned(self):
    blocks = example_blocks(GUIDE)
    self.assertEqual(len(blocks), 2)
    self.assertIn("first", blocks[0])
    self.assertNotIn("outside", "".join(blocks))

  def test_guide_without_examples_section(self):
    self.assertEqual(example_blocks("# Title\n\n## Schema\n```\nx\n```\n"), [])

  def test_one_record_per_line_for_plain_text(self):
    self.assertEqual(block_to_logs("line one\n\nline two\n"), ["line one", "line two"])

  def test_pretty_printed_json_is_one_record(self):
    self.assertEqual(block_to_logs('{\n  "a": 1,\n  "b": [1, 2]\n}'), ['{"a":1,"b":[1,2]}'])

  def test_one_json_object_per_line_stays_separate(self):
    self.assertEqual(block_to_logs('{"a":1}\n{"a":2}'), ['{"a":1}', '{"a":2}'])

  def test_multiline_xml_event_is_one_record(self):
    logs = block_to_logs("<Event xmlns='x'>\n  <System/>\n</Event>")
    self.assertEqual(logs, ["<Event xmlns='x'> <System/> </Event>"])

  def test_resolving_first_makes_unquoted_tags_valid_json(self):
    resolver = TimeTemplateService(datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)).replace_templates
    logs = extract_example_logs(GUIDE, resolve=resolver)
    self.assertEqual(len(logs), 3)
    self.assertTrue(logs[0].startswith("<14>Aug 24 11:58:00 host1"))
    self.assertEqual(logs[2], '{"time":"2026-08-24T11:55:00.000Z","epoch":1787572500}')

  def test_every_bundled_guide_has_examples(self):
    for path in sorted(GUIDES_DIR.glob("*.txt")):
      with self.subTest(guide=path.name):
        self.assertTrue(extract_example_logs(path.read_text(encoding="utf-8", errors="ignore")))


if __name__ == "__main__":
  unittest.main()
