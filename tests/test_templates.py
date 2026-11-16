"""Unit tests for relative time template replacement."""

from datetime import datetime, timezone
import re
import unittest
from logjammer.templates import (
    SUPPORTED_TIME_TAGS_PROMPT,
    TimeTemplateService,
    find_unresolved_templates,
    replace_time_templates,
    replace_time_templates_in_logs,
)


class TimeTemplateTest(unittest.TestCase):

  def setUp(self):
    self.base_time = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
    self.service = TimeTemplateService(self.base_time)

  def test_iso_timestamp_subtraction(self):
    # 2 hours, 15 minutes before 12:00:00 -> 09:45:00
    raw_text = '{"event_time": "##$TimeStamp-0d2h15m0s$##"}'
    resolved = self.service.replace_templates(raw_text)
    self.assertIn("2026-08-24T09:45:00.000Z", resolved)

  def test_iso_timestamp_addition(self):
    # 1 day, 30 minutes after 12:00:00 -> 2026-08-25 12:30:00
    raw_text = "Timestamp: ##$TimeStamp+1d0h30m0s$##"
    resolved = self.service.replace_templates(raw_text)
    self.assertIn("2026-08-25T12:30:00.000Z", resolved)

  def test_epoch_replacement(self):
    raw_text = "event_epoch=##$Epoch-0d0h10m0s$##"
    resolved = self.service.replace_templates(raw_text)
    expected_epoch = int((self.base_time).timestamp()) - 600
    self.assertEqual(resolved, f"event_epoch={expected_epoch}")

  def test_syslog_time_replacement(self):
    raw_text = "##$SyslogTime-0d1h0m0s$## host1 sshd[1234]: Failed password"
    resolved = self.service.replace_templates(raw_text)
    self.assertTrue(resolved.startswith("Aug 24 11:00:00"))

  def test_nested_structure_replacement(self):
    log_dict = {
        "user": "alice",
        "events": [
            {"time": "##$TimeStamp-0d0h5m0s$##", "action": "login"},
            {"time": "##$TimeStamp-0d0h1m0s$##", "action": "escalate"},
        ],
    }
    resolved = replace_time_templates_in_logs(log_dict, self.base_time)
    self.assertIn("2026-08-24T11:55:00", resolved["events"][0]["time"])
    self.assertIn("2026-08-24T11:59:00", resolved["events"][1]["time"])

  def test_epoch_ms_and_alias(self):
    expected = (int(self.base_time.timestamp()) - 600) * 1000
    self.assertEqual(self.service.replace_templates("start=##$EpochMS-0d0h10m0s$##"), f"start={expected}")
    self.assertEqual(self.service.replace_templates("start=##$EpochMillis-0d0h10m0s$##"), f"start={expected}")

  def test_epoch_microseconds_and_nanoseconds(self):
    base = int(self.base_time.timestamp())
    self.assertEqual(self.service.replace_templates("##$EpochMicroseconds-0d0h0m10s$##"), str((base - 10) * 1000000))
    self.assertEqual(self.service.replace_templates("##$EpochNanoseconds-0d0h0m10s$##"), str((base - 10) * 1000000000))

  def test_offset_is_optional(self):
    # The original web app allows a bare tag, meaning the base time itself.
    self.assertEqual(self.service.replace_templates("##$TimeStamp$##"), "2026-08-24T12:00:00.000Z")
    self.assertEqual(self.service.replace_templates("##$Epoch$##"), str(int(self.base_time.timestamp())))
    self.assertEqual(self.service.replace_templates("##$TimeStamp|%H:%M$##"), "12:00")

  def test_strftime_format_after_pipe(self):
    resolved = self.service.replace_templates("date=##$TimeStamp-0d0h5m0s|%Y-%m-%d$## time=##$TimeStamp-0d0h5m0s|%H:%M:%S$##")
    self.assertEqual(resolved, "date=2026-08-24 time=11:55:00")

  def test_strftime_format_with_milliseconds(self):
    # Salesforce EventLogFile compact timestamp.
    resolved = self.service.replace_templates('"Login","##$TimeStamp-0d0h5m0s|%Y%m%d%H%M%S.%3f$##"')
    self.assertEqual(resolved, '"Login","20260824115500.000"')

  def test_date_pattern_tokens(self):
    # Token style used by the original web app and by many guides.
    cases = {
        "##$TimeStamp-0d0h5m0s|yyyy/MM/dd HH:mm:ss$##": "2026/08/24 11:55:00",
        "##$TimeStamp-0d0h5m0s|YYYY/MM/DD HH:mm:ss$##": "2026/08/24 11:55:00",
        "##$TimeStamp-0d0h5m0s|MMM dd yyyy HH:mm:ss$##": "Aug 24 2026 11:55:00",
        "##$TimeStamp-0d0h5m0s|yyyy-MM-ddTHH:mm:ss.SSSZ$##": "2026-08-24T11:55:00.000Z",
        "##$TimeStamp-0d0h5m0s|dd/MMM/yyyy:HH:mm:ss +0000$##": "24/Aug/2026:11:55:00 +0000",
        "##$TimeStamp-0d0h5m0s|yyyy-MM-dd'T'HH:mm:ss'Z'$##": "2026-08-24T11:55:00Z",
    }
    for tag, expected in cases.items():
      self.assertEqual(self.service.replace_templates(tag), expected, tag)

  def test_format_with_utc_offset(self):
    # Workday sign-on audit layout, rendered in a fixed offset.
    resolved = self.service.replace_templates("##$TimeStamp-0d0h5m0s|%Y %m %d %H %M %S %3f %z|-08:00$##")
    self.assertEqual(resolved, "2026 08 24 03 55 00 000 -0800")
    colon = self.service.replace_templates("##$TimeStamp-0d0h5m0s|%Y-%m-%dT%H:%M:%S%:z|-08:00$##")
    self.assertEqual(colon, "2026-08-24T03:55:00-08:00")
    plus = self.service.replace_templates("##$TimeStamp+0d1h0m0s|%Y-%m-%dT%H:%M:%S|+0530$##")
    self.assertEqual(plus, "2026-08-24T18:30:00")
    utc = self.service.replace_templates("##$TimeStamp-0d0h5m0s|%H:%M%:z$##")
    self.assertEqual(utc, "11:55+00:00")

  def test_format_is_ignored_for_epoch(self):
    # Matches the original web app.
    self.assertEqual(
        self.service.replace_templates("##$Epoch-0d0h10m0s|%Y$##"),
        str(int(self.base_time.timestamp()) - 600),
    )

  def test_several_tags_in_one_line(self):
    resolved = self.service.replace_templates(
        "a=##$TimeStamp-0d0h0m0s|%H:%M$## b=##$Date-0d0h0m0s$## c=##$TimeStamp-1d0h0m0s|%d$##"
    )
    self.assertEqual(resolved, "a=12:00 b=2026-08-24 c=23")

  def test_find_unresolved_templates_flags_unknown_tags(self):
    bad = [
        "##$EpochMs-0d0h1m0s$##",                       # wrong capitalisation
        "##$TimeStamp-0d0h1m0s:%Y-%m-%d$##",            # colon in place of the pipe
        "##$Date-0d0h1m0s-YYYY MM DD$##",               # dash in place of the pipe
        "##$CustomTime:MMM dd yyyy HH:mm:ss-0d2h15m0s$##",
        "##$Digit100-999$##",
        "##$Epoch-0d0h1m0s||-08:00$##",
    ]
    text = "ok=##$TimeStamp-0d0h1m0s$## " + " ".join(bad)
    self.assertEqual(find_unresolved_templates(text), bad)

  def test_find_unresolved_templates_empty_when_all_supported(self):
    text = "##$SyslogTime-0d1h0m0s$## ##$TimeStamp-0d0h0m0s|%Y$## ##$EpochMS$##"
    self.assertEqual(find_unresolved_templates(text), [])

  def test_replace_time_templates_warns_on_unknown_tag(self):
    with self.assertWarns(UserWarning):
      replace_time_templates("##$SalesforceCompactTime-0d0h1m0s$##", self.base_time)

  def test_prompt_tag_examples_all_resolve(self):
    # Every example tag the prompts show to the model must be one this module can resolve.
    examples = re.findall(r"`(##\$[^`]+\$##)`", SUPPORTED_TIME_TAGS_PROMPT)
    self.assertGreaterEqual(len(examples), 10)
    for tag in examples:
      self.assertEqual(find_unresolved_templates(tag), [], tag)


if __name__ == "__main__":
  unittest.main()
