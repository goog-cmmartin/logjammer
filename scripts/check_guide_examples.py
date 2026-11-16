#!/usr/bin/env python3
"""Parses the example log lines in every schema guide with a Google SecOps parser.

A guide can pass scripts/check_guides.py and still describe a layout the parser rejects
or misreads, such as a missing positional field or a timestamp in the wrong format. This
script finds those by running each guide's own examples through the parser.

For each guide it:
  1. Takes the fenced code blocks in the examples section.
  2. Fills the time template tags against a base time three days in the past.
  3. Runs each example through the SecOps runParser API. Nothing is ingested.
  4. Reports examples that fail, that produce no event, or whose event time is the
     current time. The last case means the parser did not read the time from the log
     and fell back to ingestion time.

It needs access to a Google SecOps instance, so it is not part of the unit tests.

Configuration, by flag or environment variable, the same as for SecOps ingestion:
  --customer-id   CHRONICLE_CUSTOMER_ID or SECOPS_CUSTOMER_ID
  --project       CHRONICLE_PROJECT_NUMBER, GCP_PROJECT_NUMBER or GOOGLE_CLOUD_PROJECT
  --region        CHRONICLE_REGION, default us
Credentials come from Application Default Credentials or GOOGLE_APPLICATION_CREDENTIALS.

Which parser is used for a log type:
  1. The parser the instance lists as ACTIVE.
  2. Otherwise the newest PREBUILT parser the instance lists.
  3. Otherwise <parser-config-dir>/<LOG_TYPE>.conf, when --parser-config-dir is given.
  4. Otherwise the log type is skipped and reported as having no parser.

Usage:
  python scripts/check_guide_examples.py
  python scripts/check_guide_examples.py --types PAN_FIREWALL OKTA
  python scripts/check_guide_examples.py --guides-dir ~/.logjammer/guides --json-out report.json

Exit code 1 when any example fails to parse or produces no event. Time problems are
reported but only fail the run with --strict-time, because some parsers do not read the
event time for some formats, and real logs of that format behave the same way.
"""

import argparse
import base64
import datetime
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from logjammer.guide_examples import extract_example_logs  # noqa: E402
from logjammer.sinks.secops import SecOpsSink  # noqa: E402
from logjammer.templates import TimeTemplateService  # noqa: E402

BATCH = 20


class SecOpsParserClient:
  """Minimal client for listing parsers and calling runParser."""

  def __init__(self, customer_id=None, project=None, region=None):
    sink = SecOpsSink(customer_id=customer_id, project_id=project, region=region)
    if not sink.customer_id or not (sink.project_number or sink.project_id):
      raise ValueError(
          "A SecOps customer ID and a Google Cloud project are required. Pass --customer-id and --project, "
          "or set CHRONICLE_CUSTOMER_ID and GOOGLE_CLOUD_PROJECT."
      )
    proj = sink.project_number or sink.project_id
    self.base = (
        f"https://{sink.region}-chronicle.googleapis.com/v1alpha/projects/{proj}"
        f"/locations/{sink.region}/instances/{sink.customer_id}"
    )
    self._headers = {"Authorization": f"Bearer {sink._get_auth_token()}", "Content-Type": "application/json"}  # pylint: disable=protected-access

  def _request(self, method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=self._headers, method=method)
    with urllib.request.urlopen(req, timeout=120) as resp:
      return json.loads(resp.read().decode() or "{}")

  def find_parser(self, log_type, config_dir=None):
    """Return (cbn_base64, label) or (None, reason)."""
    parsers = []
    try:
      parsers = self._request("GET", f"{self.base}/logTypes/{log_type}/parsers?pageSize=50").get("parsers", [])
    except urllib.error.HTTPError as e:
      if e.code != 404:
        raise
    active = [p for p in parsers if p.get("state") == "ACTIVE"]
    prebuilt = sorted(
        (p for p in parsers if p.get("type") == "PREBUILT"), key=lambda p: p.get("createTime", ""), reverse=True
    )
    for p in active or prebuilt:
      return p["cbn"], f"{p.get('type', '').lower()} {p.get('state', '').lower()} {p.get('createTime', '')[:10]}"
    if config_dir:
      path = Path(config_dir) / f"{log_type}.conf"
      if path.is_file():
        return base64.b64encode(path.read_bytes()).decode(), f"file {path.name}"
    return None, "no parser on this instance"

  def run_parser(self, log_type, cbn, logs):
    results = []
    for i in range(0, len(logs), BATCH):
      chunk = logs[i:i + BATCH]
      body = {
          "parser": {"cbn": cbn},
          "log": [base64.b64encode(line.encode()).decode() for line in chunk],
          "statedump_allowed": False,
      }
      got = self._request("POST", f"{self.base}/logTypes/{log_type}:runParser", body).get("runParserResults", [])
      got += [{"error": "no result returned"}] * (len(chunk) - len(got))
      results.extend(got)
    return results


def _short_error(err):
  text = re.sub(r"\\+", "", str(err))
  m = re.search(r"(panic encountered: [^\"]+|filter \w+ \(\d+\) failed[^\"]{0,120}|failed to [^\"]{0,120})", text)
  return (m.group(1) if m else text)[-180:]


def classify(result, base_time, now):
  """Return (status, detail). Status is ok, error, no output, time not read, or time off."""
  if "error" in result:
    return "error", _short_error(result["error"])
  events = [e.get("event") or e for e in result.get("parsedEvents", {}).get("events", [])]
  entities = result.get("parsedEntities", {}).get("entities", [])
  if not events and not entities:
    return "no output", ""
  # Entity records come back either under parsedEntities or as events without an event timestamp.
  stamp = events[0].get("metadata", {}).get("eventTimestamp") if events else None
  if not stamp:
    return "ok", "no event time"
  try:
    t = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
  except ValueError:
    return "ok", "unreadable event time"
  if abs((t - now).total_seconds()) < 1800:
    return "time not read", f"event time {stamp[:19]} is the time of parsing"
  if abs((t - base_time).total_seconds()) > 7 * 86400:
    return "time off", f"event time {stamp[:19]} is far from the expected {base_time.isoformat()[:19]}"
  return "ok", ""


def main(argv=None):
  ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
  ap.add_argument("--guides-dir", default=str(REPO_ROOT / "guides"))
  ap.add_argument("--types", nargs="*", help="Log types to check. Default: every guide in the directory.")
  ap.add_argument("--customer-id")
  ap.add_argument("--project")
  ap.add_argument("--region")
  ap.add_argument("--parser-config-dir", help="Directory of <LOG_TYPE>.conf parser files, used when the instance lists no parser.")
  ap.add_argument("--strict-time", action="store_true", help="Also fail when an event time is not read from the log.")
  ap.add_argument("--json-out", help="Write the full report, including each example line, to this file.")
  args = ap.parse_args(argv)

  client = SecOpsParserClient(args.customer_id, args.project, args.region)
  now = datetime.datetime.now(datetime.timezone.utc)
  base_time = now - datetime.timedelta(days=3)
  resolver = TimeTemplateService(base_time).replace_templates

  guides = sorted(Path(args.guides_dir).expanduser().glob("*.txt"))
  wanted = {t.upper() for t in args.types} if args.types else None
  report, hard, soft, skipped = {}, 0, 0, 0
  for path in guides:
    log_type = path.stem
    if wanted and log_type not in wanted:
      continue
    logs = extract_example_logs(path.read_text(encoding="utf-8", errors="ignore"), resolve=resolver)
    entry = {"examples": len(logs), "parser": None, "results": []}
    report[log_type] = entry
    if not logs:
      print(f"{log_type:30s} no examples found")
      continue
    cbn, label = client.find_parser(log_type, args.parser_config_dir)
    entry["parser"] = label
    if cbn is None:
      skipped += 1
      print(f"{log_type:30s} skipped, {label}")
      continue
    problems = []
    for line, result in zip(logs, client.run_parser(log_type, cbn, logs)):
      status, detail = classify(result, base_time, now)
      entry["results"].append({"status": status, "detail": detail, "log": line})
      if status in ("error", "no output"):
        hard += 1
        problems.append((status, detail, line))
      elif status != "ok":
        soft += 1
        problems.append((status, detail, line))
    ok = sum(r["status"] == "ok" for r in entry["results"])
    print(f"{log_type:30s} {ok}/{len(logs)} ok   [{label}]")
    for status, detail, line in problems:
      print(f"    {status}: {detail}")
      print(f"      {line[:160]}")

  if args.json_out:
    Path(args.json_out).write_text(json.dumps(report, indent=1), encoding="utf-8")
  checked = sum(1 for e in report.values() if e["results"])
  print(
      f"\nChecked {checked} guide(s), skipped {skipped} with no parser. "
      f"{hard} example(s) failed to parse, {soft} had a time problem."
  )
  return 1 if hard or (args.strict_time and soft) else 0


if __name__ == "__main__":
  sys.exit(main())
