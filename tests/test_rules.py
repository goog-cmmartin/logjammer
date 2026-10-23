"""Unit tests for SecOps rule analysis, rule caching/service, and rule-driven generation."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from logjammer.config import LogJammerConfig
from logjammer.models import GeneratedScenario, LogEntry, LogFormat, RuleAnalysis, SecOpsRule
from logjammer.rule_analyzer import RuleAnalyzer
from logjammer.rules import RuleService, parse_date_spec
from logjammer.generator import ScenarioGenerator


SAMPLE_YARAL = """
rule m_hunting_powershell_av_exclusion_path_1 {
  meta:
    author = "Google Cloud Security"
    description = "Detects PowerShell commands adding AV exclusions"
    severity = "Medium"
    mitre_attack_tactic = "Defense Evasion"
    mitre_attack_technique = "T1562.001"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.target.process.command_line, `Set-MpPreference.*-ExclusionPath`) nocase
    $e.target.process.command_line != "Set-MpPreference -ExclusionPath C:\\\\Program Files\\\\SafeApp"
    $e.principal.user.userid = $user

  match:
    $user over 10m

  condition:
    #e >= 2
}
"""


class RuleAnalyzerTest(unittest.TestCase):

  def setUp(self):
    self.analyzer = RuleAnalyzer()

  def test_analyze_rule_parsing(self):
    rule = SecOpsRule(
        rule_id="ur_test_123",
        display_name="m_hunting_powershell_av_exclusion_path_1",
        rule_owner="Google Cloud Security",
        text=SAMPLE_YARAL,
        tactics=["TA0005"],
        techniques=["T1562.001"],
    )

    analysis = self.analyzer.analyze(rule)
    self.assertEqual(analysis.rule_id, "ur_test_123")
    self.assertEqual(analysis.display_name, "m_hunting_powershell_av_exclusion_path_1")
    self.assertIn("PROCESS_LAUNCH", analysis.event_types)
    self.assertEqual(analysis.match_window, "10m")
    self.assertEqual(analysis.threshold_count, 2)
    self.assertIn("WINDOWS_SYSMON", analysis.suggested_log_types)

    # Check positive constraints
    self.assertIn("target.process.command_line", analysis.positive_constraints)
    constraints_str = " ".join(analysis.positive_constraints["target.process.command_line"])
    self.assertIn("Set-MpPreference.*-ExclusionPath", constraints_str)

    # Check negative exclusions
    self.assertIn("target.process.command_line", analysis.negative_exclusions)
    exclusions_str = " ".join(analysis.negative_exclusions["target.process.command_line"])
    self.assertIn("SafeApp", exclusions_str)

  def test_infer_log_types_heuristic(self):
    # Network event
    rule_net = SecOpsRule(
        rule_id="net_1",
        display_name="outbound_ssh",
        text="""
        rule outbound_ssh {
          events:
            $e.metadata.event_type = "NETWORK_CONNECTION"
            $e.target.port = 22
          condition:
            $e
        }
        """
    )
    analysis_net = self.analyzer.analyze(rule_net)
    self.assertTrue(
        any(lt in analysis_net.suggested_log_types for lt in ["PAN_FIREWALL", "CISCO_ASA", "ZEEK_CONN"])
    )

    # Cloud audit event
    rule_cloud = SecOpsRule(
        rule_id="cloud_1",
        display_name="gcp_iam_change",
        text="""
        rule gcp_iam {
          events:
            $e.metadata.event_type = "USER_CHANGE_PERMISSIONS"
            $e.security_result.action = "ALLOW"
          condition:
            $e
        }
        """
    )
    analysis_cloud = self.analyzer.analyze(rule_cloud)
    self.assertIn("GCP_CLOUDAUDIT", analysis_cloud.suggested_log_types)


class RuleServiceTest(unittest.TestCase):

  def setUp(self):
    self.temp_dir = tempfile.TemporaryDirectory()
    self.rules_dir = Path(self.temp_dir.name)
    self.config = LogJammerConfig(rules_dir=self.rules_dir)
    self.service = RuleService(self.config)

  def tearDown(self):
    self.temp_dir.cleanup()

  def test_catalog_save_and_list(self):
    sample_rule = SecOpsRule(
        rule_id="ur_sample",
        display_name="Sample Rule",
        rule_owner="Google Cloud Security",
        text=SAMPLE_YARAL,
        tactics=["TA0005"],
        techniques=["T1562.001"],
        severity="High",
    )

    catalog_path = self.rules_dir / "catalog.json"
    with open(catalog_path, "w", encoding="utf-8") as f:
      json.dump([sample_rule.to_dict()], f)

    # List all rules
    rules = self.service.list_rules()
    self.assertEqual(len(rules), 1)
    self.assertEqual(rules[0].display_name, "Sample Rule")

    # Search by technique
    by_tech = self.service.list_rules(technique="T1562.001")
    self.assertEqual(len(by_tech), 1)

    # Search by non-existent technique
    by_tech_none = self.service.list_rules(technique="T9999")
    self.assertEqual(len(by_tech_none), 0)

    # Get rule by id and name
    by_id = self.service.get_rule("ur_sample")
    self.assertIsNotNone(by_id)
    self.assertEqual(by_id.rule_id, "ur_sample")

    by_name = self.service.get_rule("Sample Rule")
    self.assertIsNotNone(by_name)
    self.assertEqual(by_name.rule_id, "ur_sample")

  def test_load_local_rule_file(self):
    rule_file = self.rules_dir / "test_rule.yaral"
    rule_file.write_text(SAMPLE_YARAL, encoding="utf-8")

    rule = self.service.get_rule(str(rule_file))
    self.assertIsNotNone(rule)
    self.assertEqual(rule.display_name, "m_hunting_powershell_av_exclusion_path_1")
    self.assertEqual(rule.rule_owner, "LOCAL")

  @mock.patch.object(RuleService, "_get_auth_token", return_value="mock_token")
  @mock.patch("urllib.request.urlopen")
  def test_sync_curated_rules(self, mock_urlopen, mock_token):
    self.config.customer_id = "test-cust-id"
    self.config.project_id = "test-proj-id"

    mock_resp = mock.MagicMock()
    mock_resp.read.return_value = json.dumps({
        "featuredContentRules": [
            {
                "name": "projects/p/locations/l/instances/i/contentHub/featuredContentRules/ru_12345",
                "contentMetadata": {
                    "displayName": "Suspicious AWS IAM Activity",
                    "categories": ["Cloud Security"],
                    "severity": {"displayName": "High"},
                    "description": "Detects IAM changes",
                    "author": "Google Cloud Threat Intelligence",
                },
                "curatedRuleContent": {
                    "precision": "PRECISE",
                    "techniques": [{"id": "T1078.004"}],
                    "tactics": [{"id": "TA0001"}],
                },
                "ruleSet": {
                    "displayName": "AWS Curated Detections",
                    "id": "aws_curated",
                },
                "ruleText": "rule aws_iam_change { events: $e.metadata.event_type = \"USER_CHANGE_PERMISSIONS\" condition: $e }",
                "liveStatusEnabled": True,
            }
        ]
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    rules = self.service.sync_curated_rules(save_yaral_files=True)
    self.assertEqual(len(rules), 1)
    rule = rules[0]
    self.assertEqual(rule.rule_id, "ru_12345")
    self.assertEqual(rule.display_name, "Suspicious AWS IAM Activity")
    self.assertEqual(rule.rule_owner, "GOOGLE_CURATED")
    self.assertEqual(rule.precision, "PRECISE")
    self.assertEqual(rule.techniques, ["T1078.004"])
    self.assertEqual(rule.tactics, ["TA0001"])
    self.assertTrue(rule.live_mode_enabled)

    # Verify curated_catalog.json created
    self.assertTrue(self.service.curated_cache_file.exists())
    with open(self.service.curated_cache_file, "r", encoding="utf-8") as f:
      catalog_data = json.load(f)
    self.assertEqual(catalog_data["total_rules"], 1)
    self.assertEqual(catalog_data["total_with_logic"], 1)

    # Verify .yaral file saved
    yaral_files = list(self.service.curated_dir.rglob("ru_12345.yaral"))
    self.assertEqual(len(yaral_files), 1)
    self.assertIn("Suspicious AWS IAM Activity", yaral_files[0].read_text(encoding="utf-8"))


class RuleGenerationTest(unittest.TestCase):

  def setUp(self):
    self.config = LogJammerConfig(api_key="mock_key")
    self.generator = ScenarioGenerator(self.config)

  @mock.patch.object(ScenarioGenerator, "generate")
  def test_generate_from_rule(self, mock_generate):
    mock_sc = GeneratedScenario(
        title="Rule Trigger: m_hunting_powershell_av_exclusion_path_1",
        description="Generated logs to trigger rule",
        logs={
            "WINDOWS_SYSMON": [
                LogEntry(
                    log_type="WINDOWS_SYSMON",
                    content="<Event>Set-MpPreference -ExclusionPath C:\\Temp</Event>",
                    format=LogFormat.RAW,
                    timestamp=datetime.now(timezone.utc),
                )
            ]
        },
    )
    mock_generate.return_value = mock_sc

    rule = SecOpsRule(
        rule_id="ur_sample",
        display_name="m_hunting_powershell_av_exclusion_path_1",
        rule_owner="Google Cloud Security",
        text=SAMPLE_YARAL,
        tactics=["TA0005"],
        techniques=["T1562.001"],
    )

    res = self.generator.generate_from_rule(
        rule=rule,
        outcome="fire",
        count=2,
    )

    self.assertEqual(res.title, "Rule Trigger: m_hunting_powershell_av_exclusion_path_1")
    self.assertTrue(mock_generate.called)

    # Check arguments passed to mock_generate
    call_kwargs = mock_generate.call_args[1]
    self.assertIn("custom_system_prompt", call_kwargs)
    self.assertIn("Rule Satisfaction", call_kwargs["custom_system_prompt"])
    self.assertIn("SCENARIO GENERATION OBJECTIVE", call_kwargs["scenario"])
    self.assertIn("m_hunting_powershell_av_exclusion_path_1", call_kwargs["scenario"])


  def test_load_and_search_curated_rules(self):
    with tempfile.TemporaryDirectory() as tmp_dir:
      tmp_path = Path(tmp_dir)
      cfg = LogJammerConfig(rules_dir=tmp_path)
      service = RuleService(cfg)

      # Create mock curated catalog
      curated_file = tmp_path / "curated_catalog.json"
      mock_curated = {
          "synced_at": datetime.now(timezone.utc).isoformat(),
          "rules": [
              {
                  "rule_id": "ur_curated_01",
                  "display_name": "Google Workspace Chrome Malware Transfer",
                  "text": "rule ttp_ws_chrome_malware { events: $e.metadata.product_name = \"chrome\" condition: $e }",
                  "severity": "High",
                  "description": "Detects malware transfer in Chrome",
                  "author": "Google Cloud Threat Intelligence",
                  "rule_owner": "GOOGLE_CURATED",
                  "precision": "PRECISE",
                  "live_mode_enabled": True,
                  "techniques": ["T1204.002"],
                  "tactics": ["TA0002"],
              },
              {
                  "rule_id": "ur_curated_02",
                  "display_name": "Broad Network Activity",
                  "text": "rule broad_net { condition: $e }",
                  "severity": "Low",
                  "description": "Broad rule",
                  "author": "Google Cloud Threat Intelligence",
                  "rule_owner": "GOOGLE_CURATED",
                  "precision": "BROAD",
                  "live_mode_enabled": True,
                  "techniques": ["T1071"],
                  "tactics": ["TA0011"],
              },
          ]
      }
      curated_file.write_text(json.dumps(mock_curated), encoding="utf-8")

      # Create mock custom catalog
      custom_file = tmp_path / "catalog.json"
      mock_custom = {
          "synced_at": datetime.now(timezone.utc).isoformat(),
          "rules": [
              {
                  "rule_id": "ru_custom_01",
                  "display_name": "Custom Drive Rule",
                  "text": "rule custom_drive { condition: $e }",
                  "severity": "Low",
                  "description": "Customer rule",
                  "rule_owner": "CUSTOMER",
                  "live_mode_enabled": False,
                  "techniques": ["T1567"],
                  "tactics": ["TA0010"],
              }
          ]
      }
      custom_file.write_text(json.dumps(mock_custom), encoding="utf-8")

      # Test loading all
      all_rules = service.load_rules_from_cache(rule_type="all")
      self.assertEqual(len(all_rules), 3)

      # Test filtering curated only
      curated_rules = service.search_rules(rule_type="curated")
      self.assertEqual(len(curated_rules), 2)
      self.assertEqual(curated_rules[0].rule_id, "ur_curated_01")
      self.assertEqual(curated_rules[0].rule_owner, "GOOGLE_CURATED")

      # Test filtering curated by precision
      precise_rules = service.search_rules(rule_type="curated", precision="precise")
      self.assertEqual(len(precise_rules), 1)
      self.assertEqual(precise_rules[0].rule_id, "ur_curated_01")
      self.assertEqual(precise_rules[0].precision, "PRECISE")

      broad_rules = service.search_rules(rule_type="curated", precision="broad")
      self.assertEqual(len(broad_rules), 1)
      self.assertEqual(broad_rules[0].rule_id, "ur_curated_02")
      self.assertEqual(broad_rules[0].precision, "BROAD")

      # Test filtering custom only
      custom_rules = service.search_rules(rule_type="custom")
      self.assertEqual(len(custom_rules), 1)
      self.assertEqual(custom_rules[0].rule_id, "ru_custom_01")

      # Test get_rule by id
      retrieved = service.get_rule("ur_curated_01")
      self.assertIsNotNone(retrieved)
      self.assertEqual(retrieved.display_name, "Google Workspace Chrome Malware Transfer")

  def test_date_filtering_and_sorting(self):
    with tempfile.TemporaryDirectory() as tmp_dir:
      tmp_path = Path(tmp_dir)
      cfg = LogJammerConfig(rules_dir=tmp_path)
      service = RuleService(cfg)

      curated_file = tmp_path / "curated_catalog.json"
      mock_curated = {
          "synced_at": "2026-10-23T12:00:00Z",
          "rules": [
              {
                  "rule_id": "ur_old_01",
                  "display_name": "Older Rule",
                  "text": "rule older_rule { condition: $e }",
                  "severity": "Medium",
                  "rule_owner": "GOOGLE_CURATED",
                  "precision": "PRECISE",
                  "create_time": "2025-01-15T00:00:00Z",
                  "update_time": "2025-06-01T00:00:00Z",
              },
              {
                  "rule_id": "ur_new_02",
                  "display_name": "Recent PHP2Shell Rule",
                  "text": "rule php2shell { condition: $e }",
                  "severity": "High",
                  "rule_owner": "GOOGLE_CURATED",
                  "precision": "BROAD",
                  "create_time": "2026-10-20T10:00:00Z",
                  "update_time": "2026-10-21T15:30:00Z",
              },
          ],
      }
      curated_file.write_text(json.dumps(mock_curated), encoding="utf-8")

      # Filter by updated_after
      recent = service.search_rules(updated_after="2026-10-01")
      self.assertEqual(len(recent), 1)
      self.assertEqual(recent[0].rule_id, "ur_new_02")

      # Filter by created_before
      older = service.search_rules(created_before="2026-01-01")
      self.assertEqual(len(older), 1)
      self.assertEqual(older[0].rule_id, "ur_old_01")

      # Sort by updated descending
      sorted_rules = service.search_rules(sort_by="updated")
      self.assertEqual([r.rule_id for r in sorted_rules], ["ur_new_02", "ur_old_01"])

      # Verify parse_date_spec handles ISO and relative specs
      dt_iso = parse_date_spec("2026-10-01")
      self.assertIsNotNone(dt_iso)
      self.assertEqual(dt_iso.year, 2026)
      dt_rel = parse_date_spec("7d")
      self.assertIsNotNone(dt_rel)

  @mock.patch.object(ScenarioGenerator, "generate")
  def test_generate_from_multiple_rules_with_narrative(self, mock_generate):
    mock_sc = GeneratedScenario(
        title="Multi-Rule Attack Chain",
        description="Generated logs to trigger chain",
        logs={},
    )
    mock_generate.return_value = mock_sc

    r1 = SecOpsRule(
        rule_id="ur_http",
        display_name="ttp_network_php_oom",
        rule_owner="GOOGLE_CURATED",
        text="""
        rule ttp_network_php_oom {
          events:
            $oom.metadata.event_type = "NETWORK_HTTP"
            $probe.metadata.event_type = "NETWORK_HTTP"
          match:
            $ip over 2m
          condition:
            #oom >= 5 and #probe >= 20
        }
        """,
    )
    r2 = SecOpsRule(
        rule_id="ur_linux",
        display_name="ttp_linux_php2shell_rce",
        rule_owner="GOOGLE_CURATED",
        text="""
        rule ttp_linux_php2shell_rce {
          events:
            $e.metadata.event_type = "PROCESS_LAUNCH"
            re.regex($e.principal.process.file.full_path, `/usr/sbin/php-fpm`)
          condition:
            $e
        }
        """,
    )

    self.generator.generate_from_rule(
        rule=[r1, r2],
        outcome="fire",
        scenario_context="Simulate PHP2Shell exploit chain",
    )
    self.assertTrue(mock_generate.called)
    call_kwargs = mock_generate.call_args[1]
    self.assertIn("TARGET YARA-L DETECTION RULE(S) (2 TOTAL)", call_kwargs["scenario"])
    self.assertIn("Simulate PHP2Shell exploit chain", call_kwargs["scenario"])
    self.assertIn("CLOUDFLARE", call_kwargs["log_types"])
    self.assertIn("PAN_CORTEX_XDR_EVENTS", call_kwargs["log_types"])
    # Threshold sum (#oom >= 5 and #probe >= 20 -> 25) + 1 for r2 = 26
    self.assertIn("At least 25 events", call_kwargs["scenario"])
    self.assertIn("at least 26 trigger events across the chain", call_kwargs["scenario"])


if __name__ == "__main__":
  unittest.main()
