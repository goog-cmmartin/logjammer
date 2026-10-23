"""AI-powered scenario log generation service."""

from datetime import datetime, timezone
import json
import re
from typing import Dict, List, Optional, Union
try:
  from google.genai import types
except ImportError:
  types = None

from .config import LogJammerConfig, get_genai_client
from .gti import GTIClient
from .models import GeneratedScenario, LogEntry, LogFormat, RuleAnalysis, SecOpsRule
from .playbook import PlaybookService
from .rule_analyzer import RuleAnalyzer
from .rules import RuleService
from .templates import replace_time_templates


SCENARIO_SYSTEM_PROMPT = """You are an elite Red Team Operator and Security Telemetry Architect.
Your task is to generate highly authentic, realistic, multi-source synthetic logs depicting a security scenario.

You will be given:
1. A natural language scenario narrative (e.g., "Phishing email leading to Cobalt Strike beacon and ransomware encryption").
2. The requested log types (e.g. OKTA, CS_EDR, BIND_DNS, PAN_FIREWALL).
3. Detailed Schema Guides for each log type detailing required fields, delimiters, headers, and timestamp formats.

CRITICAL RULES:
1. **Schema Fidelity**: Strictly follow the provided Schema Guides for each log type. Every log line must conform to real-world format expectations.
2. **Cohesive Narrative**: Ensure all events across different log sources correlate coherently:
   - Usernames, internal IP addresses, external C2 IPs, and hostnames must match across different log types.
   - The timeline must progress logically (initial recon -> delivery -> execution -> persistence -> lateral movement -> exfiltration/impact).
3. **Relative Time Templating**:
   - Never hardcode static timestamps!
   - Use relative template tags:
     * ISO 8601: `##$TimeStamp-0d2h15m0s$##` (e.g. 2 hours 15 minutes before trigger)
     * Unix Epoch: `##$Epoch-0d1h30m0s$##`
     * Syslog: `##$SyslogTime-0d0h45m0s$##`
4. **Output Format**:
   Return a single valid JSON object with the following structure:
   ```json
   {
     "title": "Short descriptive title of the attack scenario",
     "summary": "2-3 sentence overview of the simulated attack chain",
     "logs": {
       "<LOG_TYPE_1>": [
         "log line 1 or JSON string",
         "log line 2 or JSON string"
       ],
       "<LOG_TYPE_2>": [
         "log line 1",
         "log line 2"
       ]
     }
   }
   ```
   Do not include any conversational preamble outside the JSON markdown block.
"""

RULE_SYSTEM_PROMPT = """You are an elite Detection Engineer and Security Telemetry Specialist.
Your task is to reverse-engineer and generate synthetic raw logs that will be parsed by Google SecOps (Chronicle SIEM) and trigger one or more specific YARA-L 2.0 detection rules.

You will be given:
1. The target YARA-L detection rule(s) (logic, metadata, MITRE techniques).
2. The deconstructed UDM constraints (required event types, positive regex/string criteria, negative exclusions to avoid, thresholds, and time windows).
3. The target log source type(s) and their detailed Schema Guides.
4. The generation objective: 'fire' (trigger detection), 'evade' (negative test), or 'full-chain' (end-to-end simulation).

CRITICAL RULES:
1. **Rule Satisfaction**:
   - For 'fire' or 'full-chain': Ensure the generated logs contain the exact strings, regexes, parameters, and UDM fields specified in the positive constraints for EVERY target rule.
   - Strictly avoid matching any negative exclusion patterns (clauses with '!=' or 'not (...)') so the rules do not discard the events.
   - If a rule requires a threshold (e.g. count > 5), generate at least that many distinct events within the specified match window.
   - If a rule is a multi-event join or part of a multi-rule attack chain, bind matching entity fields (e.g. same user, IP, hostname, and parent/child process hierarchy) across the events in proper chronological sequence.
2. **Schema Fidelity**:
   - Format each log line strictly according to the Schema Guide for the target log source (e.g. Windows Sysmon XML/Key-Value, CEF, JSON, Syslog).
   - Ensure the fields that Google SecOps parsers use to populate the target UDM attributes (e.g. CommandLine, ParentImage, TargetUserName, IpAddress, ClientRequestURI) are realistically placed in the raw log.
3. **Relative Time Templating**:
   - Use relative template tags:
     * ISO 8601: `##$TimeStamp-0d0h5m0s$##`
     * Unix Epoch: `##$Epoch-0d0h5m0s$##`
     * Syslog: `##$SyslogTime-0d0h5m0s$##`
4. **Output Format**:
   Return a single valid JSON object:
   ```json
   {
     "title": "Trigger simulation for <RULE_NAME>",
     "summary": "Explanation of how the generated logs satisfy the YARA-L detection logic",
     "logs": {
       "<LOG_TYPE>": [
         "log line 1",
         "log line 2"
       ]
     }
   }
   ```
   Do not include any conversational preamble outside the JSON markdown block.
"""


class ScenarioGenerator:
  """Generates multi-source synthetic logs for arbitrary security scenarios."""

  def __init__(
      self,
      config: Optional[LogJammerConfig] = None,
      playbook_service: Optional[PlaybookService] = None,
      gti_client: Optional[GTIClient] = None,
      rule_service: Optional[RuleService] = None,
      rule_analyzer: Optional[RuleAnalyzer] = None,
  ):
    self.config = config or LogJammerConfig()
    self.playbook_service = playbook_service or PlaybookService(self.config)
    self.gti_client = gti_client or GTIClient(api_key=self.config.gti_api_key)
    self.rule_service = rule_service or RuleService(self.config)
    available_types = self.playbook_service.list_available_log_types()
    self.rule_analyzer = rule_analyzer or RuleAnalyzer(available_types)
    self._client = None

  @property
  def client(self):
    if self._client is None:
      self._client = get_genai_client(self.config)
    return self._client

  def _build_prompt(
      self,
      scenario: str,
      log_types: List[str],
      custom_system_prompt: Optional[str] = None,
  ) -> str:
    """Construct the full generation prompt including schema guides."""
    guides_section = []
    for lt in log_types:
      guide = self.playbook_service.get_guide(lt)
      if guide:
        guides_section.append(f"### Schema Guide for {lt}:\n{guide}\n")
      else:
        guides_section.append(
            f"### Schema Guide for {lt}:\n(No saved guide found. Use standard industry format for {lt}.)\n"
        )

    guides_text = "\n".join(guides_section)

    return f"""## Scenario Description:
{scenario}

## Requested Log Types:
{', '.join(log_types)}

## Log Type Schema Guides:
{guides_text}

Generate the complete attack scenario logs as specified."""

  def generate(
      self,
      scenario: str,
      log_types: List[str],
      base_time: Optional[datetime] = None,
      custom_system_prompt: Optional[str] = None,
      enrich_gti: bool = False,
  ) -> GeneratedScenario:
    """Generate synthetic logs for the specified scenario."""
    if not log_types:
      raise ValueError("At least one log type must be provided.")
    if not scenario or len(scenario.strip()) < 10:
      raise ValueError("Scenario description must be at least 10 characters.")

    enriched_text = None
    actual_scenario = scenario
    if enrich_gti:
      enriched_text = self.gti_client.enrich_scenario(scenario)
      actual_scenario = f"""### User High-Level Intent:
{scenario}

### Google Threat Intelligence (GTI) Real-World Scenario & Indicators:
{enriched_text}
"""

    prompt = self._build_prompt(actual_scenario, log_types, custom_system_prompt)
    system_instruction = custom_system_prompt or SCENARIO_SYSTEM_PROMPT

    try:
      from google.genai import types as genai_types
      gen_config = genai_types.GenerateContentConfig(
          system_instruction=system_instruction,
          temperature=self.config.temperature,
          top_p=self.config.top_p,
          response_mime_type="application/json",
          thinking_config=genai_types.ThinkingConfig(
              thinking_budget=self.config.thinking_budget,
          ),
      )
    except (ImportError, AttributeError):
      gen_config = None

    response = self.client.models.generate_content(
        model=self.config.model,
        contents=prompt,
        config=gen_config,
    )

    raw_text = response.text or "{}"
    return self._parse_response(
        raw_text, scenario, base_time, enriched_narrative=enriched_text
    )

  def _parse_response(
      self,
      raw_text: str,
      scenario_description: str,
      base_time: Optional[datetime] = None,
      enriched_narrative: Optional[str] = None,
  ) -> GeneratedScenario:
    """Parse Gemini's JSON response and resolve time templates."""
    # Strip optional markdown code fence
    cleaned = raw_text.strip()
    if cleaned.startswith("```json"):
      cleaned = cleaned[7:]
    if cleaned.startswith("```"):
      cleaned = cleaned[3:]
    if cleaned.endswith("```"):
      cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    try:
      data = json.loads(cleaned)
    except json.JSONDecodeError:
      # Fallback: extract json using regex
      match = re.search(r"\{.*\}", cleaned, re.DOTALL)
      if match:
        data = json.loads(match.group(0))
      else:
        data = {"title": "Generated Scenario", "logs": {}}

    title = data.get("title", "Synthetic Attack Scenario")
    raw_logs = data.get("logs", {})

    parsed_logs: Dict[str, List[LogEntry]] = {}

    for log_type, entries in raw_logs.items():
      parsed_logs[log_type] = []
      for entry in entries:
        # Convert dict to JSON string if needed
        if isinstance(entry, (dict, list)):
          entry_str = json.dumps(entry)
          fmt = LogFormat.JSON
        else:
          entry_str = str(entry)
          fmt = LogFormat.JSON if entry_str.strip().startswith(("{", "[")) else LogFormat.RAW

        # Resolve relative timestamps into real dates
        resolved_content = replace_time_templates(entry_str, base_time)

        parsed_logs[log_type].append(
            LogEntry(
                log_type=log_type,
                content=resolved_content,
                format=fmt,
                timestamp=base_time or datetime.now(timezone.utc),
            )
        )

    return GeneratedScenario(
        title=title,
        description=scenario_description,
        logs=parsed_logs,
        raw_response=raw_text,
        enriched_narrative=enriched_narrative,
    )

  def infer_log_types(self, case_text: str) -> List[str]:
    """Analyze a case report and infer the appropriate SIEM log types from available playbooks."""
    available_types = self.playbook_service.list_available_log_types()
    available_str = (
        ", ".join(available_types)
        if available_types
        else "AWS_CLOUDTRAIL, AWS_VPC_FLOW, GUARDDUTY, OKTA, WINDOWS_SYSMON, GCP_CLOUDAUDIT"
    )

    prompt = f"""Given the following Security Case Report / Incident Alert Summary, identify the most relevant SIEM log types required to generate full surrounding telemetry (Pre-incident setup, Core alert events, and Post-incident outcome).

Available Log Jammer Playbook Schemas:
{available_str}

Case Report:
{case_text}

Return a valid JSON array of 1 to 5 matching log type strings (e.g. ["AWS_CLOUDTRAIL", "AWS_VPC_FLOW"]).
Return ONLY the JSON array."""

    try:
      from google.genai import types as genai_types
      gen_config = genai_types.GenerateContentConfig(
          response_mime_type="application/json",
          temperature=0.2,
      )
      response = self.client.models.generate_content(
          model=self.config.model,
          contents=prompt,
          config=gen_config,
      )
      data = json.loads(response.text)
      if isinstance(data, list) and data:
        return [str(x) for x in data]
    except Exception:
      pass

    # Heuristic fallback matching keywords
    text_lower = case_text.lower()
    inferred = []
    if any(k in text_lower for k in ("aws", "cloudtrail", "glue", "iam", "sts", "s3")):
      inferred.append("AWS_CLOUDTRAIL")
      if any(k in text_lower for k in ("ip", "network", "connection", "vpc", "flow")):
        inferred.append("AWS_VPC_FLOW")
    elif any(k in text_lower for k in ("gcp", "google", "bigquery")):
      inferred.append("GCP_CLOUDAUDIT")
    elif any(k in text_lower for k in ("azure", "entra")):
      inferred.append("AZURE_ACTIVITY")
    elif "slack" in text_lower:
      inferred.append("SLACK_AUDIT")
    elif "github" in text_lower:
      inferred.append("GITHUB")

    return inferred or ["AWS_CLOUDTRAIL"]

  def generate_from_case(
      self,
      case_text: str,
      log_types: Optional[List[str]] = None,
      surround_before: str = "30m",
      surround_after: str = "30m",
      outcome: str = "benign",
      base_time: Optional[datetime] = None,
      custom_system_prompt: Optional[str] = None,
      enrich_gti: bool = False,
  ) -> GeneratedScenario:
    """Generate a multi-stage surrounding log scenario from an input case report."""
    if not log_types:
      log_types = self.infer_log_types(case_text)

    case_scenario_prompt = f"""### INPUT CASE REPORT / INCIDENT ALERT:
{case_text}

### SCENARIO GENERATION REQUIREMENTS:
1. **Pre-Incident Phase (-{surround_before} before anchor timeline)**:
   Generate initial authentication, network handshakes, STS session creation, API key lookups, or user activity leading up to the case events.
2. **Core Incident Anchor Phase**:
   Re-create the exact sequence of events detailed in the case report timeline.
3. **Post-Incident Phase (+{surround_after} after anchor timeline)**:
   Generate the outcome activity based on the specified verdict/outcome: '{outcome}'.
   If benign: routine data verification, cleanup, session logout, or normal scheduled task completion.
   If malicious: credential dumping, data exfiltration, lateral movement, or backdoor creation.
4. **Entity Consistency**:
   Re-use all exact IPs, usernames, role ARNs, session IDs, hostnames, and account IDs from the case report across all generated log types.
"""
    return self.generate(
        scenario=case_scenario_prompt,
        log_types=log_types,
        base_time=base_time,
        custom_system_prompt=custom_system_prompt,
        enrich_gti=enrich_gti,
    )

  def _resolve_rule(self, rule: Union[SecOpsRule, str]) -> SecOpsRule:
    if isinstance(rule, SecOpsRule):
      return rule
    rule_obj = self.rule_service.get_rule(rule)
    if not rule_obj:
      # Check if rule string is raw YARA-L rule code
      if "rule " in rule and ("meta:" in rule or "events:" in rule or "condition:" in rule):
        from .rules import extract_mitre_ids
        techs, tacs = extract_mitre_ids({}, rule)
        rule_name_match = re.search(r"rule\s+([A-Za-z0-9_]+)", rule)
        rule_obj = SecOpsRule(
            rule_id=rule_name_match.group(1) if rule_name_match else "custom_rule",
            display_name=rule_name_match.group(1) if rule_name_match else "Custom Rule",
            text=rule,
            techniques=techs,
            tactics=tacs,
        )
      else:
        raise ValueError(
            f"Could not find SecOps rule '{rule}' in local cache, files, or tenant API."
        )
    return rule_obj

  def generate_from_rule(
      self,
      rule: Union[SecOpsRule, str, List[Union[SecOpsRule, str]]],
      log_types: Optional[List[str]] = None,
      outcome: str = "fire",
      base_time: Optional[datetime] = None,
      custom_system_prompt: Optional[str] = None,
      count: Optional[int] = None,
      scenario_context: Optional[str] = None,
  ) -> GeneratedScenario:
    """Generate synthetic logs engineered to trigger or test one or more YARA-L rules."""
    if isinstance(rule, list):
      rule_objs = [self._resolve_rule(r) for r in rule]
    elif isinstance(rule, str) and "," in rule and "rule " not in rule:
      rule_objs = [self._resolve_rule(r.strip()) for r in rule.split(",") if r.strip()]
    else:
      rule_objs = [self._resolve_rule(rule)]

    analyses = [self.rule_analyzer.analyze(r) for r in rule_objs]

    # Inferred log types if not provided
    if not log_types:
      inferred: List[str] = []
      for a in analyses:
        for lt in a.suggested_log_types[:2]:
          if lt not in inferred:
            inferred.append(lt)
      log_types = inferred if inferred else ["WINDOWS_SYSMON"]

    # Target event count
    total_threshold = sum(max(a.threshold_count, 1) for a in analyses)
    target_count = count or total_threshold

    rules_blocks: List[str] = []
    for idx, (r_obj, a_obj) in enumerate(zip(rule_objs, analyses), start=1):
      rules_blocks.append(
          f"#### RULE {idx} OF {len(rule_objs)}: {r_obj.display_name} ({r_obj.rule_id})\n"
          f"MITRE Techniques: {', '.join(a_obj.techniques) if a_obj.techniques else 'N/A'}\n"
          f"MITRE Tactics: {', '.join(a_obj.tactics) if a_obj.tactics else 'N/A'}\n\n"
          f"**YARA-L 2.0 Rule Text**:\n```yara\n{r_obj.text}\n```\n\n"
          f"**Trigger Analysis & UDM Requirements**:\n{a_obj.summary}"
      )

    context_section = ""
    if scenario_context:
      context_section = f"\n### ADDITIONAL SCENARIO NARRATIVE & STORY CONTEXT:\n{scenario_context}\n"

    rules_joined = "\n\n---\n\n".join(rules_blocks)
    rule_scenario_prompt = f"""### TARGET YARA-L DETECTION RULE(S) ({len(rule_objs)} TOTAL):
{rules_joined}
{context_section}
### SCENARIO GENERATION OBJECTIVE:
Objective: '{outcome.upper()}'
- If 'fire': You MUST generate a cohesive, realistic sequence of logs that triggers EVERY ONE of the {len(rule_objs)} target detection rule(s) listed above. Every positive constraint in each rule must be matched, and exclusions MUST be strictly avoided. Ensure all shared entities (hostnames, IPs, users, parent/child process trees) are consistent across the attack chain.
- If 'evade' or 'negative': Deliberately generate activity that resembles the threat but hits at least one exclusion clause (to verify false positive defense).
- If 'full-chain': Generate pre-incident recon/initial access, followed by all {len(rule_objs)} rule trigger phases (at least {target_count} trigger events across the chain), followed by post-incident activity and cross-source telemetry correlation.

Generate raw logs in the specified log format(s) ({', '.join(log_types)}) that Google SecOps parsers will convert into UDM events satisfying all target rules.
"""
    system_instruction = custom_system_prompt or RULE_SYSTEM_PROMPT
    return self.generate(
        scenario=rule_scenario_prompt,
        log_types=log_types,
        base_time=base_time,
        custom_system_prompt=system_instruction,
    )
