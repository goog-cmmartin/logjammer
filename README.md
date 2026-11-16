# Log Jammer (Open Source Edition)

AI-Powered Synthetic Log Generator for Security Testing, Detection Engineering, and SIEM Validation.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## ⚡ Overview

**Log Jammer** is an open-source framework that creates realistic, multi-source synthetic log events driven by **Google Gemini 3.7 Flash**. It empowers detection engineers, purple teams, and security researchers to simulate complex attack chains across custom and standard log formats without needing live attack infrastructure.

---

## 🚀 Key Features

- **Built-in & Pre-packaged Schema Playbooks**: Includes pre-built format specifications for cloud providers (18 AWS sources: CloudTrail, VPC Flow, GuardDuty, WAF, S3, Route 53, etc.) and enterprise infrastructure (Windows Sysmon, Windows DNS, Cisco ASA, Palo Alto, Microsoft 365).
- **Hierarchical & Multi-Directory Guide Organization**: Organize playbooks neatly into subdirectories (e.g. `guides/AWS/`, `guides/AZURE/`). Discovers `.txt`, `.md`, and `.markdown` files recursively with flexible alias resolution (`AWS_CLOUDTRAIL`, `CLOUDTRAIL`, `VPC_FLOW`).
- **Learn Any Custom Schema**: Provide raw sample logs (`.json`, `.log`, `.csv`, `.raw`) from internal services, custom firewalls, or niche appliances. Log Jammer analyzes the structure and produces an AI schema playbook—even directly into subdirectories.
- **Reverse-Engineer Detection Rules to Synthetic Telemetry**: Ingest Google SecOps curated (`ur_*`) or custom YARA-L 2.0 rules, or local `.yaral` files. Automatically deconstruct positive constraints, negative exclusions (`!=`), thresholds, and entity bindings, then generate realistic raw logs to trigger (`fire`), test false-positive avoidance (`evade`), or simulate an end-to-end incident (`full-chain`).
- **Google SecOps Detection Rule Catalog & CLI**: Synchronize, search, inspect, and analyze curated rules and MITRE ATT&CK techniques directly within Log Jammer without external dependencies.
- **Natural Language Attack Scenarios**: Describe full attack chains in plain English (e.g., *"Spear-phishing email with PDF attachment leading to credential dumping via Mimikatz and S3 exfiltration"*).
- **Dynamic Relative Time Templating**: Automatically resolves chronological offsets (e.g. `##$TimeStamp-0d2h15m0s$##` $\to$ ISO 8601 timestamps) ensuring events tell a coherent chronological story.
- **Pluggable Output Sinks**: Export generated events directly to **JSONL files**, **Syslog (UDP/TCP/TLS)**, **SIEM Webhooks (Splunk HEC, Elastic, Chronicle)**, or **stdout**.
- **Pure Python SDK & CLI**: Zero infrastructure dependencies—run locally with standard `GEMINI_API_KEY`.

## 📦 Installation

Install directly from GitHub:
```bash
git clone https://github.com/goog-cmmartin/logjammer.git
cd logjammer
pip install -r requirements.txt
pip install -e .
```

---

## ⚙️ Configuration & Environment Variables

Log Jammer uses **environment variables** or command-line options for configuration. No dedicated `.conf` or `.ini` file is required.

| Environment Variable | Description | Default / Fallback |
| --- | --- | --- |
| `GEMINI_API_KEY` | **Required**. Google Gemini API Key for log learning and generation. | CLI `--api-key` |
| `GTI_API_KEY` (or `VIRUSTOTAL_API_KEY`) | Google Threat Intelligence / VirusTotal API Key for `--enrich-gti`. | CLI `--gti-api-key` |
| `SECOPS_CUSTOMER_ID` / `CHRONICLE_CUSTOMER_ID` | Google SecOps / Chronicle Instance Customer ID for direct log replay. | URI `secops://CUSTOMER_ID` |
| `GCP_PROJECT_NUMBER` / `GOOGLE_CLOUD_PROJECT` | GCP Project ID or Number for Google SecOps `v1alpha` API ingestion. | CLI `--project` |
| `CHRONICLE_REGION` | Google SecOps API region (`us`, `europe-west1`, `asia-east1`, etc.). | `us` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP Service Account JSON credentials for SecOps authentication. | `gcloud` ADC |
| `LOGJAMMER_MODEL` | Gemini model to use for schema learning and generation. | `gemini-3.7-flash` |
| `LOGJAMMER_GUIDES_DIR` | Path to directory storing learned AI schema guide playbooks. | `~/.logjammer/guides` |

---

## 🛠️ CLI Quickstart

### 1. Learn a Custom Log Schema
Feed a sample file OR an entire directory containing multiple sample event files (e.g., `login.json`, `privilege_change.json`):
```bash
# Learn from a single sample file
logjammer learn --type CUSTOM_AUTH --sample ./samples/auth/login.json

# Or learn from an entire directory of diverse event samples
logjammer learn --type OKTA --sample ./samples/identity/okta/
```

### 2. List & Inspect Guides
```bash
# List all available log types across root and subdirectories (e.g. guides/AWS/)
logjammer list

# Display schema guides using canonical names, aliases, or paths
logjammer show-guide --type AWS_CLOUDTRAIL
logjammer show-guide --type VPC_FLOW
logjammer show-guide --type WINDOWS_SYSMON
```

### 3. Generate Synthetic Attack Logs
Generate multi-source attack logs across cloud and endpoint telemetry:
```bash
logjammer generate \
  --scenario "Compromised AWS IAM credentials used to modify S3 bucket policy and exfiltrate data via anomalous VPC flow" \
  --types AWS_CLOUDTRAIL,AWS_VPC_FLOW,WINDOWS_SYSMON \
  --output ./attack_scenario.jsonl
```

### 4. Enrich Scenario with Google Threat Intelligence (GTI)
Use the GTI Agent to enrich your prompt with real-world IOCs, commands, and MITRE ATT&CK techniques before generation:
```bash
export GTI_API_KEY="your-gti-api-key"

logjammer generate \
  --scenario "BlackSuit ransomware infection and lateral movement" \
  --types WINDOWS_SYSMON,WINDOWS_DNS \
  --enrich-gti \
  --show-gti-enrichment \
  --output ./ransomware_simulation.jsonl
```

### 5. Replay Directly to Google SecOps (Chronicle) or Syslog
```bash
# Stream directly to network Syslog (UDP/TCP)
logjammer generate \
  --scenario "Port scan followed by SQL injection" \
  --types PAN_FIREWALL,APACHE \
  --output syslog://siem.corp.internal:514

# Replay directly into Google SecOps (Chronicle) SIEM with custom scenario tags & labels
logjammer generate \
  --scenario "Phishing email leading to credential dumping" \
  --types OFFICE_365,WINDOWS_SYSMON \
  --output secops://YOUR_SECOPS_CUSTOMER_ID@us \
  --project YOUR_GCP_PROJECT_ID \
  --scenario-name office_worker_simulation \
  --label TEAM=blue_team \
  --label ENVIRONMENT=staging
```

### 6. Local Scenario Storage & Instant Replay (No LLM Required)
Every generated scenario is automatically stored locally in `~/.logjammer/scenarios/<ID>.json`. You can list, view, save, and instant-replay scenarios to SIEMs or files on demand **without consuming LLM tokens**:

```bash
# List all locally cached scenarios
logjammer scenario list

# Show details and log breakdown for a specific scenario
logjammer scenario show a1b2c3d4

# Export scenario JSON to a custom file or folder
logjammer scenario save a1b2c3d4 -o ./my_scenario.json

# Instant-replay scenario directly to Google SecOps or Syslog (0 LLM latency or token usage)
logjammer replay \
  -s a1b2c3d4 \
  -o secops://YOUR_SECOPS_CUSTOMER_ID@us \
  -p YOUR_GCP_PROJECT_ID \
  --scenario-name background_worker_replay
```

### 7. Expand SOAR / SIEM Case Reports (`--from-case`)
Feed a raw case report or SOAR alert summary (`~/case.txt`) into Log Jammer. Log Jammer automatically infers the required SIEM log types, pins core entities, and generates full pre-incident setup and post-incident outcome events:

```bash
# Expand case with auto-inferred log types and default 30m pre/post time windows
logjammer generate \
  --from-case ~/case.txt \
  --surround-before 30m \
  --surround-after 30m \
  --outcome benign \
  --output secops://YOUR_SECOPS_CUSTOMER_ID@us \
  --project YOUR_GCP_PROJECT_ID
```

### 8. Work Backwards from SecOps Rules (`--from-rule`, `--from-technique`)
Generate synthetic telemetry tailored specifically to trigger or validate YARA-L 2.0 detection rules:

```bash
# 1. Sync rule catalog from your Google SecOps tenant (Curated + Custom)
logjammer rules sync --all
# Or sync only curated rules from Content Hub
logjammer rules sync --curated

# 2. Search rules by MITRE technique or keyword
logjammer rules list --technique T1562.008
logjammer rules list --search powershell

# 3. Inspect rule logic and automated trigger deconstruction
logjammer rules show aws_cloudtrail_logging_tampered

# 4. Generate synthetic logs to trigger ('fire') the detection
logjammer generate \
  --from-rule aws_cloudtrail_logging_tampered \
  --rule-outcome fire \
  --output ./cloudtrail_tamper.jsonl

# 5. Generate logs directly by MITRE technique
logjammer generate \
  --from-technique T1562.008 \
  --rule-outcome fire \
  --output ./technique_simulation.jsonl

# 6. Test false positive avoidance ('evade') or full attack progression ('full-chain')
logjammer generate \
  --from-rule m_hunting_powershell_av_exclusion_path_1 \
  --rule-outcome evade \
  --output ./evasion_test.jsonl

# 7. Use a local YARA-L rule file (.yaral or .json)
logjammer generate \
  --from-rule ./my_custom_rule.yaral \
  --rule-outcome fire \
  --output secops://YOUR_SECOPS_CUSTOMER_ID@us
```

---

## 📚 Schema Guides & Directory Organization

Log Jammer discovers schema guides recursively from the configured guides directory (`~/.logjammer/guides`, `./guides`, or `--guides-dir`). Both `.txt`, `.md`, and `.markdown` files are supported.

### Pre-packaged Guides
- **AWS Cloud Telemetry (`guides/AWS/`)**: 18 playbooks covering `AWS_CLOUDTRAIL`, `AWS_VPC_FLOW`, `AWS_GUARDDUTY`, `AWS_WAF`, `AWS_S3`, `AWS_ROUTE53`, `AWS_EC2`, `AWS_ELB`, `AWS_LAMBDA`, `AWS_COGNITO`, `AWS_CONFIG`, `AWS_DYNAMODB`, `AWS_ECS`, `AWS_RDS`, `AWS_SSM`, `AWS_STS`, and `AWS_NETWORK_FIREWALL`.
- **Enterprise Infrastructure (`guides/`)**: `WINDOWS_SYSMON`, `WINDOWS_DNS`, `CISCO_ASA_FIREWALL`, `PAN_FIREWALL`, `OFFICE_365`, `OFFICE_365_MESSAGETRACE`.

### Flexible Identifier Matching
When specifying `--types` or querying guides, Log Jammer automatically matches:
- **Canonical / Normalized names**: `AWS_CLOUDTRAIL`, `CLOUDTRAIL`, `AWS_VPC_FLOW`, `VPC_FLOW`, `AWS_GUARDDUTY`, etc.
- **Official SecOps header tags**: Extracted directly from format references (`Official SecOps Log Type: <TYPE>`).
- **Relative directory paths**: `AWS/cloudtrail_log_format_reference`, `AWS/vpc_flow_logs_format_reference`.
- **Filename stems**: `cloudtrail_log_format_reference`, `CISCO_ASA_FIREWALL`.

---

## 🐍 Python SDK Usage

```python
import logjammer

# 1. Initialize client
client = logjammer.LogJammer()

# 2. Learn a custom log format from a file
client.learn(
    log_type="PAYMENT_GATEWAY",
    sample="sample_payment_logs.json"
)

# 3. Generate a scenario (optionally enriched with GTI)
scenario = client.generate(
    scenario="Failed login bursts from TOR exit nodes followed by successful API token creation",
    log_types=["PAYMENT_GATEWAY", "OKTA"],
    enrich_gti=True
)

# 4. Generate logs tailored to a Google SecOps detection rule
rule = client.get_rule("aws_cloudtrail_logging_tampered")
rule_scenario = client.generate_from_rule(
    rule=rule,
    outcome="fire",
    count=2,
)

# 5. Export to file or SIEM (JSONL, Syslog, Webhook, SecOps)
client.export(
    scenario,
    destination="secops://YOUR_SECOPS_CUSTOMER_ID@us",
    project="YOUR_GCP_PROJECT",
    scenario_name="remote_worker_simulation",
    labels={"TEAM": "red_team", "ENVIRONMENT": "lab"}
)
print(f"Generated and ingested {scenario.total_log_count} realistic events into Google SecOps!")
```

---

## 🧪 Testing

Run test suite:
```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

### Checking schema guides

A guide that teaches the generator a time tag the engine cannot fill, or a field layout the parser rejects, produces logs that look fine but carry placeholders or wrong event times. Two checks catch this.

`scripts/check_guides.py` needs no network access. It lists time template tags that LogJammer cannot fill. The same check runs in the unit tests for the bundled guides, and `logjammer learn` exits with code 2 when a new guide contains such a tag.
```bash
python scripts/check_guides.py                      # ./guides and ~/.logjammer/guides
python scripts/check_guides.py path/to/guides
```

`scripts/check_guide_examples.py` needs a Google SecOps instance. It runs every guide's example log lines through the SecOps `runParser` API, which ingests nothing, and reports examples that fail to parse or whose event time was not read from the log.
```bash
export CHRONICLE_CUSTOMER_ID=<customer-id> GOOGLE_CLOUD_PROJECT=<project>
python scripts/check_guide_examples.py
python scripts/check_guide_examples.py --types PAN_FIREWALL OKTA --json-out report.json
```
Log types with no parser on the instance are skipped unless `--parser-config-dir` points to a folder of `<LOG_TYPE>.conf` files. Some parsers do not read the event time for some formats, so time problems only fail the run with `--strict-time`.

### Time template tags

| Tag | Output |
| :--- | :--- |
| `##$TimeStamp-0d2h15m0s$##` | ISO 8601 UTC with milliseconds |
| `##$Epoch-0d1h0m0s$##` | Unix seconds |
| `##$EpochMS-0d1h0m0s$##` | Unix milliseconds |
| `##$EpochMicroseconds-0d1h0m0s$##`, `##$EpochNanoseconds-0d1h0m0s$##` | Unix microseconds, nanoseconds |
| `##$Date-0d0h0m0s$##` | `YYYY-MM-DD` |
| `##$SyslogTime-0d0h45m0s$##` | `Aug 24 11:15:00`, with no year |
| `##$TimeStamp-0d0h45m0s\|%Y/%m/%d %H:%M:%S$##` | Any `strftime` layout. `%3f` is milliseconds and `%:z` is an offset with a colon. `yyyy/MM/dd HH:mm:ss` style tokens also work. |
| `##$TimeStamp-0d0h45m0s\|%Y-%m-%dT%H:%M:%S%:z\|-08:00$##` | The same, rendered in a fixed UTC offset |

The offset after the tag name is optional. The format separator is a pipe.
