"""Log Jammer - AI-Powered Synthetic Log Generation Library."""

from .client import LogJammer
from .config import LogJammerConfig
from .generator import ScenarioGenerator
from .models import GeneratedScenario, LearnResult, LogEntry, LogFormat, LogTypeGuide, RuleAnalysis, SecOpsRule
from .playbook import PlaybookService
from .rule_analyzer import RuleAnalyzer
from .rules import RuleService
from .sinks.base import BaseSink
from .sinks.file import FileSink
from .sinks.syslog import SyslogSink
from .sinks.webhook import WebhookSink
from .templates import TimeTemplateService, replace_time_templates, replace_time_templates_in_logs

__version__ = "0.2.0"

__all__ = [
    "LogJammer",
    "LogJammerConfig",
    "LogEntry",
    "LogFormat",
    "LogTypeGuide",
    "GeneratedScenario",
    "LearnResult",
    "SecOpsRule",
    "RuleAnalysis",
    "TimeTemplateService",
    "PlaybookService",
    "ScenarioGenerator",
    "RuleService",
    "RuleAnalyzer",
    "replace_time_templates",
    "replace_time_templates_in_logs",
    "BaseSink",
    "FileSink",
    "SyslogSink",
    "WebhookSink",
]
