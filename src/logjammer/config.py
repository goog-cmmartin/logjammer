"""Configuration management for Log Jammer OSS."""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Optional


DEFAULT_MODEL = "gemini-3.7-flash"
DEFAULT_GUIDES_DIR = Path.home() / ".logjammer" / "guides"
DEFAULT_SCENARIOS_DIR = Path.home() / ".logjammer" / "scenarios"
DEFAULT_RULES_DIR = Path.home() / ".logjammer" / "rules"


@dataclass
class LogJammerConfig:
  """Configuration settings for Log Jammer."""

  api_key: Optional[str] = None
  gti_api_key: Optional[str] = None
  model: str = DEFAULT_MODEL
  temperature: float = 1.0
  top_p: float = 0.95
  thinking_budget: int = -1
  guides_dir: Path = field(default_factory=lambda: DEFAULT_GUIDES_DIR)
  scenarios_dir: Path = field(default_factory=lambda: DEFAULT_SCENARIOS_DIR)
  rules_dir: Path = field(default_factory=lambda: DEFAULT_RULES_DIR)
  customer_id: Optional[str] = None
  project_id: Optional[str] = None
  region: str = "us"
  credentials_file: Optional[str] = None

  def __post_init__(self):
    if not self.api_key:
      env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
      self.api_key = env_key.strip() if env_key and env_key.strip() else None

    if not self.gti_api_key:
      env_gti = (
          os.environ.get("GTI_API_KEY")
          or os.environ.get("VIRUSTOTAL_API_KEY")
          or os.environ.get("VT_API_KEY")
      )
      self.gti_api_key = env_gti.strip() if env_gti and env_gti.strip() else None

    env_model = os.environ.get("LOGJAMMER_MODEL")
    if env_model and env_model.strip():
      self.model = env_model.strip()

    if self.guides_dir == DEFAULT_GUIDES_DIR:
      env_guides = os.environ.get("LOGJAMMER_GUIDES_DIR")
      if env_guides and env_guides.strip():
        self.guides_dir = Path(env_guides.strip())

    if self.scenarios_dir == DEFAULT_SCENARIOS_DIR:
      env_scenarios = os.environ.get("LOGJAMMER_SCENARIOS_DIR")
      if env_scenarios and env_scenarios.strip():
        self.scenarios_dir = Path(env_scenarios.strip())

    if self.rules_dir == DEFAULT_RULES_DIR:
      env_rules = os.environ.get("LOGJAMMER_RULES_DIR")
      if env_rules and env_rules.strip():
        self.rules_dir = Path(env_rules.strip())

    if not self.customer_id:
      env_cust = (
          os.environ.get("CHRONICLE_CUSTOMER_ID")
          or os.environ.get("SECOPS_CUSTOMER_ID")
      )
      self.customer_id = env_cust.strip() if env_cust and env_cust.strip() else None

    if not self.project_id:
      env_proj = (
          os.environ.get("CHRONICLE_PROJECT_NUMBER")
          or os.environ.get("GCP_PROJECT_NUMBER")
          or os.environ.get("GOOGLE_CLOUD_PROJECT")
          or os.environ.get("GCP_PROJECT_ID")
      )
      self.project_id = env_proj.strip() if env_proj and env_proj.strip() else None

    env_reg = os.environ.get("CHRONICLE_REGION")
    if env_reg and env_reg.strip():
      self.region = env_reg.strip().lower()

    if not self.credentials_file:
      env_cred = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
      self.credentials_file = env_cred.strip() if env_cred and env_cred.strip() else None

    # Ensure directories exist
    self.guides_dir.mkdir(parents=True, exist_ok=True)
    self.scenarios_dir.mkdir(parents=True, exist_ok=True)
    self.rules_dir.mkdir(parents=True, exist_ok=True)


def get_genai_client(config: Optional[LogJammerConfig] = None):
  """Instantiate a Google GenAI client using configuration."""
  cfg = config or LogJammerConfig()
  if not cfg.api_key:
    raise ValueError(
        "[Pre-flight Validation Failed] Missing required environment variable GEMINI_API_KEY.\n"
        "Please export a valid API key:\n"
        "    export GEMINI_API_KEY=\"your_key_here\"\n"
        "Or pass --api-key \"your_key_here\" on the command line.\n"
        "Get an API key at: https://aistudio.google.com/app/apikey"
    )

  try:
    from google import genai
  except ImportError:
    raise ImportError(
        "The 'google-genai' package is required for AI generation. "
        "Install it via: pip install google-genai"
    )

  try:
    return genai.Client(api_key=cfg.api_key)
  except Exception as e:
    raise ValueError(
        f"[Pre-flight Validation Failed] Invalid Gemini API key ({e}).\n"
        "Please check your GEMINI_API_KEY environment variable."
    ) from None

