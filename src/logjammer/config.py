"""Configuration management for Log Jammer OSS."""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Optional


DEFAULT_MODEL = "gemini-3.7-flash"
DEFAULT_VERTEX_LOCATION = "global"
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
  vertexai: Optional[bool] = None
  vertex_location: str = DEFAULT_VERTEX_LOCATION

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

    if self.vertexai is None:
      env_vertex = (
          os.environ.get("GOOGLE_GENAI_USE_VERTEXAI")
          or os.environ.get("LOGJAMMER_USE_VERTEXAI")
      )
      if env_vertex and env_vertex.strip():
        self.vertexai = env_vertex.strip().lower() in ("1", "true", "yes", "on")

    if self.vertex_location == DEFAULT_VERTEX_LOCATION:
      env_vloc = (
          os.environ.get("LOGJAMMER_VERTEX_LOCATION")
          or os.environ.get("VERTEX_LOCATION")
          or os.environ.get("GOOGLE_CLOUD_LOCATION")
      )
      if env_vloc and env_vloc.strip():
        self.vertex_location = env_vloc.strip()

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

    # Fallback to previously synced catalog metadata if customer_id/project_id not set
    if not self.customer_id or not self.project_id:
      import json
      for cat_name in ("curated_catalog.json", "catalog.json"):
        cat_file = self.rules_dir / cat_name
        if cat_file.exists():
          try:
            with open(cat_file, "r", encoding="utf-8") as f:
              # Only read first 512 bytes to avoid parsing the entire multi-MB catalog on startup
              head = f.read(512)
            import re
            if not self.customer_id:
              m_c = re.search(r'"customer_id"\s*:\s*"([^"]+)"', head)
              if m_c:
                self.customer_id = m_c.group(1)
            if not self.project_id:
              m_p = re.search(r'"project_id"\s*:\s*"([^"]+)"', head)
              if m_p:
                self.project_id = m_p.group(1)
            break
          except Exception:
            pass


def resolve_vertex_adc(config: Optional[LogJammerConfig] = None) -> tuple[Optional[object], Optional[str]]:
  """Resolve Google Cloud ADC credentials and project ID for Vertex AI."""
  cfg = config or LogJammerConfig()
  project = cfg.project_id
  creds = None

  try:
    import google.auth

    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    if cfg.credentials_file:
      from google.oauth2 import service_account

      creds = service_account.Credentials.from_service_account_file(
          cfg.credentials_file, scopes=scopes
      )
      if not project:
        project = getattr(creds, "project_id", None)
    else:
      creds, adc_project = google.auth.default(scopes=scopes)
      if not project:
        project = adc_project or getattr(creds, "quota_project_id", None)
  except Exception:
    creds = None

  if not project:
    import subprocess

    try:
      gcloud_proj = subprocess.check_output(
          ["gcloud", "config", "get-value", "project"],
          stderr=subprocess.DEVNULL,
          text=True,
      ).strip()
      if gcloud_proj and gcloud_proj != "(unset)":
        project = gcloud_proj
    except Exception:
      pass

  return creds, project


def has_vertex_adc(config: Optional[LogJammerConfig] = None) -> bool:
  """Return True if Vertex AI can be initialized via ADC credentials and a project."""
  cfg = config or LogJammerConfig()
  if cfg.vertexai is False:
    return False
  creds, project = resolve_vertex_adc(cfg)
  return bool(creds and project)


def get_genai_client(config: Optional[LogJammerConfig] = None):
  """Instantiate a Google GenAI client using API key or Vertex AI ADC."""
  cfg = config or LogJammerConfig()

  try:
    from google import genai
  except ImportError:
    raise ImportError(
        "The 'google-genai' package is required for AI generation. "
        "Install it via: pip install google-genai"
    )

  # 1. Use Gemini API Key if provided and Vertex AI is not explicitly forced
  if cfg.api_key and not cfg.vertexai:
    try:
      return genai.Client(api_key=cfg.api_key)
    except Exception as e:
      raise ValueError(
          f"[Pre-flight Validation Failed] Invalid Gemini API key ({e}).\n"
          "Please check your GEMINI_API_KEY environment variable."
      ) from None

  # 2. Fallback to (or explicitly use) Vertex AI with Application Default Credentials
  if cfg.vertexai is not False:
    creds, project = resolve_vertex_adc(cfg)
    if creds and project:
      location = cfg.vertex_location or DEFAULT_VERTEX_LOCATION
      try:
        return genai.Client(
            vertexai=True,
            project=project,
            location=location,
            credentials=creds,
        )
      except Exception as e:
        raise ValueError(
            f"[Pre-flight Validation Failed] Failed to initialize Vertex AI client ({e}).\n"
            "Verify your GCP project and ADC credentials via: gcloud auth application-default login"
        ) from None

  raise ValueError(
      "[Pre-flight Validation Failed] Missing required environment variable GEMINI_API_KEY or Vertex AI ADC credentials.\n"
      "Either export a Gemini API key:\n"
      "    export GEMINI_API_KEY=\"your_key_here\"\n"
      "Or authenticate with Google Cloud ADC for Vertex AI:\n"
      "    gcloud auth application-default login\n"
      "    gcloud config set project YOUR_GCP_PROJECT_ID"
  )
