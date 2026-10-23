"""Unit tests for pre-flight validation of environment variables and credentials."""

import os
import unittest
from unittest import mock

from logjammer.client import LogJammer
from logjammer.config import LogJammerConfig, get_genai_client
from logjammer.sinks.secops import SecOpsSink


class PreflightValidationTest(unittest.TestCase):

  @mock.patch("logjammer.client.has_vertex_adc", return_value=False)
  def test_blank_gemini_api_key_fails_preflight(self, _mock_adc):
    config = LogJammerConfig(api_key="")
    client = LogJammer(api_key="")
    # Manually set api_key to None/empty
    client.config.api_key = None

    with self.assertRaises(ValueError) as ctx:
      client.validate_preflight(require_genai=True)

    self.assertIn("[Pre-flight Validation Failed]", str(ctx.exception))
    self.assertIn("GEMINI_API_KEY", str(ctx.exception))

  @mock.patch("logjammer.client.has_vertex_adc", return_value=True)
  def test_vertex_adc_without_api_key_passes_preflight(self, _mock_adc):
    client = LogJammer(api_key="")
    client.config.api_key = None
    client.validate_preflight(require_genai=True)

  @mock.patch("logjammer.config.resolve_vertex_adc")
  @mock.patch("google.genai.Client")
  def test_get_genai_client_uses_vertex_adc_when_no_api_key(
      self, mock_genai_client, mock_resolve_adc
  ):
    fake_creds = mock.MagicMock()
    mock_resolve_adc.return_value = (fake_creds, "my-gcp-project")
    cfg = LogJammerConfig(api_key="", vertex_location="global")
    cfg.api_key = None

    get_genai_client(cfg)

    mock_genai_client.assert_called_once_with(
        vertexai=True,
        project="my-gcp-project",
        location="global",
        credentials=fake_creds,
    )

  def test_blank_secops_customer_id_fails_preflight(self):
    client = LogJammer(api_key="test_key")

    with self.assertRaises(ValueError) as ctx:
      client.validate_preflight(
          require_genai=True,
          destination="secops://YOUR_SECOPS_CUSTOMER_ID@us",
          project="my-gcp-project",
      )

    self.assertIn("[Pre-flight Validation Failed]", str(ctx.exception))
    self.assertIn("Customer ID", str(ctx.exception))

  @mock.patch.dict(os.environ, {"SECOPS_CUSTOMER_ID": "00000000-1111-2222-3333-444444444444"})
  def test_valid_secops_preflight_passes(self):
    client = LogJammer(api_key="test_key")
    # Should not raise any error
    client.validate_preflight(
        require_genai=True,
        destination="secops://00000000-1111-2222-3333-444444444444@us",
        project="my-gcp-project",
    )


if __name__ == "__main__":
  unittest.main()
