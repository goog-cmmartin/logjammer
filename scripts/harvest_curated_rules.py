#!/usr/bin/env python3
"""Batch download Google SecOps Curated Detection Rules from Content Hub.

Extracts all curated detection rules with full executable YARA-L 2.0 text,
saves individual .yaral files organized by Category/Ruleset, and builds
a unified fast-lookup catalog index.
"""

import logging
from pathlib import Path
import sys

# Ensure oss_logjammer src is in path
CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from logjammer.config import LogJammerConfig
from logjammer.rules import RuleService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("curated_harvester")


def harvest_curated_rules(
    config: LogJammerConfig,
    output_dir: Path,
    catalog_path: Path,
    page_size: int = 100,
):
  """Harvest curated rules using RuleService."""
  rule_service = RuleService(config)

  def progress(batch, total):
    logger.info(f"Fetched {batch} curated rules (Total so far: {total})...")

  rules = rule_service.sync_curated_rules(
      output_dir=output_dir,
      catalog_path=catalog_path,
      page_size=page_size,
      save_yaral_files=True,
      progress_callback=progress,
  )

  logger.info(
      f"✓ Harvest Complete!\n"
      f"  Total Rules Processed: {len(rules)}\n"
      f"  Catalog saved to: {catalog_path}\n"
      f"  YARA-L tree saved to: {output_dir}"
  )
  return rules


if __name__ == "__main__":
  conf = LogJammerConfig()
  out_dir = Path.home() / ".logjammer" / "rules" / "curated"
  cat_file = Path.home() / ".logjammer" / "rules" / "curated_catalog.json"
  harvest_curated_rules(conf, out_dir, cat_file)
