"""Sigma-based detection: base rules, correlations, alerts."""

from soclab.detections.engine import DetectionEngine
from soclab.detections.matcher import RuleMatcher, UnsupportedRuleError
from soclab.detections.models import Alert

__all__ = ["Alert", "DetectionEngine", "RuleMatcher", "UnsupportedRuleError"]
