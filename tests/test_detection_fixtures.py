"""Detection-as-code: every alerting rule ships with a true positive and a true negative log.

tests/fixtures/detections/<rule_name>/true_positive.<log_source>.log  -> the rule MUST fire
tests/fixtures/detections/<rule_name>/true_negative.<log_source>.log  -> the rule must NOT fire
Lines starting with # describe the case and are skipped.
"""

from pathlib import Path

import pytest

from soclab.detections import DetectionEngine
from soclab.ingest import parse_lines

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "detections"
ENGINE = DetectionEngine.from_path(ROOT / "rules")


def _fixtures(kind: str) -> list[Path]:
    return sorted(FIXTURES.glob(f"*/{kind}.*.log"))


def _alerts_for(path: Path) -> list[str]:
    source = path.name.split(".")[1]  # true_positive.<source>.log
    lines = [x for x in path.read_text().splitlines() if not x.startswith("#")]
    result = parse_lines(lines, source, year=2026)
    assert result.malformed == 0, f"{path}: fixture has malformed lines {result.error_samples}"
    return [a.rule_name for a in ENGINE.run(result.events)]


@pytest.mark.parametrize("rule", ENGINE.alerting_rules)
def test_every_alerting_rule_has_both_fixtures(rule):
    for kind in ("true_positive", "true_negative"):
        assert list((FIXTURES / rule).glob(f"{kind}.*.log")), f"{rule} has no {kind} fixture"


@pytest.mark.parametrize("path", _fixtures("true_positive"), ids=lambda p: p.parent.name)
def test_true_positive_fires(path):
    assert path.parent.name in _alerts_for(path)


@pytest.mark.parametrize("path", _fixtures("true_negative"), ids=lambda p: p.parent.name)
def test_true_negative_stays_quiet(path):
    assert path.parent.name not in _alerts_for(path)
