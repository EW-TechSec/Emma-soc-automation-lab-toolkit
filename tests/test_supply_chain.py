"""Supply chain guard for an accepted dependency vulnerability (ADR 0006).

diskcache (pulled in by pySigma) has PYSEC-2026-2447: pickle deserialisation of its cache
directory, no fixed version. pySigma only uses it in sigma.data.mitre_attack and
sigma.data.mitre_d3fend. The risk is accepted because none of our code paths load them.
This test keeps that true: if a change makes the vulnerable code reachable, it fails.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

WORKLOAD = """
import sys, tempfile
from soclab.simulate import generate, write_dataset
from soclab.ingest import load_log
from soclab.detections import DetectionEngine
from soclab.detections.incidents import build_incidents
from soclab.detections.evaluation import run_suite
from soclab.kql import convert_rules

d = tempfile.mkdtemp()
write_dataset(generate(), d)
events = load_log(d, "auth.log", "linux_auth", 2026).events
events += load_log(d, "ufw.log", "ufw", 2026).events
build_incidents(DetectionEngine.from_path("rules").run(events))
run_suite([0])
convert_rules("rules")
print(",".join(sorted(m for m in sys.modules if m == "diskcache" or m.startswith("sigma.data"))))
"""


def test_vulnerable_diskcache_code_is_not_reachable():
    # A fresh interpreter: modules imported by other tests cannot hide or fake the result.
    result = subprocess.run(  # noqa: S603  fixed command, no user input
        [sys.executable, "-c", WORKLOAD], cwd=ROOT, capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "", f"vulnerable modules loaded: {result.stdout.strip()}"
