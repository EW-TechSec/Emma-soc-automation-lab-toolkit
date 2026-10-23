"""Read log files safely and turn them into Events."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from soclab.ingest.parsers import PARSERS
from soclab.schema import Event
from soclab.security import safe_path

MAX_ERROR_SAMPLES = 20


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    ignored: int = 0  # valid lines that carry nothing we use yet
    malformed: int = 0  # lines we could not parse at all
    error_samples: list[tuple[int, str]] = field(default_factory=list)  # (line no, reason)


def parse_lines(lines: Iterable[str], source: str, year: int | None = None) -> ParseResult:
    """Parse lines for a known source. A bad line is counted, never fatal."""
    if source not in PARSERS:
        raise ValueError(f"Unknown log source {source!r}. Known: {sorted(PARSERS)}")
    parser = PARSERS[source]
    year = year or datetime.now(UTC).year
    result = ParseResult()

    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        try:
            event = parser(line, year)
        except ValueError as exc:
            result.malformed += 1
            if len(result.error_samples) < MAX_ERROR_SAMPLES:
                result.error_samples.append((lineno, str(exc)))
            continue
        if event is None:
            result.ignored += 1
        else:
            result.events.append(event)
    return result


def load_log(base_dir: str | Path, name: str, source: str, year: int | None = None) -> ParseResult:
    """Load `name` from inside `base_dir`. Paths escaping base_dir are refused."""
    path = safe_path(base_dir, name)
    # errors="replace": binary junk or bad encoding in a log must not stop ingestion.
    with path.open(encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh, source, year)
