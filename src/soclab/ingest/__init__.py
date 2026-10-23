"""Log ingestion: raw log lines in, normalized Events out."""

from soclab.ingest.loader import ParseResult, load_log, parse_lines
from soclab.ingest.parsers import PARSERS

__all__ = ["PARSERS", "ParseResult", "load_log", "parse_lines"]
