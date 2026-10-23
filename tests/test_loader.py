import pytest

from soclab.ingest import load_log
from soclab.security import PathTraversalError

LINE = "Oct 20 09:14:03 web01 sshd[1]: Failed password for root from 203.0.113.66 port 1 ssh2\n"


def test_load_log_reads_inside_base(tmp_path):
    (tmp_path / "auth.log").write_text(LINE * 3)
    assert len(load_log(tmp_path, "auth.log", "linux_auth", 2026).events) == 3


def test_load_log_refuses_traversal(tmp_path):
    base = tmp_path / "logs"
    base.mkdir()
    (tmp_path / "secret.log").write_text(LINE)
    with pytest.raises(PathTraversalError):
        load_log(base, "../secret.log", "linux_auth")


def test_binary_junk_does_not_stop_ingestion(tmp_path):
    (tmp_path / "auth.log").write_bytes(LINE.encode() + b"\xff\xfe\x00garbage\n" + LINE.encode())
    r = load_log(tmp_path, "auth.log", "linux_auth", 2026)
    assert len(r.events) == 2
    assert r.malformed == 1
