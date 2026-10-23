import pytest

from soclab.security import PathTraversalError, safe_path


@pytest.fixture
def base(tmp_path):
    logs = tmp_path / "logs"
    (logs / "auth").mkdir(parents=True)
    (logs / "auth" / "auth.log").write_text("ok")
    (tmp_path / "secret.txt").write_text("do not read")
    return logs


@pytest.mark.parametrize("name", ["auth/auth.log", "auth/../auth/auth.log", "./auth"])
def test_allows_paths_inside_base(base, name):
    assert safe_path(base, name).is_relative_to(base.resolve())


@pytest.mark.parametrize(
    "attack",
    [
        "../secret.txt",  # classic traversal
        "auth/../../secret.txt",  # traversal hidden after a valid prefix
        "../../../../../etc/passwd",  # deep traversal
        "/etc/passwd",  # absolute path replaces the base
        "..",  # the parent directory itself
    ],
)
def test_blocks_traversal(base, attack):
    with pytest.raises(PathTraversalError):
        safe_path(base, attack)


def test_blocks_null_byte(base):
    with pytest.raises(PathTraversalError):
        safe_path(base, "auth.log\x00.txt")


def test_blocks_symlink_escape(base, tmp_path):
    # A link inside the base that points outside it: the string looks safe, the target is not.
    (base / "innocent.log").symlink_to(tmp_path / "secret.txt")
    with pytest.raises(PathTraversalError):
        safe_path(base, "innocent.log")


def test_sibling_dir_with_shared_prefix_is_blocked(base, tmp_path):
    # Naive string checks (startswith("/x/logs")) wrongly accept "/x/logs-evil".
    (tmp_path / "logs-evil").mkdir()
    with pytest.raises(PathTraversalError):
        safe_path(base, "../logs-evil")
