import re
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from scripts.ugrep_harvest import sanitise_path_for_filename


def test_sanitise_replaces_separators():
    path = Path("/var/www/html/index.php")
    result = sanitise_path_for_filename(path)
    assert "var" in result and "www" in result and "html" in result
    assert "__" in result
    assert "/" not in result and "\\" not in result


def test_sanitise_handles_root_path():
    assert sanitise_path_for_filename(Path("/")) == "root"


def test_sanitise_long_path_appends_hash():
    long_components = ["segment" + str(i) for i in range(60)]
    long_path = Path("/") / "/".join(long_components)
    result = sanitise_path_for_filename(long_path)
    assert len(result) <= 202
    # the tail should include a digest marker when truncated
    if len("__".join(long_components)) > 200:
        assert re.search(r"[0-9a-f]{40}$", result)
