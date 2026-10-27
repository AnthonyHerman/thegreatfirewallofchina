from pathlib import Path

from gfw.scan import scan_text, scan_tree

ROOT = Path(__file__).resolve().parents[1]


def test_scanner_flags_a_planted_key(tmp_path):
    planted = "ak_" + ("a" * 20)
    (tmp_path / "leak.txt").write_text(f"token {planted}\n", encoding="utf-8")
    findings = scan_tree(tmp_path)
    assert len(findings) == 1
    assert findings[0]["path"] == "leak.txt"
    assert planted not in findings[0]["match"]
    assert scan_text(planted)


def test_repo_tree_has_no_secret_shaped_strings():
    assert scan_tree(ROOT) == []
