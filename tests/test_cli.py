from pathlib import Path

import pytest

from gfw.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_help_exits_zero():
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0


def test_offline_egress_blocks_beijing_oss(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GFW_AUDIT", str(tmp_path / "audit.jsonl"))
    code = main(["egress", "probe.oss-cn-beijing.aliyuncs.com", "--offline"])
    assert code == 3
    assert "hard_deny:aliyuncs.com" in capsys.readouterr().out


def test_offline_egress_reviews_an_unknown_name(tmp_path, monkeypatch):
    monkeypatch.setenv("GFW_AUDIT", str(tmp_path / "audit.jsonl"))
    assert main(["egress", "example.com", "--offline"]) == 2


def test_scan_of_this_repo_is_clean():
    assert main(["scan", str(ROOT)]) == 0
