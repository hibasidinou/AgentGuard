from getpass import GetPassWarning
from backend.security.auth import bootstrap
from backend.security.auth.users import UserStore


def test_bootstrap_prompt_then_no_changes(tmp_path, monkeypatch, capsys):
    path = tmp_path / "bootstrap.db"
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(path))
    alice = "test-only-alice-passphrase"
    bob = "test-only-bob-passphrase"
    answers = iter([alice, alice, bob, bob])
    monkeypatch.setattr(bootstrap, "getpass", lambda _: next(answers))
    assert bootstrap.main() == 0
    assert bootstrap.main() == 0  # must not call getpass again
    out = capsys.readouterr()
    assert "already initialized" in out.out
    assert alice not in out.out + out.err and bob not in out.out + out.err
    assert UserStore(path).authenticate("alice", alice).role == "intern"


def test_mismatch_no_accounts_created(tmp_path, monkeypatch, capsys):
    path = tmp_path / "bootstrap.db"
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(path))
    answers = iter(["test-only-alice-passphrase", "different-test-passphrase"])
    monkeypatch.setattr(bootstrap, "getpass", lambda _: next(answers))
    assert bootstrap.main() == 1
    assert UserStore(path).missing_demo_users() == ("alice", "bob")
    assert "mismatch" in capsys.readouterr().err


def test_unmasked_terminal_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "bootstrap.db"
    monkeypatch.setenv("AGENTGUARD_DB_PATH", str(path))
    def unavailable(_):
        raise GetPassWarning("unavailable")
    monkeypatch.setattr(bootstrap, "getpass", unavailable)
    assert bootstrap.main() == 1
    assert UserStore(path).missing_demo_users() == ("alice", "bob")
