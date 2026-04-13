"""Tests for git commit detection in the audit guard."""

from tools.audit_guard import _is_git_commit_command, _test_git_commit_detection, is_git_commit


class TestGitCommitDetection:
    def test_self_check_cases(self):
        _test_git_commit_detection()

    def test_detects_plain_git_commit(self):
        assert _is_git_commit_command('git commit -m "message"') is True
        assert is_git_commit('git commit -m "message"') is True

    def test_detects_git_c_flag_before_commit(self):
        assert _is_git_commit_command("git -c core.editor=true commit") is True

    def test_detects_git_no_pager_before_commit(self):
        assert _is_git_commit_command("git --no-pager commit -m x") is True

    def test_detects_git_dir_before_commit(self):
        assert _is_git_commit_command("git --git-dir=/foo commit") is True

    def test_detects_env_wrapped_git_commit(self):
        assert _is_git_commit_command("env VAR=1 git --no-pager commit -m x") is True

    def test_rejects_echo_false_positive(self):
        assert _is_git_commit_command("echo git commit") is False

    def test_rejects_python_string_false_positive(self):
        assert _is_git_commit_command('python -c "print(\\"git commit\\")"') is False

    def test_rejects_other_git_subcommands(self):
        assert _is_git_commit_command("git log --oneline") is False
        assert _is_git_commit_command("git status") is False
        assert _is_git_commit_command("git show HEAD") is False
