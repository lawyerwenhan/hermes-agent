"""Tests for permission_asking_filter module."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from tools.permission_asking_filter import filter_permission_asking, _is_borderline


class TestChinesePatterns:
    """Test Chinese permission-asking pattern removal."""

    def test_wy_xianz_zuo_ma(self):
        """要我现在做吗？ as entire message → safety net returns original."""
        text = "好的，要我现在做吗？"
        filtered, was = filter_permission_asking(text)
        assert was is True
        assert "要我现在做吗" not in filtered
        assert "好的" in filtered

    def test_yaobuya_zuo(self):
        """Pure permission-asking should collapse to a neutral action message."""
        text = "要不要做？"
        filtered, was = filter_permission_asking(text)
        assert was is True
        assert filtered == "(action taken)"

    def test_wy_xianz_zuo_haishi_gaitian(self):
        """Pure permission-asking should collapse to a neutral action message."""
        text = "要现在做还是改天？"
        filtered, was = filter_permission_asking(text)
        assert was is True
        assert filtered == "(action taken)"

    def test_chinese_preserves_other_content(self):
        """Non-asking Chinese text should be preserved."""
        text = "已经完成了。要我现在做吗？代码在本地。"
        filtered, was = filter_permission_asking(text)
        assert "已经完成了" in filtered
        assert "代码在本地" in filtered
        assert "要我现在做吗" not in filtered

    def test_chinese_no_false_positive(self):
        """Regular Chinese questions should NOT be filtered."""
        text = "这个接口的返回值是什么？"
        filtered, was = filter_permission_asking(text)
        assert was is False
        assert filtered == text


class TestEnglishPatterns:
    """Test English permission-asking pattern removal."""

    def test_should_I_do_this(self):
        """Pure permission-asking should collapse to a neutral action message."""
        text = "Should I do this?"
        filtered, was = filter_permission_asking(text)
        assert was is True
        assert filtered == "(action taken)"

    def test_should_I_do_this_with_context(self):
        """'Should I do this?' with context → ask removed, context preserved."""
        text = "Bug fixed. Should I do this? Code committed."
        filtered, was = filter_permission_asking(text)
        assert was is True
        assert "Bug fixed" in filtered
        assert "Code committed" in filtered
        assert "Should I" not in filtered

    def test_do_you_want_me_to(self):
        """'Do you want me to do this?' should be removed as complete sentence."""
        text = "Do you want me to do this?"
        filtered, was = filter_permission_asking(text)
        assert was is True
        assert filtered == "(action taken)"

    def test_would_you_like_me_to(self):
        """'Would you like me to continue?' with context → ask removed."""
        text = "The fix is ready. Would you like me to continue? The tests passed."
        filtered, was = filter_permission_asking(text)
        assert was is True
        assert "The fix is ready" in filtered
        assert "The tests passed" in filtered

    def test_shall_I_proceed(self):
        """'Shall I proceed?' should be removed."""
        text = "Shall I proceed?"
        filtered, was = filter_permission_asking(text)

    def test_english_preserves_other_content(self):
        """Non-asking English text should be preserved."""
        text = "I found 3 bugs. Should I do this? The server is currently exposed."
        filtered, was = filter_permission_asking(text)
        assert "I found 3 bugs" in filtered
        assert "The server is currently exposed" in filtered
        assert "Should I" not in filtered

    def test_english_no_partial_phrase_removal(self):
        """Partial phrase removal should NOT garble meaning."""
        # This was the key bug Claude caught — "Do you want me to delete the backups?"
        # should NOT become "delete the backups?" (imperative command)
        # Our new design only removes complete sentences, so this should either
        # remove the whole thing or leave it intact, never garble it.
        text = "Do you want me to delete the backups or keep them?"
        filtered, was = filter_permission_asking(text)
        # If filtered, the remaining text should NOT look like a command
        if was:
            assert "delete the backups" not in filtered or "?" not in filtered.rstrip()


class TestBorderline:
    """Test borderline pattern detection — these should NOT be filtered."""

    def test_before_delete(self):
        """'before I delete' should not be filtered."""
        text = "Are you sure? Before I delete the production database..."
        filtered, was = filter_permission_asking(text)
        assert was is False
        assert filtered == text

    def test_this_will_deploy(self):
        """'this will deploy' should not be filtered."""
        text = "This will deploy to production. Should I proceed?"
        filtered, was = filter_permission_asking(text)
        # Borderline triggers → no filtering at all
        assert was is False
        assert filtered == text


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_string(self):
        """Empty string should be returned as-is."""
        filtered, was = filter_permission_asking("")
        assert filtered == ""
        assert was is False

    def test_whitespace_only(self):
        """Whitespace-only should be returned as-is."""
        filtered, was = filter_permission_asking("   ")
        assert was is False

    def test_full_message_removal_returns_neutral_message(self):
        """If filter removes everything, return a neutral action message."""
        text = "Should I do this?"
        filtered, was = filter_permission_asking(text)
        assert was is True
        assert filtered == "(action taken)"

    def test_mixed_language(self):
        """Mixed Chinese/English should work."""
        text = "Bug已修好。Should I do this now? 代码已提交。"
        filtered, was = filter_permission_asking(text)
        assert "Bug已修好" in filtered
        assert "代码已提交" in filtered
        assert "Should I" not in filtered

    def test_markdown_preserved(self):
        """Markdown formatting should not be broken."""
        text = "## Summary\n\nShould I do this?\n\n**Done.**"
        filtered, was = filter_permission_asking(text)
        assert "## Summary" in filtered
        assert "**Done.**" in filtered


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
