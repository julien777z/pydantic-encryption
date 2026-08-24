import pytest

from pydantic_encryption.normalization import normalize_value


class TestStripWhitespace:
    def test_strips_leading_trailing(self):
        assert normalize_value("  hello  ", {"strip_whitespace": True}) == "hello"

    def test_collapses_internal_whitespace(self):
        assert normalize_value("hello   world", {"strip_whitespace": True}) == "hello world"

    def test_strips_and_collapses(self):
        assert normalize_value("  hello   world  ", {"strip_whitespace": True}) == "hello world"

    def test_tabs_and_newlines(self):
        assert normalize_value("\thello\n\tworld\n", {"strip_whitespace": True}) == "hello world"

    def test_noop_when_disabled(self):
        assert normalize_value("  hello   world  ", {}) == "  hello   world  "


class TestStripNonCharacters:
    def test_removes_digits_and_symbols(self):
        assert normalize_value("hello123world!", {"strip_non_characters": True}) == "helloworld"

    def test_keeps_only_letters(self):
        assert normalize_value("12 (34) 56-78", {"strip_non_characters": True}) == ""

    def test_preserves_mixed_case(self):
        assert normalize_value("Hello World 123", {"strip_non_characters": True}) == "HelloWorld"


class TestStripNonDigits:
    def test_removes_non_digits(self):
        assert normalize_value("a1 (b2) c3-d4", {"strip_non_digits": True}) == "1234"

    def test_keeps_only_digits(self):
        assert normalize_value("abc123def456", {"strip_non_digits": True}) == "123456"

    def test_empty_when_no_digits(self):
        assert normalize_value("hello world", {"strip_non_digits": True}) == ""


class TestStripTrailingPunctuation:
    """Test stripping trailing periods and commas from whitespace-separated tokens."""

    def test_removes_trailing_period(self):
        """Test that a period ending the last token is removed."""

        assert normalize_value("first second.", {"strip_trailing_punctuation": True}) == "first second"

    def test_removes_trailing_comma(self):
        """Test that a comma ending an interior token is removed."""

        assert normalize_value("first, second", {"strip_trailing_punctuation": True}) == "first second"

    def test_removes_a_trailing_run(self):
        """Test that a whole run of trailing punctuation is removed at once."""

        assert normalize_value("first.., second.,", {"strip_trailing_punctuation": True}) == "first second"

    def test_drops_punctuation_only_tokens(self):
        """Test that a token left empty vanishes together with its leading separator."""

        assert normalize_value("first , second", {"strip_trailing_punctuation": True}) == "first second"

    def test_drops_a_leading_punctuation_token(self):
        """Test that punctuation-only tokens at the start vanish with their separators."""

        assert normalize_value(", . first", {"strip_trailing_punctuation": True}) == "first"

    def test_keeps_interior_punctuation(self):
        """Test that punctuation inside a token is untouched."""

        assert normalize_value("a.b. c", {"strip_trailing_punctuation": True}) == "a.b c"

    def test_whitespace_is_preserved(self):
        """Test that whitespace is left alone unless strip_whitespace is also set."""

        assert normalize_value("  a.   b. ", {"strip_trailing_punctuation": True}) == "  a   b "

    def test_empty_string_stays_empty(self):
        """Test that an empty input passes through unchanged."""

        assert normalize_value("", {"strip_trailing_punctuation": True}) == ""

    def test_noop_when_disabled(self):
        """Test that the flag left unset changes nothing."""

        assert normalize_value("first second.", {}) == "first second."


class TestNormalizeToLowercase:
    def test_lowercases(self):
        assert normalize_value("AbC-123", {"normalize_to_lowercase": True}) == "abc-123"

    def test_already_lowercase(self):
        assert normalize_value("hello", {"normalize_to_lowercase": True}) == "hello"


class TestNormalizeToUppercase:
    def test_uppercases(self):
        assert normalize_value("AbC-123", {"normalize_to_uppercase": True}) == "ABC-123"


class TestCombined:
    def test_whitespace_then_lowercase(self):
        assert (
            normalize_value("  Hello  World  ", {"strip_whitespace": True, "normalize_to_lowercase": True})
            == "hello world"
        )

    def test_strip_non_digits_then_no_case_effect(self):
        result = normalize_value(
            "Label: a1-b2-c3", {"strip_non_digits": True, "normalize_to_lowercase": True}
        )
        assert result == "123"

    def test_strip_non_characters_then_trailing_punctuation(self):
        """Test that stripping non-characters first leaves trailing punctuation nothing to do."""

        combined = normalize_value(
            "first, second.",
            {"strip_non_characters": True, "strip_trailing_punctuation": True},
        )

        assert combined == normalize_value("first, second.", {"strip_non_characters": True})

    def test_all_strip_options(self):
        result = normalize_value(
            "  Hello 123 World!  ",
            {"strip_whitespace": True, "strip_non_characters": True},
        )
        assert result == "HelloWorld"


class TestConflictingOptions:
    def test_strip_non_characters_and_strip_non_digits_raises(self):
        with pytest.raises(ValueError, match="strip_non_characters and strip_non_digits cannot both be True"):
            normalize_value("test", {"strip_non_characters": True, "strip_non_digits": True})

    def test_normalize_to_lowercase_and_normalize_to_uppercase_raises(self):
        with pytest.raises(
            ValueError, match="normalize_to_lowercase and normalize_to_uppercase cannot both be True"
        ):
            normalize_value("test", {"normalize_to_lowercase": True, "normalize_to_uppercase": True})
