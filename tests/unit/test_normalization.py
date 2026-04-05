from pydantic_encryption.normalization import strip_value


class TestStripWhitespace:
    def test_strips_leading_trailing(self):
        assert strip_value("  hello  ", strip_whitespace=True) == "hello"

    def test_collapses_internal_whitespace(self):
        assert strip_value("hello   world", strip_whitespace=True) == "hello world"

    def test_strips_and_collapses(self):
        assert strip_value("  hello   world  ", strip_whitespace=True) == "hello world"

    def test_tabs_and_newlines(self):
        assert strip_value("\thello\n\tworld\n", strip_whitespace=True) == "hello world"

    def test_noop_when_disabled(self):
        assert strip_value("  hello   world  ") == "  hello   world  "


class TestStripNonCharacters:
    def test_removes_digits_and_symbols(self):
        assert strip_value("hello123world!", strip_non_characters=True) == "helloworld"

    def test_keeps_only_letters(self):
        assert strip_value("+1 (555) 123-4567", strip_non_characters=True) == ""

    def test_preserves_mixed_case(self):
        assert strip_value("Hello World 123", strip_non_characters=True) == "HelloWorld"


class TestStripNonDigits:
    def test_removes_non_digits(self):
        assert strip_value("+1 (555) 123-4567", strip_non_digits=True) == "15551234567"

    def test_keeps_only_digits(self):
        assert strip_value("abc123def456", strip_non_digits=True) == "123456"

    def test_empty_when_no_digits(self):
        assert strip_value("hello world", strip_non_digits=True) == ""


class TestNormalizeToLowercase:
    def test_lowercases(self):
        assert strip_value("Hello@Example.COM", normalize_to_lowercase=True) == "hello@example.com"

    def test_already_lowercase(self):
        assert strip_value("hello", normalize_to_lowercase=True) == "hello"


class TestNormalizeToUppercase:
    def test_uppercases(self):
        assert strip_value("Hello@Example.com", normalize_to_uppercase=True) == "HELLO@EXAMPLE.COM"


class TestCombined:
    def test_whitespace_then_lowercase(self):
        assert strip_value("  Hello  World  ", strip_whitespace=True, normalize_to_lowercase=True) == "hello world"

    def test_strip_non_digits_then_no_case_effect(self):
        result = strip_value("Phone: +1-555-0100", strip_non_digits=True, normalize_to_lowercase=True)
        assert result == "15550100"

    def test_all_strip_options(self):
        result = strip_value(
            "  Hello 123 World!  ",
            strip_whitespace=True,
            strip_non_characters=True,
        )
        assert result == "HelloWorld"
