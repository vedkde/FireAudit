from fireaudit.parsers.csv_parser import CsvParser

SAMPLE = "sample_configs/generic_sample.csv"


def test_parses_all_rules():
    ruleset = CsvParser().parse(SAMPLE)
    assert len(ruleset.rules) == 8


def test_boolean_logging_parsed():
    ruleset = CsvParser().parse(SAMPLE)
    logged = next(r for r in ruleset.rules if r.name == "Allow-Internal-DNS")
    not_logged = next(r for r in ruleset.rules if r.name == "Allow-Any-Any-Temp")
    assert logged.logging is True
    assert not_logged.logging is False


def test_hit_count_parsed_as_int():
    ruleset = CsvParser().parse(SAMPLE)
    rule = ruleset.rules[0]
    assert isinstance(rule.hit_count, int)
    assert rule.hit_count == 84210
