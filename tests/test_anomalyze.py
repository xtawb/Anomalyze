"""Unit tests for Anomalyze. Run with: pytest"""
import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import Anomalyze as anom  # noqa: E402


def make_args(**overrides):
    defaults = dict(
        url='http://example.com', method='GET', header=None, header_file=None,
        params=None, data=None, proxy=None, proxy_list=None, threads=5,
        timeout=15, delay=0, insecure=False, deep_scan=False, max_depth=2,
        path=None, paths_file=None, default_paths=False, cookie=None,
        content_type=None, user_agent=None, user_agent_file=None,
        patterns_file=None, min_severity='Info', verbose=False, output='json',
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestResponseAnalyzer:
    def setup_method(self):
        self.analyzer = anom.ResponseAnalyzer(anom.SENSITIVE_PATTERNS)

    def test_header_name_alone_does_not_false_positive(self):
        # A "Server" header whose value doesn't contain a sensitive word
        # must not be flagged just because the header *name* matches.
        findings = self.analyzer.analyze_content('', {'Server': 'nginx'})
        assert not any(f['type'] == '🖥️ Server Info' for fs in findings.values() for f in fs)

    def test_header_value_match_is_detected(self):
        findings = self.analyzer.analyze_content('', {'X-Powered-By': 'PHP/8.1'})
        matches = [f for fs in findings.values() for f in fs]
        assert any(f['type'] == '💻 Tech Stack' for f in matches)

    def test_body_credential_detected_as_critical(self):
        findings = self.analyzer.analyze_content('leaked password=hunter2', {})
        assert any(f['type'] == '🔒 Sensitive Credential' for f in findings['Critical'])

    def test_min_severity_filters_low_findings(self):
        analyzer = anom.ResponseAnalyzer(anom.SENSITIVE_PATTERNS, min_severity='Critical')
        findings = analyzer.analyze_content('this server runs php', {})
        assert 'Low' not in findings

    def test_extract_links_same_domain_absolute(self):
        html = '<a href="https://example.com/admin">Admin</a>'
        links = self.analyzer.extract_links(html, 'https://example.com')
        assert '/admin' in links

    def test_extract_links_excludes_external_domain(self):
        html = '<a href="https://evil.com/phish">x</a>'
        links = self.analyzer.extract_links(html, 'https://example.com')
        assert links == set()

    def test_extract_links_excludes_mailto_and_protocol_relative(self):
        html = '<a href="mailto:a@b.com">m</a><a href="//cdn.example.com/x.js">c</a>'
        links = self.analyzer.extract_links(html, 'https://example.com')
        assert links == set()

    def test_extract_links_relative_path(self):
        html = '<a href="/dashboard">Dash</a>'
        links = self.analyzer.extract_links(html, 'https://example.com')
        assert '/dashboard' in links

    def test_extract_links_from_json(self):
        text = '{"next": "/api/next"}'
        links = self.analyzer.extract_links(text, 'https://example.com')
        assert '/api/next' in links


class TestAnomalyzeHelpers:
    def test_normalize_base_url_adds_scheme(self):
        assert anom.Anomalyze.normalize_base_url('example.com') == 'http://example.com'

    def test_normalize_base_url_keeps_https(self):
        assert anom.Anomalyze.normalize_base_url('https://example.com/') == 'https://example.com'

    def test_parse_headers(self):
        parsed = anom.Anomalyze.parse_headers(['Authorization: Bearer xyz', 'X-Test:1'])
        assert parsed == {'Authorization': 'Bearer xyz', 'X-Test': '1'}

    def test_parse_params(self):
        parsed = anom.Anomalyze.parse_params(['id=1', 'name=test'])
        assert parsed == [('id', '1'), ('name', 'test')]

    def test_load_paths_defaults_when_nothing_specified(self):
        instance = anom.Anomalyze(make_args())
        assert ('/admin', 0) in instance.paths

    def test_load_paths_dedupes_and_preserves_order(self):
        instance = anom.Anomalyze(make_args(path=['/a', '/a', '/b']))
        assert instance.paths == [('/a', 0), ('/b', 0)]

    def test_threads_floor_is_one(self):
        instance = anom.Anomalyze(make_args(path=['/a'], threads=0))
        assert instance.threads == 1


class TestArgParsing:
    def test_positive_int_rejects_zero(self):
        import pytest
        with pytest.raises(argparse.ArgumentTypeError):
            anom.positive_int('0')

    def test_delay_ms_plain_integer(self):
        assert anom.delay_ms('250') == 250

    def test_delay_ms_random_expression(self):
        value = anom.delay_ms('random(100-200)')
        assert 100 <= value <= 200
