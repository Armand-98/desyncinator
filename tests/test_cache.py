"""Cache analysis tests, from messages assembled by hand against RFC 9111.

Two properties are load-bearing. A finding must describe a response a shared
cache would really store and really serve to somebody else, and the shapes that
only look like that (a real static asset, a header that is present but never
reflected, a response nothing will store) must produce nothing at all. Half of
these tests exist to say no.
"""

import pytest

from desyncinator.cache import (KIND_DECEPTION, KIND_POISONING, SEVERITY_HIGH,
                                SEVERITY_MEDIUM, cache_key, deception_finding,
                                is_cacheable, poisoning_findings)
from desyncinator.http.message import parse
from desyncinator.http.profiles import STRICT


def response(*headers, status=b"HTTP/1.1 200 OK", body=b""):
    data = b"\r\n".join((status,) + headers) + b"\r\n\r\n" + body
    return parse(data, STRICT, is_request=False)


def request(*headers, target=b"/", method=b"GET"):
    line = method + b" " + target + b" HTTP/1.1"
    return parse(b"\r\n".join((line, b"Host: example.com") + headers)
                 + b"\r\n\r\n", STRICT)


# --- is_cacheable ----------------------------------------------------------

def test_a_plain_200_is_cached_heuristically():
    ok, why = is_cacheable(response(b"Content-Type: text/html"))
    assert ok and "heuristically" in why


def test_no_store_stops_everything():
    ok, why = is_cacheable(response(b"Cache-Control: public, max-age=600, no-store"))
    assert not ok and "no-store" in why


def test_private_is_not_stored_by_a_shared_cache():
    ok, why = is_cacheable(response(b"Cache-Control: private, s-maxage=600"))
    assert not ok and "private" in why


def test_no_cache_is_revalidated_so_it_is_not_served_alone():
    ok, why = is_cacheable(response(b"Cache-Control: no-cache"))
    assert not ok and "no-cache" in why


def test_a_qualified_no_cache_restricts_one_field_only():
    ok, _ = is_cacheable(response(b'Cache-Control: no-cache="Set-Cookie", max-age=60'))
    assert ok


def test_max_age_zero_is_stale_on_arrival():
    assert is_cacheable(response(b"Cache-Control: max-age=0"))[0] is False


def test_max_age_positive_is_cacheable():
    ok, why = is_cacheable(response(b"Cache-Control: max-age=60"))
    assert ok and "max-age=60" in why


def test_s_maxage_beats_max_age_for_a_shared_cache():
    assert is_cacheable(response(b"Cache-Control: max-age=600, s-maxage=0"))[0] is False
    assert is_cacheable(response(b"Cache-Control: max-age=0, s-maxage=600"))[0] is True


def test_public_alone_is_enough():
    ok, why = is_cacheable(response(b"Cache-Control: public"))
    assert ok and "public" in why


def test_expires_in_the_future_against_the_response_date():
    ok, _ = is_cacheable(response(b"Date: Sun, 01 Jan 2023 00:00:00 GMT",
                                  b"Expires: Mon, 02 Jan 2023 00:00:00 GMT",
                                  status=b"HTTP/1.1 302 Found"))
    assert ok


def test_expires_before_the_response_date_is_already_past():
    ok, why = is_cacheable(response(b"Date: Sun, 01 Jan 2023 00:00:00 GMT",
                                    b"Expires: Sat, 31 Dec 2022 00:00:00 GMT"))
    assert not ok and "past" in why


def test_an_unparseable_expires_counts_as_past():
    assert is_cacheable(response(b"Expires: 0"))[0] is False


def test_a_post_response_is_not_stored_without_explicit_freshness():
    assert is_cacheable(response(), method="POST")[0] is False
    assert is_cacheable(response(b"Cache-Control: s-maxage=60"), method="POST")[0]


def test_statuses_outside_the_heuristic_set_need_directives():
    assert is_cacheable(response(status=b"HTTP/1.1 500 Error"))[0] is False
    assert is_cacheable(response(status=b"HTTP/1.1 404 Gone"))[0] is True


def test_repeated_cache_control_headers_combine():
    ok, _ = is_cacheable(response(b"Cache-Control: public", b"Cache-Control: no-store"))
    assert not ok


# --- web cache deception ---------------------------------------------------

def dynamic(*extra):
    return response(b"Content-Type: text/html; charset=utf-8",
                    b"Set-Cookie: session=abc",
                    *extra,
                    body=b"<p>hello armand</p>")


def test_a_dynamic_page_under_a_css_suffix_is_deception():
    finding = deception_finding("/account/profile.css", dynamic())
    assert finding is not None
    assert finding.kind == KIND_DECEPTION
    assert finding.severity == SEVERITY_HIGH
    assert "Set-Cookie" in finding.evidence
    assert "text/css" in finding.evidence


def test_a_genuinely_static_asset_is_not_deception():
    static = response(b"Content-Type: text/css", b"Cache-Control: public, max-age=600",
                      body=b"body{}")
    assert deception_finding("/assets/site.css", static) is None


def test_a_dynamic_page_with_no_static_suffix_is_not_deception():
    assert deception_finding("/account/profile", dynamic()) is None


def test_a_path_parameter_hiding_the_suffix():
    finding = deception_finding("/account/profile;.css", dynamic())
    assert finding is not None
    assert "path parameter" in finding.evidence


@pytest.mark.parametrize("target", ["/account/profile%2F..%2f",
                                    "/account/profile/..%2f",
                                    "/account/profile%3f"])
def test_an_encoded_delimiter_tail_is_deception(target):
    finding = deception_finding(target, dynamic())
    assert finding is not None
    assert "encoded delimiter" in finding.evidence


def test_a_private_response_is_still_deception_under_a_suffix_rule():
    """The suffix rule runs before the directives are read, which is the bug."""
    finding = deception_finding("/account/profile.css",
                                dynamic(b"Cache-Control: private"))
    assert finding is not None
    assert "regardless" in finding.reason


def test_no_store_clears_the_deception_finding():
    assert deception_finding("/account/profile.css",
                             dynamic(b"Cache-Control: no-store")) is None


def test_an_encoded_delimiter_needs_a_cache_that_would_store_it():
    """With no suffix to key on there is no rule overriding the directives."""
    assert deception_finding("/account/profile/..%2f",
                             dynamic(b"Cache-Control: private")) is None


def test_a_content_type_contradicting_the_suffix_is_enough_alone():
    page = response(b"Content-Type: text/html", body=b"<p>balance: 42</p>")
    finding = deception_finding("/account/statement.jpg", page)
    assert finding is not None
    assert finding.severity == SEVERITY_MEDIUM


def test_a_redirect_is_not_a_sensitive_body():
    moved = response(b"Location: /login", b"Set-Cookie: x=1",
                     status=b"HTTP/1.1 302 Found")
    assert deception_finding("/account/profile.css", moved) is None


def test_the_suffix_must_be_in_the_path_not_the_query():
    assert deception_finding("/account/profile.css?v=1", dynamic()) is not None
    assert deception_finding("/account/profile?v=.css", dynamic()) is None


def test_an_absolute_form_target_is_split_before_the_suffix_check():
    finding = deception_finding("http://example.com/account/profile.css", dynamic())
    assert finding is not None
    assert "/account/profile.css" in finding.reason


# --- cache poisoning -------------------------------------------------------

def test_the_cache_key_leaves_the_unkeyed_header_out():
    assert cache_key(request(b"X-Forwarded-Host: evil.test"), "/p?a=1") == (
        "GET", "example.com", "/p", "a=1")


def test_an_unkeyed_host_reflected_in_the_body_is_poisoning():
    reflected = response(b"Cache-Control: public, max-age=60",
                         body=b'<script src="//evil.test/x.js">')
    findings = poisoning_findings("/", request(b"X-Forwarded-Host: evil.test"),
                                  reflected)
    assert len(findings) == 1
    assert findings[0].kind == KIND_POISONING
    assert findings[0].severity == SEVERITY_HIGH
    assert "X-Forwarded-Host: evil.test" in findings[0].evidence
    assert "GET example.com/" in findings[0].reason


def test_a_header_that_is_present_but_never_reflected_is_not_poisoning():
    plain = response(b"Cache-Control: public, max-age=60", body=b"<p>hello</p>")
    assert poisoning_findings("/", request(b"X-Forwarded-Host: evil.test"), plain) == []


@pytest.mark.parametrize("directive", [b"no-store", b"private"])
def test_nothing_is_poisoned_when_nothing_is_stored(directive):
    reflected = response(b"Cache-Control: " + directive, body=b"evil.test")
    assert poisoning_findings("/", request(b"X-Forwarded-Host: evil.test"),
                              reflected) == []


def test_vary_on_the_header_puts_it_back_in_the_key():
    reflected = response(b"Cache-Control: public, max-age=60",
                         b"Vary: Accept-Encoding, X-Forwarded-Host",
                         body=b"evil.test")
    assert poisoning_findings("/", request(b"X-Forwarded-Host: evil.test"),
                              reflected) == []


def test_vary_star_means_no_stored_response_is_reused():
    reflected = response(b"Cache-Control: public, max-age=60", b"Vary: *",
                         body=b"evil.test")
    assert poisoning_findings("/", request(b"X-Forwarded-Host: evil.test"),
                              reflected) == []


def test_a_reflection_in_a_response_header():
    redirect = response(b"Cache-Control: public, max-age=60",
                        b"Location: http://evil.test/login",
                        status=b"HTTP/1.1 301 Moved")
    findings = poisoning_findings("/", request(b"X-Forwarded-Host: evil.test"),
                                  redirect)
    assert findings[0].evidence.endswith("the Location response header")
    assert findings[0].severity == SEVERITY_HIGH


def test_findings_come_back_worst_first():
    reflected = response(b"Cache-Control: public, max-age=60",
                         body=b"host=evil.test client=203.0.113.9")
    findings = poisoning_findings(
        "/", request(b"X-Forwarded-For: 203.0.113.9",
                     b"X-Forwarded-Host: evil.test"), reflected)
    assert [f.severity for f in findings] == [SEVERITY_HIGH, SEVERITY_MEDIUM]
    assert findings[0].evidence.startswith("X-Forwarded-Host")


def test_a_forwarded_header_is_unkeyed_too():
    reflected = response(b"Cache-Control: public, max-age=60",
                         body=b"Forwarded host=evil.test")
    findings = poisoning_findings("/", request(b"Forwarded: host=evil.test"),
                                  reflected)
    assert len(findings) == 1


def test_a_generic_value_is_never_evidence():
    """Neither the bare word nor the scheme inside a URL: see the TLS case below."""
    stored = response(b"Cache-Control: public, max-age=60",
                      body=b"<p>we serve https traffic</p>")
    assert poisoning_findings("/", request(b"X-Forwarded-Proto: https"), stored) == []


def test_echoing_the_keyed_host_is_not_evidence():
    """The cache already keys on the host, so seeing it back proves nothing."""
    reflected = response(b"Cache-Control: public, max-age=60",
                         body=b'<a href="//example.com/">home</a>')
    assert poisoning_findings("/", request(b"X-Forwarded-Host: example.com"),
                              reflected) == []


def test_the_reflection_search_is_case_insensitive():
    reflected = response(b"Cache-Control: public, max-age=60", body=b"EVIL.TEST")
    assert len(poisoning_findings("/", request(b"X-Forwarded-Host: evil.test"),
                                  reflected)) == 1


def test_one_finding_per_header_however_many_values_it_has():
    reflected = response(b"Cache-Control: public, max-age=60",
                         body=b"evil.test worse.test")
    findings = poisoning_findings("/", request(b"X-Forwarded-Host: evil.test",
                                               b"X-Forwarded-Host: worse.test"),
                                  reflected)
    assert len(findings) == 1


def test_a_post_response_no_cache_stores_is_not_poisoning():
    reflected = response(body=b"evil.test")
    poisoned = request(b"X-Forwarded-Host: evil.test", method=b"POST")
    assert poisoning_findings("/", poisoned, reflected) == []


def test_the_body_scan_is_bounded():
    """A reflection past the scan limit is missed, deliberately, not hunted."""
    huge = response(b"Cache-Control: public, max-age=60",
                    body=b"." * (1 << 20) + b"evil.test")
    assert poisoning_findings("/", request(b"X-Forwarded-Host: evil.test"),
                              huge) == []


# --- hostile input ---------------------------------------------------------

def test_a_target_past_the_bound_loses_its_suffix_rather_than_growing_the_scan():
    assert deception_finding("/" + "a" * 20000 + ".css", dynamic()) is None


@pytest.mark.parametrize("target", ["", "/", "..", "%", "%2", "///;;;",
                                    "http://", "https://host", "/x?" + "&" * 500,
                                    "/\x00.css", "/." + "." * 500])
def test_odd_targets_return_a_result_rather_than_raising(target):
    finding = deception_finding(target, dynamic())
    assert finding is None or finding.kind == KIND_DECEPTION
    assert poisoning_findings(target, request(), response()) == []


@pytest.mark.parametrize("value", [b"", b",,,", b'no-cache="', b"max-age=-1",
                                   b"max-age=" + b"9" * 100, b"=", b'private="x"'])
def test_odd_cache_control_values_still_decide(value):
    assert isinstance(is_cacheable(response(b"Cache-Control: " + value))[0], bool)


# --- shapes that must stay silent, found by review -------------------------

def test_a_tls_terminating_load_balancer_is_not_a_poisoning_report():
    """X-Forwarded-Proto: https plus an https redirect is every site on earth."""
    redirect = response(b"Cache-Control: public, max-age=3600",
                        b"Location: https://example.com/home",
                        status=b"HTTP/1.1 301 Moved Permanently")
    assert poisoning_findings("/", request(b"X-Forwarded-Proto: https"),
                              redirect) == []


def test_an_https_link_in_a_page_is_not_a_poisoning_report():
    page = response(b"Cache-Control: public, max-age=60",
                    b"Content-Type: text/html",
                    body=b'<a href="https://example.com/help">help</a>')
    assert poisoning_findings("/", request(b"X-Forwarded-Proto: https"), page) == []


def test_an_unusual_scheme_value_is_still_evidence():
    """Dropping the ubiquitous values must not drop an attacker-chosen one."""
    redirect = response(b"Cache-Control: public, max-age=60",
                        b"Location: https://evil.test/", status=b"HTTP/1.1 301 Moved")
    assert len(poisoning_findings("/", request(b"X-Forwarded-Proto: https://evil.test"),
                                  redirect)) == 1


@pytest.mark.parametrize("target,ctype", [("/static/font.woff2", b"application/octet-stream"),
                                          ("/docs/manual.pdf", b"application/octet-stream"),
                                          ("/static/app.js.map", b"binary/octet-stream")])
def test_a_server_that_does_not_know_the_type_is_not_a_dynamic_response(target, ctype):
    """application/octet-stream means "unlabelled bytes", not "a per-user page"."""
    asset = response(b"Content-Type: " + ctype,
                     b"Cache-Control: public, max-age=31536000", body=b"\x00\x01")
    assert deception_finding(target, asset) is None


def test_a_type_that_really_contradicts_the_suffix_still_counts():
    page = response(b"Content-Type: application/json",
                    b"Cache-Control: public, max-age=60", body=b'{"balance":42}')
    assert deception_finding("/account/statement.css", page) is not None


def test_an_expires_no_arithmetic_can_hold_is_a_result_not_a_crash():
    """Header bytes are attacker influenced, so nothing here may raise."""
    for value in (b"Fri, 31 Dec 99999999999 23:59:59 GMT",
                  b"Thu, 01 Jan 1970 00:00:00 " + b"9" * 14):
        broken = response(b"Expires: " + value, b"Content-Type: text/html",
                          b"Set-Cookie: session=abc", body=b"evil.test")
        assert is_cacheable(broken)[0] is False
        assert deception_finding("/account/profile.css", broken) is not None
        assert poisoning_findings("/", request(b"X-Forwarded-Host: evil.test"),
                                  broken) == []


def test_a_qualified_repeat_cannot_erase_a_bare_directive():
    assert is_cacheable(response(b"Cache-Control: no-store",
                                 b'Cache-Control: no-store="x"'))[0] is False
    assert is_cacheable(response(b'Cache-Control: private, private="Set-Cookie"'))[0] is False
