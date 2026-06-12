from urlhaus_threat_intel.url_utils import infer_default_port, parse_url


def test_parse_ip_url_with_explicit_port():
    parsed = parse_url("http://117.216.19.13:42598/i")
    assert parsed.scheme == "http"
    assert parsed.host == "117.216.19.13"
    assert parsed.host_type == "ip"
    assert parsed.ip_address == "117.216.19.13"
    assert parsed.port == 42598
    assert parsed.path_depth == 1


def test_parse_domain_url_with_default_https_port():
    parsed = parse_url("https://example.com/path/to/file.exe?x=1")
    assert parsed.scheme == "https"
    assert parsed.host == "example.com"
    assert parsed.host_type == "domain"
    assert parsed.registered_domain == "example.com"
    assert parsed.tld == "com"
    assert parsed.port == 443
    assert parsed.path_depth == 3
    assert parsed.has_query is True


def test_default_port_unknown_scheme():
    assert infer_default_port("ftp") is None
