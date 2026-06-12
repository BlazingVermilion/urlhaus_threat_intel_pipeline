"""Shared schema definitions for URLhaus data."""

URLHAUS_COLUMNS = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
]

NORMALIZED_COLUMNS = [
    *URLHAUS_COLUMNS,
    "dateadded_utc",
    "scheme",
    "host",
    "host_type",
    "registered_domain",
    "tld",
    "ip_address",
    "port",
    "path",
    "path_depth",
    "url_length",
    "tag_count",
    "has_query",

    "host_length",
    "host_digit_ratio",
    "host_entropy",
    "path_length",
    "path_digit_ratio",
    "file_extension",
    "has_executable_extension",
    "has_suspicious_path_keyword",
    "is_ip_host",
    "is_default_port",
    "is_non_standard_port",
]
