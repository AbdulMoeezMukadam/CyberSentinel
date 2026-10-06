"""Small, dependency-light helpers used across CyberSentinel."""
from __future__ import unicode_literals

import json
import os
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl


def validate_url(url):
    """Normalise a user-supplied URL, defaulting to https:// when no scheme."""
    url = (url or "").strip()
    if not url:
        raise ValueError("Empty URL")
    if not urlparse(url).scheme:
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid URL: {}".format(url))
    return urlunparse(parsed)


def get_url_host(url):
    """Return the hostname (without port) for report naming and scoping."""
    netloc = urlparse(url).netloc
    return netloc.split("@")[-1].split(":")[0]


def same_host(a, b):
    return get_url_host(a) == get_url_host(b)


def dict_iterate(d):
    """Stable (key, value) iteration, usable on both py2/py3 dict views."""
    return list(d.items())


def set_query_param(url, name, value):
    """Return url with query parameter `name` set/overwritten to `value`."""
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[name] = value
    new_query = urlencode(params)
    return urlunparse(parsed._replace(query=new_query))


def add_duplicate_param(url, name, value):
    """Append a duplicate query parameter (used for HPP checks)."""
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def check_boolean_option(value, default=False):
    """Interpret common truthy/falsey strings as a bool."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "y", "yes", "true", "on")


def read_config(path=None):
    """Read optional JSON config; return {} when absent or unreadable."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (IOError, OSError, ValueError):
        return {}
