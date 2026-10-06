"""Very lightweight technology fingerprinting from headers + HTML markers.

Returns a dict of {app_name: [categories]} so main.py can group detected
technologies. This is passive: it only reads what the server already sends.
"""
from __future__ import unicode_literals

import re

from .client import NotAPage, RedirectedToExternal

# name -> (category, header-or-html signature regex, where)
SIGNATURES = [
    ("WordPress", "CMS", re.compile(r"wp-content|wp-includes", re.I), "html"),
    ("Drupal", "CMS", re.compile(r"Drupal", re.I), "html"),
    ("Joomla", "CMS", re.compile(r"com_content|Joomla", re.I), "html"),
    ("jQuery", "JS Library", re.compile(r"jquery[.-]", re.I), "html"),
    ("React", "JS Framework", re.compile(r"data-reactroot|__REACT", re.I), "html"),
    ("Bootstrap", "UI Framework", re.compile(r"bootstrap(\.min)?\.css", re.I), "html"),
    ("Nginx", "Web Server", re.compile(r"nginx", re.I), "server"),
    ("Apache", "Web Server", re.compile(r"apache", re.I), "server"),
    ("Microsoft-IIS", "Web Server", re.compile(r"iis", re.I), "server"),
    ("PHP", "Language", re.compile(r"php", re.I), "powered"),
    ("ASP.NET", "Framework", re.compile(r"asp\.net", re.I), "powered"),
    ("Express", "Framework", re.compile(r"express", re.I), "powered"),
    ("Cloudflare", "CDN", re.compile(r"cloudflare", re.I), "server"),
]


def app_detect(url, client):
    detected = {}
    try:
        page = client.get(url)
    except (NotAPage, RedirectedToExternal, Exception):
        return detected

    server = page.headers.get("Server", "")
    powered = page.headers.get("X-Powered-By", "")
    html = page.text or ""

    for name, category, pattern, where in SIGNATURES:
        haystack = {"server": server, "powered": powered, "html": html}.get(where, "")
        if haystack and pattern.search(haystack):
            detected.setdefault(name, [])
            if category not in detected[name]:
                detected[name].append(category)
    return detected
