"""HTTP client and Page model for CyberSentinel.

The Client is a thin wrapper around requests.Session that returns Page
objects. A Page lazily parses the HTML once so the attack checks can reuse
the parsed forms / links / inputs instead of re-parsing on every call.
"""
from __future__ import unicode_literals

from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {
    "User-Agent": "CyberSentinel/1.0 (+authorized security assessment)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Content types we are willing to parse as a "page".
HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")


class NotAPage(Exception):
    """Raised when a response is not an HTML page we can meaningfully scan."""


class RedirectedToExternal(Exception):
    """Raised when a request is redirected off the original host."""


class Form(object):
    """A lightweight representation of an HTML <form>."""

    def __init__(self, action, method, inputs):
        self.action = action
        self.method = (method or "get").lower()
        # inputs: list of dicts {name, type, value}
        self.inputs = inputs

    @property
    def input_names(self):
        return [i["name"] for i in self.inputs if i.get("name")]

    def __repr__(self):
        return "<Form {} {} fields={}>".format(
            self.method.upper(), self.action, self.input_names
        )


class Page(object):
    """A fetched HTTP response with lazily-parsed HTML helpers."""

    def __init__(self, response):
        self._response = response
        self.url = response.url
        self.status_code = response.status_code
        self.headers = response.headers
        self.cookies = response.cookies
        try:
            self.text = response.text
        except Exception:
            self.text = ""
        self._soup = None
        self._forms = None
        self._links = None

    @property
    def content_type(self):
        return self.headers.get("Content-Type", "").lower()

    @property
    def is_html(self):
        return any(ct in self.content_type for ct in HTML_CONTENT_TYPES)

    @property
    def soup(self):
        if self._soup is None:
            parser = "lxml"
            try:
                self._soup = BeautifulSoup(self.text, parser)
            except Exception:
                self._soup = BeautifulSoup(self.text, "html.parser")
        return self._soup

    @property
    def query_params(self):
        """Dict of query-string params present on this page's own URL."""
        return parse_qs(urlparse(self.url).query)

    @property
    def forms(self):
        if self._forms is None:
            self._forms = self._parse_forms()
        return self._forms

    def _parse_forms(self):
        forms = []
        for f in self.soup.find_all("form"):
            action = urljoin(self.url, f.get("action") or self.url)
            method = f.get("method", "get")
            inputs = []
            for tag in f.find_all(["input", "textarea", "select"]):
                inputs.append(
                    {
                        "name": tag.get("name"),
                        "type": tag.get("type", "text"),
                        "value": tag.get("value", ""),
                    }
                )
            forms.append(Form(action, method, inputs))
        return forms

    @property
    def links(self):
        if self._links is None:
            self._links = self._parse_links()
        return self._links

    def _parse_links(self):
        links = set()
        for a in self.soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            links.add(urljoin(self.url, href))
        return sorted(links)

    def __repr__(self):
        return "<Page [{}] {}>".format(self.status_code, self.url)


class Client(object):
    """Session-backed HTTP client with sane defaults and a short timeout."""

    def __init__(self, timeout=15, verify_tls=True, max_retries=2):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.timeout = timeout
        self.verify_tls = verify_tls
        adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _host(self, url):
        return urlparse(url).netloc

    def request(self, method, url, allow_external_redirect=False, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        kwargs.setdefault("allow_redirects", True)
        origin_host = self._host(url)
        resp = self.session.request(method, url, **kwargs)
        if (
            not allow_external_redirect
            and self._host(resp.url)
            and self._host(resp.url) != origin_host
        ):
            raise RedirectedToExternal(
                "{} redirected to external host {}".format(url, resp.url)
            )
        return resp

    def get(self, url, require_html=True, **kwargs):
        resp = self.request("GET", url, **kwargs)
        page = Page(resp)
        if require_html and not page.is_html:
            raise NotAPage("{} is not HTML ({})".format(url, page.content_type))
        return page

    def raw_get(self, url, **kwargs):
        """GET returning a Page without the HTML-type requirement."""
        return Page(self.request("GET", url, **kwargs))

    def post(self, url, data=None, **kwargs):
        return Page(self.request("POST", url, data=data, **kwargs))
