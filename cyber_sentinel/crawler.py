"""A polite, same-host crawler.

Iterating a Crawler yields Page objects discovered by following in-scope
links breadth-first, bounded by max_pages. `.count` reflects how many
pages have been yielded so far (read it after iterating).
"""
from __future__ import unicode_literals

from collections import deque

from .client import NotAPage, RedirectedToExternal
from .utils import same_host


class Crawler(object):
    def __init__(self, start_url, client, additional_pages=None,
                 max_pages=40, max_depth=3):
        self.start_url = start_url
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.additional_pages = additional_pages or []
        self.count = 0

    def __iter__(self):
        seen = set()
        queue = deque()
        queue.append((self.start_url, 0))
        for extra in self.additional_pages:
            queue.append((extra, 0))

        while queue and self.count < self.max_pages:
            url, depth = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            try:
                page = self.client.get(url)
            except (NotAPage, RedirectedToExternal):
                continue
            except Exception:
                continue

            self.count += 1
            yield page

            if depth < self.max_depth:
                for link in page.links:
                    if link not in seen and same_host(link, self.start_url):
                        queue.append((link, depth + 1))
