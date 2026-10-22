"""Thin HTTP wrapper so network access is explicit, testable and never leaks tokens."""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from . import __version__

USER_AGENT = f"oss-intake/{__version__}"
DEFAULT_TIMEOUT = 30
GITHUB_API_HOST = "api.github.com"


class HttpError(Exception):
    """Network or protocol failure. Messages never include request headers."""


class Http:
    """Interface used by all network-facing modules. Tests substitute a fake."""

    def get_json(self, url: str, params: dict | None = None) -> tuple[int, Any]:
        raise NotImplementedError

    def post_json(self, url: str, body: Any) -> tuple[int, Any]:
        raise NotImplementedError


class RequestsHttp(Http):
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, github_token: str | None = None) -> None:
        import requests

        self._requests = requests
        self._session = requests.Session()
        self._session.headers["User-Agent"] = USER_AGENT
        self._timeout = timeout
        # Read once, held privately, attached only to api.github.com requests, never logged.
        self._github_token = github_token if github_token is not None else os.environ.get("GITHUB_TOKEN")

    def _headers(self, url: str) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if urlparse(url).hostname == GITHUB_API_HOST:
            headers["Accept"] = "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            if self._github_token:
                headers["Authorization"] = f"Bearer {self._github_token}"
        return headers

    def _do(self, method: str, url: str, **kw: Any) -> tuple[int, Any]:
        try:
            r = self._session.request(method, url, headers=self._headers(url), timeout=self._timeout, **kw)
        except self._requests.RequestException as exc:
            # str(exc) can include the URL but not headers; the token is never in the URL.
            raise HttpError(f"{method} {urlparse(url).netloc}{urlparse(url).path}: {type(exc).__name__}") from None
        if r.status_code == 204 or not r.content:
            return r.status_code, None
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, None

    def get_json(self, url: str, params: dict | None = None) -> tuple[int, Any]:
        return self._do("GET", url, params=params)

    def post_json(self, url: str, body: Any) -> tuple[int, Any]:
        return self._do("POST", url, json=body)

    @property
    def has_github_token(self) -> bool:
        return bool(self._github_token)
