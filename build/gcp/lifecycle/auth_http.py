"""Bounded stdlib HTTP/auth shared by explicit cloud adapters (#161).

No retries or credential persistence. Callers map statuses to their own domain
errors; uncertain transport outcomes must never be interpreted as absence.
Only fixed Google API hosts are admitted, and redirects are not followed.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import subprocess
from typing import Callable
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class TransportError(Exception):
    """Sanitized authentication, network or response-bound failure."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes


def gcloud_token() -> str:
    """Obtain a short-lived token from the trusted runner's existing identity.

    No shell, login, account switching, token files or token logging. Captured
    subprocess diagnostics are deliberately excluded from raised errors.
    """
    try:
        result = subprocess.run(
            ["gcloud", "auth", "print-access-token", "--quiet"],
            capture_output=True, text=True, timeout=30, check=True)
        token = result.stdout.strip()
        _check_token(token)
        return token
    except Exception:
        raise TransportError("short-lived credential acquisition failed") from None


def _check_token(token: str) -> None:
    if (not isinstance(token, str) or not 1 <= len(token) <= 4096 or
            not re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", token)):
        raise TransportError("invalid short-lived credential")


def bearer_headers(token_provider: Callable[[], str]) -> dict[str, str]:
    try:
        token = token_provider()
        _check_token(token)
    except Exception:
        raise TransportError("short-lived credential acquisition failed") from None
    return {"Authorization": f"Bearer {token}"}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpTransport:
    """HTTP statuses return unchanged; network/bound failures raise safely."""

    def __init__(self, *, opener=None):
        self._opener = opener if opener is not None else build_opener(_NoRedirect())

    def request(self, method: str, url: str, *, headers: dict[str, str],
                body: bytes | None = None, timeout: float = 20,
                max_bytes: int = 1_048_576) -> HttpResponse:
        try:
            target = urlsplit(url)
            if (target.scheme != "https" or target.hostname not in
                    {"storage.googleapis.com", "compute.googleapis.com",
                     "oslogin.googleapis.com"} or
                    target.netloc != target.hostname or target.fragment or
                    method not in {"GET", "POST", "DELETE"} or
                    not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or
                    not 1 <= max_bytes <= 2_097_152 or not 0 < timeout <= 60):
                raise ValueError("invalid request")
            req = Request(url, data=body, headers=headers, method=method)
            try:
                response = self._opener.open(req, timeout=timeout)
            except HTTPError as exc:
                response = exc
            with response:
                payload = response.read(max_bytes + 1)
                if len(payload) > max_bytes:
                    raise ValueError("response exceeds limit")
                return HttpResponse(response.code, payload)
        except Exception:
            # Never echo URL, request headers, body, token or server diagnostics.
            raise TransportError("cloud HTTP request failed or exceeded bounds") from None
