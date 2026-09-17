"""One transport policy for authenticated requests: HTTPS and no redirects."""
from __future__ import annotations

import math
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def validate_https_url(value: str, *, allow_query: bool = True) -> str:
    if not isinstance(value, str) or any(ch.isspace() or ord(ch) < 32 for ch in value):
        raise ValueError("Endpoint must be a valid HTTPS URL")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or "\\" in value
                or (parsed.query and not allow_query)):
            raise ValueError
        _ = parsed.port
    except ValueError:
        raise ValueError("Endpoint must use HTTPS, without embedded credentials or a fragment") from None
    return value


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "Authenticated redirects are refused", headers, fp)


def secure_urlopen(request: Request, *, timeout: float = 60):
    validate_https_url(request.full_url)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("HTTP timeout must be positive and finite")
    return build_opener(NoRedirects()).open(request, timeout=timeout)


def read_response(response, *, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    data = response.read(limit + 1)
    if len(data) > limit:
        raise URLError("Response exceeds the allowed byte limit")
    return data


def multipart_filename(name: str) -> str:
    # File identity is local display metadata, not a raw multipart header.
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)[:200] or "upload"
