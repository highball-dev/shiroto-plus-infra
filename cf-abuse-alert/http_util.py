from __future__ import annotations

import http.client
import json
import socket
import ssl
import urllib.error
import urllib.request
from typing import Callable

import certifi

# (url, headers, json payload, timeout seconds) -> (status, body). Tests inject a fake.
Post = Callable[[str, dict, dict, float], tuple[int, bytes]]

_SSL = ssl.create_default_context(cafile=certifi.where())


def post_json(url: str, headers: dict, payload: dict, timeout: float) -> tuple[int, bytes]:
    """POST JSON. Raises TimeoutError or OSError, and nothing else.

    The error text never contains the URL or a header: the Slack webhook URL and the Cloudflare
    token are secrets, and urllib puts the URL into some of its own messages.
    """
    data = json.dumps(payload).encode("utf-8")
    try:
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except (OSError, http.client.HTTPException):
            return e.code, b""
    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise TimeoutError("timeout") from None
        raise OSError(f"network error: {type(e.reason).__name__}") from None
    except (socket.timeout, TimeoutError):
        raise TimeoutError("timeout") from None
    except http.client.HTTPException as e:
        # IncompleteRead, BadStatusLine, RemoteDisconnected (some are not OSError).
        raise OSError(f"network error: {type(e).__name__}") from None
    except ValueError:
        # "unknown url type: <the whole URL>": a URL without a scheme.
        raise OSError("invalid URL") from None
    except OSError as e:
        raise OSError(f"network error: {type(e).__name__}") from None
