# Ported to Python from https://github.com/SAP/gigya-android-sdk/tree/main
# Licensed under Apache 2.0, a copy of which is enclosed in this repository

import base64
import hmac
import urllib.parse
import hashlib
from collections import OrderedDict
from typing import Optional


def _build_encoded_query(params: dict) -> str:
    if not params:
        return ""
    return "&".join(
        f"{key}={urllib.parse.quote_plus(str(value))}" for key, value in params.items() if value
    )


def _url_encode(value: str) -> str:
    return urllib.parse.quote_plus(value).replace("+", "%20").replace("*", "%2A").replace("%7E", "~")


def _encode_signature(base_signature: str, secret: str) -> str:
    key = base64.b64decode(secret)
    signing_key = hmac.new(key, base_signature.encode("utf-8"), digestmod=hashlib.sha1)
    return base64.urlsafe_b64encode(signing_key.digest()).decode("utf-8")


def get_signature(secret: str, http_method: str, url: str, params: dict) -> Optional[str]:
    if not all([params, url, http_method, secret]):
        return None

    try:
        params = OrderedDict(params)
        normalized_url = urllib.parse.urlunparse(
            urllib.parse.ParseResult(
                scheme=urllib.parse.urlparse(url).scheme.lower(),
                netloc=urllib.parse.urlparse(url).netloc.lower(),
                path=urllib.parse.urlparse(url).path,
                params="",
                query="",
                fragment="",
            )
        )
        base_signature = f"{http_method.upper()}&{_url_encode(normalized_url)}&{_url_encode(_build_encoded_query(params))}"
        return _encode_signature(base_signature, secret)
    except Exception as ex:
        print(f"Error generating signature: {ex}")
        return None
