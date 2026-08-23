"""Regex/parser-based entity recognition per field (docs/BLUEPRINT.md 5.2).

A field is labelled with an entity type when a large enough share of its
non-empty values look like that entity. Two labels cannot be decided from values
alone and require a field-name hint:

* ``port`` -- every port is just a small integer, and so are status codes,
  ASNs, and byte counts.
* ``user`` -- a username has no shape of its own.

``file_path`` is also name-guarded on POSIX-looking values, because ``/products``
is a URL path, not a file path, and mislabelling it would send ECS gap analysis
at the wrong target field.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import Any, Callable, Sequence

DEFAULT_THRESHOLD = 0.8
MAX_SAMPLED_VALUES = 500


class EntityType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    EMAIL = "email"
    URL = "url"
    PORT = "port"
    FILE_PATH = "file_path"
    PROCESS_NAME = "process_name"
    USER = "user"


_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://\S+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?!-)[A-Za-z0-9\-_]{1,63}(?<!-)(?:\.[A-Za-z0-9\-_]{1,63})*\.[A-Za-z]{2,63}$"
)
_WINDOWS_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\)")
_POSIX_PATH_RE = re.compile(r"^/(?:[^/\0]+/)+[^/\0]*$")
_PROCESS_RE = re.compile(r"^[\w.\- ]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|sh|py|jar)$", re.IGNORECASE)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][\w.\-@\\$ ]{0,63}$")

_PORT_NAMES = re.compile(r"(^|[._\-])port(s)?([._\-]|$)|port$", re.IGNORECASE)
_USER_NAMES = re.compile(
    r"(user|username|account|logon|login|principal|samaccountname|actor|owner|subject)",
    re.IGNORECASE,
)
# Names that contain a user-ish word but describe something else entirely:
# LogonProcessName, AuthenticationPackageName, LogonType, UserAgent, accountid.
_NOT_USER_NAMES = re.compile(r"(process|package|type|agent|id$|_id|count|time|status|domain)", re.IGNORECASE)
_FILE_NAMES = re.compile(r"(file|path|directory|folder|dir|image|executable|binary)", re.IGNORECASE)
_URLISH_NAMES = re.compile(r"(uri|url|request|referer|referrer|query|endpoint)", re.IGNORECASE)
_PROCESS_NAMES = re.compile(r"(process|image|command|proc|exe)", re.IGNORECASE)


def _is_ip(_name: str, value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_hash(_name: str, value: str) -> bool:
    return bool(_HASH_RE.match(value))


def _is_email(_name: str, value: str) -> bool:
    return bool(_EMAIL_RE.match(value))


def _is_url(_name: str, value: str) -> bool:
    return bool(_URL_RE.match(value))


def _is_domain(_name: str, value: str) -> bool:
    # An all-numeric last label means this is a bare IPv4, already handled above.
    return bool(_DOMAIN_RE.match(value)) and not value.rsplit(".", 1)[-1].isdigit()


def _is_file_path(name: str, value: str) -> bool:
    if _WINDOWS_PATH_RE.match(value):
        return True
    if not _POSIX_PATH_RE.match(value):
        return False
    # A POSIX-looking path in a URL field is a URL path, not a file path.
    return bool(_FILE_NAMES.search(name)) and not _URLISH_NAMES.search(name)


def _is_process_name(name: str, value: str) -> bool:
    if _PROCESS_RE.match(value):
        return True
    if _WINDOWS_PATH_RE.match(value) and _PROCESS_NAMES.search(name):
        return True
    return False


def _is_port(name: str, value: str) -> bool:
    if not _PORT_NAMES.search(name):
        return False
    try:
        return 0 <= int(value) <= 65535
    except ValueError:
        return False


def _is_user(name: str, value: str) -> bool:
    if not _USER_NAMES.search(name) or _NOT_USER_NAMES.search(name):
        return False
    if value.isdigit() or _is_ip(name, value):
        return False
    return bool(_USERNAME_RE.match(value))


# Ordered most specific first: an email also looks like a domain, a URL contains
# one, and a hash is a plausible username.
_DETECTORS: tuple[tuple[EntityType, Callable[[str, str], bool]], ...] = (
    (EntityType.IP, _is_ip),
    (EntityType.EMAIL, _is_email),
    (EntityType.URL, _is_url),
    (EntityType.HASH, _is_hash),
    (EntityType.PORT, _is_port),
    (EntityType.PROCESS_NAME, _is_process_name),
    (EntityType.FILE_PATH, _is_file_path),
    (EntityType.DOMAIN, _is_domain),
    (EntityType.USER, _is_user),
)


def detect_entity_type(
    field_name: str,
    values: Sequence[Any],
    *,
    threshold: float = DEFAULT_THRESHOLD,
) -> EntityType | None:
    """Label a field with the entity type most of its values look like.

    Returns None when no detector reaches ``threshold`` -- an honest "unknown"
    beats a wrong label that later steps would trust.
    """
    samples = _clean(values)
    if not samples:
        return None

    for entity_type, matcher in _DETECTORS:
        hits = sum(1 for value in samples if matcher(field_name, value))
        if hits / len(samples) >= threshold:
            return entity_type
    return None


def _clean(values: Sequence[Any]) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            cleaned.append(text)
        if len(cleaned) >= MAX_SAMPLED_VALUES:
            break
    return cleaned
