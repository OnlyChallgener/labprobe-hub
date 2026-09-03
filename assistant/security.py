"""Small authenticated-encryption wrapper for provider credentials."""

from __future__ import annotations

import base64
import hashlib
import os
from typing import List, Optional, Tuple

from Crypto.Cipher import AES


class MasterKeyUnavailable(RuntimeError):
    """Raised instead of ever falling back to a plaintext credential."""


def _derive_key(value: str) -> bytes:
    return hashlib.sha256(("LabProbe AI credential v1\0" + value).encode("utf-8")).digest()


def _master_key_values() -> List[Tuple[str, bytes]]:
    """Return the credential-encryption key without making first-run unusable.

    A Hub already requires ``APP_TOKEN`` before it accepts any APP request.  It is
    therefore a suitable deployment-local secret for deriving the key used to
    encrypt a provider key when the optional dedicated key has not been set.
    Keeping ``LABPROBE_AI_MASTER_KEY`` as the first choice lets operators rotate
    the AI credential boundary independently when they need to.
    """
    dedicated = str(os.environ.get("LABPROBE_AI_MASTER_KEY") or "").strip()
    if dedicated:
        return [("master", _derive_key(dedicated))]
    current = str(os.environ.get("APP_TOKEN") or "").strip()
    if not current or current == "change-app-token":
        raise MasterKeyUnavailable(
            "Hub 缺少可用于加密 API Key 的 APP_TOKEN；请先在 Hub 配置中设置 APP_TOKEN"
        )
    values = [("current", _derive_key(current))]
    previous = str(os.environ.get("APP_TOKEN_PREVIOUS") or "").strip()
    if previous and previous not in {"change-app-token", current}:
        values.append(("previous", _derive_key(previous)))
    return values


def _master_key() -> bytes:
    return _master_key_values()[0][1]


def encrypt_secret(value: str) -> str:
    """Return versioned AES-GCM ciphertext; callers must not log ``value``."""
    if not isinstance(value, str) or not value:
        raise ValueError("API key is required")
    # A fixed nonce length makes the compact versioned storage format explicit.
    cipher = AES.new(_master_key(), AES.MODE_GCM, nonce=os.urandom(12))
    ciphertext, tag = cipher.encrypt_and_digest(value.encode("utf-8"))
    return "v1:" + base64.urlsafe_b64encode(cipher.nonce + tag + ciphertext).decode("ascii")


def decrypt_secret_with_migration(value: Optional[str]) -> Tuple[str, Optional[str]]:
    """Decrypt a credential and return a current-key replacement when needed.

    During APP_TOKEN rotation the previous token is only considered when no
    dedicated AI master key is configured. Callers can persist the returned
    replacement with a compare-and-swap update, then safely remove PREVIOUS.
    """
    if not value or not value.startswith("v1:"):
        raise ValueError("stored AI API key is missing or has an unsupported format")
    try:
        packed = base64.urlsafe_b64decode(value[3:].encode("ascii"))
        nonce, tag, ciphertext = packed[:12], packed[12:28], packed[28:]
        if len(nonce) != 12 or len(tag) != 16 or not ciphertext:
            raise ValueError("invalid ciphertext")
        for source, key in _master_key_values():
            try:
                plaintext = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag).decode("utf-8")
            except Exception:
                continue
            return plaintext, encrypt_secret(plaintext) if source == "previous" else None
        raise ValueError("authentication failed")
    except MasterKeyUnavailable:
        raise
    except Exception as exc:
        raise ValueError("stored AI API key could not be decrypted") from exc


def decrypt_secret(value: Optional[str]) -> str:
    return decrypt_secret_with_migration(value)[0]


def mask_secret(value: Optional[str]) -> Optional[str]:
    """Mask a known configured secret without decrypting it."""
    return "configured" if value else None
