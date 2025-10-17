#!/usr/bin/env python3
"""Emit a signed JWT string for the given fixture."""

from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys

SIGNING_KEY_PATH = pathlib.Path(__file__).with_name("jwt-signing.key")
KEY_ID = "local-dev-cert"
ALGORITHM = "RS256"


def encode_segment(data: dict) -> str:
    json_bytes = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")


def load_payload(name: str) -> dict:
    fixture_path = pathlib.Path(__file__).with_name(f"{name}.json")
    return json.loads(fixture_path.read_text(encoding="utf-8"))

def load_token(name: str) -> str:
    payload = load_payload(name)
    header = {
        "alg": ALGORITHM,
        "kid": KEY_ID,
        "typ": "JWT",
    }

    header_segment = encode_segment(header)
    payload_segment = encode_segment(payload)

    message = f"{header_segment}.{payload_segment}".encode("ascii")
    signature_segment = sign_jwt(message)

    return f"{header_segment}.{payload_segment}.{signature_segment}"


def sign_jwt(message: bytes) -> str:
    if not SIGNING_KEY_PATH.exists():
        raise FileNotFoundError(f"signing key not found at {SIGNING_KEY_PATH}")

    result = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(SIGNING_KEY_PATH),
        ],
        input=message,
        capture_output=True,
        check=True,
    )

    signature = base64.urlsafe_b64encode(result.stdout).decode("ascii").rstrip("=")
    return signature


def main() -> None:
    if len(sys.argv) != 2:
        script = pathlib.Path(sys.argv[0]).name
        print(f"usage: {script} <token-name>", file=sys.stderr)
        sys.exit(1)

    try:
        token = load_token(sys.argv[1])
    except FileNotFoundError:
        print(f"unknown token fixture '{sys.argv[1]}'", file=sys.stderr)
        sys.exit(1)

    print(token)


if __name__ == "__main__":
    main()
