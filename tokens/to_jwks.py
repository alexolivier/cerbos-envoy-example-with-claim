#!/usr/bin/env python3
"""Convert an RSA PEM public key into a JWKS document."""

from __future__ import annotations

import base64
import json
import pathlib
import sys
from typing import Tuple

PUB_PEM_PATH = pathlib.Path(__file__).with_name("jwt-signing.pub.pem")
JWKS_PATH = pathlib.Path(__file__).with_name("jwt-signing.jwks.json")
KEY_ID = "local-dev-cert"


def _read_length(buffer: bytes, offset: int) -> Tuple[int, int]:
    first = buffer[offset]
    offset += 1
    if first & 0x80 == 0:
        return first, offset
    num_bytes = first & 0x7F
    length = int.from_bytes(buffer[offset : offset + num_bytes], "big")
    offset += num_bytes
    return length, offset


def _read_element(buffer: bytes, offset: int, expected_tag: int) -> Tuple[bytes, int]:
    if buffer[offset] != expected_tag:
        raise ValueError(f"unexpected ASN.1 tag: expected {expected_tag:#x}, got {buffer[offset]:#x}")
    offset += 1
    length, offset = _read_length(buffer, offset)
    end = offset + length
    return buffer[offset:end], end


def _decode_pem(path: pathlib.Path) -> bytes:
    text = path.read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines() if line and not line.startswith("-----")]
    data = base64.b64decode("".join(lines))
    return data


def _read_rsa_public_numbers(subject_public_key_info: bytes) -> Tuple[int, int]:
    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    offset = 0
    spki, _ = _read_element(subject_public_key_info, offset, 0x30)  # SEQUENCE
    offset = 0

    # algorithm identifier
    _, offset = _read_element(spki, offset, 0x30)  # AlgorithmIdentifier sequence

    # subjectPublicKey BIT STRING
    bit_string, _ = _read_element(spki, offset, 0x03)

    if not bit_string:
        raise ValueError("empty BIT STRING")
    unused_bits = bit_string[0]
    if unused_bits != 0:
        raise ValueError("unexpected unused bits in BIT STRING")
    rsa_public_key = bit_string[1:]

    # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    offset = 0
    rsa_seq, _ = _read_element(rsa_public_key, offset, 0x30)
    offset = 0

    modulus_bytes, offset = _read_element(rsa_seq, offset, 0x02)
    exponent_bytes, _ = _read_element(rsa_seq, offset, 0x02)

    modulus = int.from_bytes(modulus_bytes, "big")
    exponent = int.from_bytes(exponent_bytes, "big")

    return modulus, exponent


def _b64url_int(value: int) -> str:
    if value == 0:
        return "AA"
    byte_length = (value.bit_length() + 7) // 8
    data = value.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def main() -> None:
    if not PUB_PEM_PATH.exists():
        print(f"public key not found at {PUB_PEM_PATH}", file=sys.stderr)
        sys.exit(1)

    spki = _decode_pem(PUB_PEM_PATH)
    modulus, exponent = _read_rsa_public_numbers(spki)

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KEY_ID,
                "n": _b64url_int(modulus),
                "e": _b64url_int(exponent),
            }
        ]
    }

    JWKS_PATH.write_text(json.dumps(jwks, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
