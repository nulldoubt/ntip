#!/usr/bin/env python3
"""Generate deterministic NTIP Noise transcripts with noiseprotocol 0.3.1.

This is an optional development oracle, not a runtime or build dependency.
The checked-in Zig golden values can be refreshed with an isolated environment:

    python -m pip install noiseprotocol==0.3.1
    python tests/protocol/noise_oracle.py
"""

import json

from cryptography.exceptions import InvalidTag
from noise.connection import Keypair, NoiseConnection


PROLOGUE_PREFIX = b"NTIP\x00\x01\x00"
INITIATOR_TRANSPORT_PAYLOAD = b"node-to-master"
RESPONDER_TRANSPORT_PAYLOAD = b"master-to-node"


def secret(fill: int) -> bytes:
    return bytes([(fill + 1) & 0xFF]) + bytes([fill]) * 31


def connection(name: bytes, initiator: bool, static_fill: int, ephemeral_fill: int,
               context_fill: int, remote_static_fill: int | None = None,
               psk_fill: int | None = None) -> NoiseConnection:
    peer = NoiseConnection.from_name(name)
    peer.set_as_initiator() if initiator else peer.set_as_responder()
    peer.set_prologue(PROLOGUE_PREFIX + bytes([context_fill]) * 16)
    peer.set_keypair_from_private_bytes(Keypair.STATIC, secret(static_fill))
    peer.set_keypair_from_private_bytes(Keypair.EPHEMERAL, secret(ephemeral_fill))
    if remote_static_fill is not None:
        remote_key = NoiseConnection.from_name(name).noise_protocol.dh_fn.klass.from_private_bytes(
            secret(remote_static_fill)
        )
        peer.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_key.public_bytes)
    if psk_fill is not None:
        peer.set_psks(psk=bytes([psk_fill]) * 32)
    peer.start_handshake()
    return peer


def first_transport_messages(initiator: NoiseConnection, responder: NoiseConnection) -> dict:
    initiator_to_responder = bytes(initiator.encrypt(INITIATOR_TRANSPORT_PAYLOAD))
    assert bytes(responder.decrypt(initiator_to_responder)) == INITIATOR_TRANSPORT_PAYLOAD

    responder_to_initiator = bytes(responder.encrypt(RESPONDER_TRANSPORT_PAYLOAD))
    assert bytes(initiator.decrypt(responder_to_initiator)) == RESPONDER_TRANSPORT_PAYLOAD

    return {
        "initiator_to_responder": initiator_to_responder.hex(),
        "responder_to_initiator": responder_to_initiator.hex(),
    }


def read_rejected(reader: NoiseConnection, message: bytes, case: str) -> bool:
    try:
        reader.read_message(message)
    except InvalidTag:
        return True
    raise AssertionError(f"{case}: altered credentials or transcript were accepted")


def xk() -> dict:
    name = b"Noise_XKpsk1_25519_ChaChaPoly_BLAKE2s"
    initiator = connection(name, True, 1, 3, 6, remote_static_fill=2, psk_fill=5)
    responder = connection(name, False, 2, 4, 6, psk_fill=5)
    m1 = bytes(initiator.write_message(b"enroll"))
    assert bytes(responder.read_message(m1)) == b"enroll"
    m2 = bytes(responder.write_message(b"accept"))
    assert bytes(initiator.read_message(m2)) == b"accept"
    m3 = bytes(initiator.write_message(b"confirm"))
    assert bytes(responder.read_message(m3)) == b"confirm"
    assert initiator.get_handshake_hash() == responder.get_handshake_hash()
    return {
        "messages": [m1.hex(), m2.hex(), m3.hex()],
        "hash": initiator.get_handshake_hash().hex(),
        "transport": first_transport_messages(initiator, responder),
    }


def ik() -> dict:
    name = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"
    initiator = connection(name, True, 11, 13, 15, remote_static_fill=12)
    responder = connection(name, False, 12, 14, 15)
    m1 = bytes(initiator.write_message(b"reconnect"))
    assert bytes(responder.read_message(m1)) == b"reconnect"
    m2 = bytes(responder.write_message(b"session"))
    assert bytes(initiator.read_message(m2)) == b"session"
    assert initiator.get_handshake_hash() == responder.get_handshake_hash()
    return {
        "messages": [m1.hex(), m2.hex()],
        "hash": initiator.get_handshake_hash().hex(),
        "transport": first_transport_messages(initiator, responder),
    }


def negative_cases() -> dict:
    xk_name = b"Noise_XKpsk1_25519_ChaChaPoly_BLAKE2s"
    xk_initiator = connection(xk_name, True, 1, 3, 6, remote_static_fill=2, psk_fill=5)
    xk_wrong_psk = connection(xk_name, False, 2, 4, 6, psk_fill=8)
    wrong_psk_message = bytes(xk_initiator.write_message(b"enroll"))

    xk_wrong_static_initiator = connection(
        xk_name, True, 1, 3, 6, remote_static_fill=7, psk_fill=5
    )
    xk_responder = connection(xk_name, False, 2, 4, 6, psk_fill=5)
    wrong_xk_static_message = bytes(xk_wrong_static_initiator.write_message(b"enroll"))

    xk_prologue_initiator = connection(
        xk_name, True, 1, 3, 6, remote_static_fill=2, psk_fill=5
    )
    xk_altered_prologue = connection(xk_name, False, 2, 4, 7, psk_fill=5)
    altered_xk_prologue_message = bytes(xk_prologue_initiator.write_message(b"enroll"))

    ik_name = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"
    ik_wrong_static_initiator = connection(
        ik_name, True, 11, 13, 15, remote_static_fill=16
    )
    ik_responder = connection(ik_name, False, 12, 14, 15)
    wrong_ik_static_message = bytes(ik_wrong_static_initiator.write_message(b"reconnect"))

    ik_prologue_initiator = connection(
        ik_name, True, 11, 13, 15, remote_static_fill=12
    )
    ik_altered_prologue = connection(ik_name, False, 12, 14, 16)
    altered_ik_prologue_message = bytes(ik_prologue_initiator.write_message(b"reconnect"))

    return {
        "xkpsk1_wrong_psk_rejected": read_rejected(
            xk_wrong_psk, wrong_psk_message, "XKpsk1 wrong PSK"
        ),
        "xkpsk1_wrong_responder_static_rejected": read_rejected(
            xk_responder, wrong_xk_static_message, "XKpsk1 wrong responder static"
        ),
        "xkpsk1_altered_prologue_rejected": read_rejected(
            xk_altered_prologue,
            altered_xk_prologue_message,
            "XKpsk1 altered prologue",
        ),
        "ik_wrong_responder_static_rejected": read_rejected(
            ik_responder, wrong_ik_static_message, "IK wrong responder static"
        ),
        "ik_altered_prologue_rejected": read_rejected(
            ik_altered_prologue, altered_ik_prologue_message, "IK altered prologue"
        ),
    }


print(
    json.dumps(
        {
            "oracle": "noiseprotocol==0.3.1",
            "xkpsk1": xk(),
            "ik": ik(),
            "negative": negative_cases(),
        },
        indent=2,
    )
)
