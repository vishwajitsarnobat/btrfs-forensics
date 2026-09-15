"""LZO1X decoder (substrate/lzo.py): known vectors, hostile streams, bounds.

The four decoder vectors below are copied from dissect.util 3.24
`tests/compression/test_lzo.py` (Copyright Fox-IT / NCC Group, Apache License 2.0,
https://github.com/fox-it/dissect.util). Only the hex streams, output bounds and SHA-256 digests
are reused; the "header" vector's 5-byte python-lzo header (0xf0 + big-endian length) is stripped
because btrfs streams carry no such header.
"""

import hashlib
import random

import pytest

from btrfska.substrate.lzo import LzoError, decompress
from tests.helpers import lzo_literal_stream

# (stream hex, output bound, sha256 of the output) from dissect.util 3.24, Apache-2.0.
DISSECT_UTIL_VECTORS = {
    "basic": (
        "0361626361626320f314000f616263616263616263616263616263616263110000",
        300,
        "d9f5aeb06abebb3be3f38adec9a2e3b94228d52193be923eb4e24c9b56ee0930",
    ),
    "large": (
        "160900a40100400003a83e8e6302003800007104ff4000fc012add00032016dd"
        "00042016dd00052016dd00062016dd00072016dd00082016dd00092016dd000a"
        "2016dd000b2016dd000c2016dd000d2016dd000e2016dd000f2016dd00102016"
        "dd00112016dd00122016dd00132016dd00142016dd00152016dd00162016dd00"
        "172016dd00182016dd00192016dd001a2016dd001b2016dd001c2016dd001d20"
        "16dd001e2016dd001f2016dd00202016dd00212016dd00222016dd00232016dd"
        "00242016dd00252016dd00262016dd00272016dd00282016dd00292016dd002a"
        "2016dd002b2016dd002c2016dd002d2016dd002e2016dd002f2016dd00302016"
        "dd00312016dd00322016dd00332016dd00342016dd00352016dd00362016dd00"
        "372016dd00382016dd00392016dd003a2016dd003b2016dd003c2016dd003d20"
        "16dd003e2016dd003f2016dd00402016dd00412016dd00422016dd00432016dd"
        "00442016dd00452016dd00462016dd00472016dd00482016dd00492016dd004a"
        "2016dd004b2016dd004c2016dd004d2016dd004e2016dd004f2016dd00502016"
        "dd00512016dd00522016dd00532016dd00542016dd00552016dd00562016dd00"
        "572016dd00582016dd00592016dd005a2016dd005b2016dd005c2016dd005d20"
        "16dd005e2016dd005f2016dd00602016dd00612016dd00622016dd00632016dd"
        "00642016dd0065200adf000800ed27dc006001228d57e32501556c29dc00fd0b"
        "f55d04662b5c00307d010031dd004f5d06675c0027ce06c03f3b5e02e4022059"
        "0e00880228dd02115d16682002bc03ff020a00ff8902c75d0669dc0322dc5507"
        "736d616c6c2d66696c652a9500d455046ad404229455016469722f6f045f3639"
        "2a9a00eb4209096bd80422b0526804082d776974682d78617474722a1e077543"
        "080a7c3622cd5d91cd126d9500e0943a110000",
        8192,
        "a4d6951085717a9698cd814899d11c931db1d4c0f7ddc3b1cba0f582142d4cf4",
    ),
    "header": ("f0000000041574657374110000"[10:], 4, hashlib.sha256(b"test").hexdigest()),
}
# The "larger" dissect.util vector (8192-byte bound) is in tests/fixtures/lzo_larger.hex.
CRAFTED_LOOKBEHIND = bytes.fromhex("15414243444 0ff110000".replace(" ", ""))


def larger_vector():
    from tests.helpers import REPO_ROOT

    lines = (REPO_ROOT / "tests" / "fixtures" / "lzo_larger.hex").read_text().splitlines()
    return (
        "".join(line for line in lines if not line.startswith("#")),
        8192,
        "efcff6f6fddf392a7d63966d2441accb27a62d61fe9aa57c5cb521d75e871f0c",
    )


def all_vectors():
    return {**DISSECT_UTIL_VECTORS, "larger": larger_vector()}


@pytest.mark.parametrize("name", ["basic", "large", "larger", "header"])
def test_dissect_util_vectors(name):
    stream, bound, digest = all_vectors()[name]
    out = decompress(bytes.fromhex(stream), bound)
    assert hashlib.sha256(out).hexdigest() == digest
    assert len(out) <= bound


def test_basic_vector_is_exactly_its_bound():
    stream, bound, _ = DISSECT_UTIL_VECTORS["basic"]
    assert len(decompress(bytes.fromhex(stream), bound)) == 300


def test_crafted_lookbehind_stream_raises():
    """4 literals, then a 3-byte match 2 041 bytes back: before the start of the output."""
    with pytest.raises(LzoError) as exc:
        decompress(CRAFTED_LOOKBEHIND, 4096)
    assert exc.value.kind == "lookbehind_overrun"


@pytest.mark.parametrize("cut", range(1, len(CRAFTED_LOOKBEHIND)))
def test_truncated_crafted_stream_raises(cut):
    with pytest.raises(LzoError):
        decompress(CRAFTED_LOOKBEHIND[:cut], 4096)


def test_truncated_stream_mid_instruction_is_an_input_overrun():
    with pytest.raises(LzoError) as exc:
        decompress(CRAFTED_LOOKBEHIND[:6], 4096)  # the match opcode 0x40 without its distance byte
    assert exc.value.kind == "input_overrun"


def test_stream_without_end_marker_is_reported():
    stream = bytes.fromhex(DISSECT_UTIL_VECTORS["basic"][0])[:-3]
    with pytest.raises(LzoError) as exc:
        decompress(stream, 300)
    assert exc.value.kind == "missing_end_marker"


def test_output_bound_is_enforced():
    stream, bound, _ = DISSECT_UTIL_VECTORS["basic"]
    with pytest.raises(LzoError) as exc:
        decompress(bytes.fromhex(stream), bound - 1)
    assert exc.value.kind == "output_overrun"


def test_bytes_after_the_end_marker_are_reported():
    with pytest.raises(LzoError) as exc:
        decompress(bytes.fromhex(DISSECT_UTIL_VECTORS["basic"][0]) + b"\0", 300)
    assert exc.value.kind == "trailing_input"


def test_empty_input_raises():
    with pytest.raises(LzoError) as exc:
        decompress(b"", 4096)
    assert exc.value.kind == "input_overrun"


def test_end_marker_alone_is_an_empty_stream():
    assert decompress(b"\x11\x00\x00", 0) == b""


def test_version_byte_streams_are_refused():
    """First byte 17 with at least 5 bytes announces a bitstream version (lzo.rst): LZO-RLE."""
    with pytest.raises(LzoError) as exc:
        decompress(b"\x11\x01\x15abcd\x11\x00\x00", 4096)
    assert exc.value.kind == "unsupported_version"


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 237, 238, 239, 255, 256, 4096, 70000])
def test_literal_streams_round_trip(size):
    data = random.Random(size).randbytes(size)
    assert decompress(lzo_literal_stream(data), size) == data


@pytest.mark.parametrize(
    ("stream", "expected"),
    [
        # 0x16 = 5 literals; 0x40 0x00: copy 3 from distance 1 (overlapping run); end marker.
        ("16414243444540 00 110000", b"ABCDE" + b"EEE"),
        # 0x16 = 5 literals; 0x81 0x00: copy 5 from distance 1, then 1 trailing literal "Z".
        ("1641424344458100 5a 110000", b"ABCDE" + b"EEEEE" + b"Z"),
        # 0x16 = 5 literals; 0x20 0x03: copy 2 + 31 + 3 = 36 bytes from distance 5 (LE16 0x0010).
        ("164142434445 20 03 1000 110000", b"ABCDE" * 8 + b"A"),
    ],
)
def test_hand_assembled_instructions(stream, expected):
    assert decompress(bytes.fromhex(stream.replace(" ", "")), len(expected)) == expected


def test_three_byte_match_after_four_literals_uses_the_2kb_offset():
    """After >= 4 literals, 0000DDSS HHHHHHHH copies 3 bytes from (H << 2) + D + 2049."""
    data = random.Random(7).randbytes(2049)
    stream = lzo_literal_stream(data)[:-3] + bytes([0x00, 0x00]) + b"\x11\x00\x00"
    assert decompress(stream, 2052) == data + data[:3]


def test_two_byte_match_after_one_to_three_literals():
    """With state 1..3, 0000DDSS HHHHHHHH copies 2 bytes from (H << 2) + D + 1."""
    # 0x12: 1 literal "A", state 1; 0x00 0x00: copy 2 from distance 1 -> "AAA".
    assert decompress(bytes.fromhex("1241 0000 110000".replace(" ", "")), 3) == b"AAA"


def test_long_distance_match_within_48kb():
    """0001HLLL LE16: distance 16384 + (H << 14) + (LE16 >> 2); lengths use 3-bit runs."""
    data = random.Random(8).randbytes(16390)
    # 0x11 (H 0, L 1: length 3) is the end marker only at distance 16384; D = 6 gives 16390.
    stream = lzo_literal_stream(data)[:-3] + bytes([0x11]) + (6 << 2).to_bytes(2, "little")
    stream += b"\x11\x00\x00"
    assert decompress(stream, 16393) == data + data[:3]


def _bounded(stream: bytes, bound: int) -> None:
    try:
        out = decompress(stream, bound)
    except LzoError:
        return
    assert len(out) <= bound


def test_random_streams_raise_only_lzo_error_and_respect_the_bound():
    rng = random.Random(20260915)
    for _ in range(3000):
        _bounded(rng.randbytes(rng.randrange(0, 200)), rng.choice([0, 1, 16, 4096]))


@pytest.mark.parametrize("name", ["basic", "large", "larger"])
def test_bit_flipped_vectors_raise_only_lzo_error_and_respect_the_bound(name):
    stream, bound, _ = all_vectors()[name]
    stream = bytes.fromhex(stream)
    rng = random.Random(name)
    for _ in range(600):
        flipped = bytearray(stream)
        bit = rng.randrange(len(flipped) * 8)
        flipped[bit // 8] ^= 1 << (bit % 8)
        _bounded(bytes(flipped), bound)


def test_lzo_error_is_an_ordinary_exception_with_a_kind():
    error = LzoError("input_overrun", "detail")
    assert isinstance(error, Exception)
    assert (error.kind, error.detail) == ("input_overrun", "detail")
