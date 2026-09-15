"""A bounds-checked LZO1X decoder for btrfs segments.

Written from the kernel's bitstream description, Documentation/staging/lzo.rst (tag v7.0), and
dissect.util 3.24's Apache-2.0 decoder; not derived from GPL decoder sources. Every failure raises
`LzoError` with a `kind` named after the kernel's LZO_E_* result it corresponds to
(include/linux/lzo.h):
- input_overrun: an instruction or its operands run past the input (LZO_E_INPUT_OVERRUN);
- output_overrun: the output would exceed `max_out` (LZO_E_OUTPUT_OVERRUN);
- lookbehind_overrun: a match reaches before the start of the output (LZO_E_LOOKBEHIND_OVERRUN);
- missing_end_marker: the input ends between instructions (LZO_E_EOF_NOT_FOUND);
- trailing_input: bytes follow the end marker (LZO_E_INPUT_NOT_CONSUMED);
- unsupported_version: a versioned (LZO-RLE, version 1) stream, which btrfs never writes.

Decoding succeeds without any integrity check: LZO carries none, so a successful decode is never
evidence that the bytes are the ones originally written (plan.md §3.5).

Instruction set (lzo.rst "Byte sequences"); `state` is the number of literals the previous
instruction copied (0, 1..3, or 4 for four or more):
- first byte 18..255: copy byte - 17 literals. lzo.rst prints "0..3" and "4..238" for the two
  ranges, but byte - 17 is 1..4 and 5..238; state is that count, capped at 4;
- 0000LLLL, state 0: 3 + length literals (4-bit run), state 4;
- 0000DDSS H, state 1..3: copy 2 bytes from (H << 2) + D + 1;
- 0000DDSS H, state 4: copy 3 bytes from (H << 2) + D + 2049;
- 0001HLLL LE16: copy 2 + length (3-bit run) from 16384 + (H << 14) + (LE16 >> 2); a distance of
  exactly 16384 is the end marker;
- 001LLLLL LE16: copy 2 + length (5-bit run) from (LE16 >> 2) + 1;
- 01LDDDSS H: copy 3 + L from (H << 3) + D + 1;
- 1LLDDDSS H: copy 5 + L from (H << 3) + D + 1.
Every match is followed by S (0..3) literals, which become the new state. A run of b bits holds
its value when non-zero; otherwise it is 2**b - 1 + 255 per zero byte + the next non-zero byte.
"""


class LzoError(Exception):
    """The stream is not a valid LZO1X stream within the given bounds."""

    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind
        self.detail = detail


_END_DISTANCE = 16384


def decompress(src: bytes, max_out: int) -> bytes:
    """Decode one LZO1X stream that must end with the end marker and produce at most `max_out`
    bytes. Raises only LzoError."""
    src = bytes(src)
    n = len(src)
    out = bytearray()
    ip = 0

    def need(count: int) -> None:
        if ip + count > n:
            raise LzoError("input_overrun", f"{count} bytes needed at input offset {ip} of {n}")

    def run(value: int, bits_max: int) -> int:
        nonlocal ip
        if value:
            return value
        length = bits_max
        while True:
            need(1)
            byte = src[ip]
            ip += 1
            if byte:
                return length + byte
            length += 255

    def reserve(count: int) -> None:
        if len(out) + count > max_out:
            raise LzoError(
                "output_overrun", f"{len(out)} + {count} bytes exceed the bound of {max_out}"
            )

    def literals(count: int) -> None:
        nonlocal ip
        need(count)
        reserve(count)
        out.extend(src[ip : ip + count])
        ip += count

    def match(distance: int, length: int) -> None:
        if distance > len(out):
            raise LzoError(
                "lookbehind_overrun",
                f"distance {distance} at output offset {len(out)} (input offset {ip})",
            )
        reserve(length)
        start = len(out) - distance
        if distance >= length:
            out.extend(out[start : start + length])
        else:  # overlapping copy: the output repeats with period `distance`
            out.extend((out[start:] * (length // distance + 1))[:length])

    need(1)
    state = 0
    if src[0] == 17 and n >= 5:
        raise LzoError("unsupported_version", f"bitstream version byte {src[1]}")
    if src[0] > 17:
        ip = 1
        count = src[0] - 17
        literals(count)
        state = min(count, 4)

    while True:
        if ip >= n:
            raise LzoError("missing_end_marker", f"input ends at offset {n} without an end marker")
        op = src[ip]
        ip += 1
        if op < 16:
            if state == 0:
                literals(run(op & 15, 15) + 3)
                state = 4
                continue
            need(1)
            high = src[ip]
            ip += 1
            if state < 4:
                distance, length = (high << 2) + (op >> 2 & 3) + 1, 2
            else:
                distance, length = (high << 2) + (op >> 2 & 3) + 2049, 3
            trailing = op & 3
        elif op < 32:
            length = run(op & 7, 7) + 2
            need(2)
            le16 = src[ip] | src[ip + 1] << 8
            ip += 2
            distance = _END_DISTANCE + ((op & 8) << 11) + (le16 >> 2)
            if distance == _END_DISTANCE:
                if ip != n:
                    raise LzoError("trailing_input", f"{n - ip} bytes after the end marker")
                return bytes(out)
            trailing = le16 & 3
        elif op < 64:
            length = run(op & 31, 31) + 2
            need(2)
            le16 = src[ip] | src[ip + 1] << 8
            ip += 2
            distance, trailing = (le16 >> 2) + 1, le16 & 3
        else:
            need(1)
            high = src[ip]
            ip += 1
            length = 3 + (op >> 5 & 1) if op < 128 else 5 + (op >> 5 & 3)
            distance, trailing = (high << 3) + (op >> 2 & 7) + 1, op & 3
        match(distance, length)
        literals(trailing)
        state = trailing
