from __future__ import annotations

import pytest

from gatehouse.proxy.framing import (
    BatchFrame,
    FrameError,
    FrameKind,
    LineReader,
    Oversized,
    encode,
    parse_frame,
)


def test_request() -> None:
    f = parse_frame(b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n')
    assert f.kind is FrameKind.REQUEST
    assert f.method == "tools/list"
    assert f.id == 1
    assert f.raw.endswith(b"}")


def test_notification() -> None:
    f = parse_frame(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
    assert f.kind is FrameKind.NOTIFICATION
    assert f.id is None


def test_response() -> None:
    f = parse_frame(b'{"jsonrpc":"2.0","id":"a","result":{}}')
    assert f.kind is FrameKind.RESPONSE


def test_error_response_with_null_id() -> None:
    f = parse_frame(b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}')
    assert f.kind is FrameKind.RESPONSE


def test_id_keys_distinguish_int_and_string() -> None:
    a = parse_frame(b'{"jsonrpc":"2.0","id":1,"result":{}}')
    b = parse_frame(b'{"jsonrpc":"2.0","id":"1","result":{}}')
    assert a.id_key != b.id_key


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        (b"not json", "invalid_json"),
        (b'{"jsonrpc":"2.0","id":1,"method":"a","method":"tools/call"}', "duplicate_key"),
        (b'{"jsonrpc":"2.0","id":1,"result":{"x":NaN}}', "invalid_json"),
        (b'{"jsonrpc":"2.0","id":1,"result":{"x":Infinity}}', "invalid_json"),
        (b'"just a string"', "invalid_shape"),
        (b'{"id":1,"method":"x"}', "invalid_shape"),
        (b'{"jsonrpc":"1.0","id":1,"method":"x"}', "invalid_shape"),
        (b'{"jsonrpc":"2.0","id":1,"method":""}', "invalid_shape"),
        (b'{"jsonrpc":"2.0","id":true,"method":"x"}', "invalid_shape"),
        (b'{"jsonrpc":"2.0","id":1.5,"method":"x"}', "invalid_shape"),
        (b'{"jsonrpc":"2.0","id":{"a":1},"method":"x"}', "invalid_shape"),
        (b'{"jsonrpc":"2.0","id":1,"method":"x","params":"s"}', "invalid_shape"),
        (b'{"jsonrpc":"2.0","id":1}', "invalid_shape"),
        (b'{"jsonrpc":"2.0","id":1,"result":{},"error":{}}', "invalid_shape"),
        (b'{"jsonrpc":"2.0","id":1,"result":[]}', "invalid_shape"),
        (b'{"jsonrpc":"2.0","id":1,"method":"x","result":{}}', "invalid_shape"),
        (b'\xff\xfe{"jsonrpc":"2.0"}', "invalid_utf8"),
        (b"[" * 100_000, "invalid_json"),
    ],
)
def test_invalid_frames(line: bytes, kind: str) -> None:
    with pytest.raises(FrameError) as info:
        parse_frame(line)
    assert info.value.kind == kind


def test_invalid_frame_keeps_usable_id() -> None:
    with pytest.raises(FrameError) as info:
        parse_frame(b'{"jsonrpc":"1.0","id":7,"method":"x"}')
    assert info.value.request_id == 7


def test_batch_is_reported() -> None:
    with pytest.raises(BatchFrame) as info:
        parse_frame(b'[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]')
    assert info.value.size == 1


def test_encode_is_one_line() -> None:
    data = encode({"text": "a\nb\r\nc"})
    assert data.count(b"\n") == 1 and data.endswith(b"\n")


def _receiver(chunks: list[bytes]):  # type: ignore[no-untyped-def]
    it = iter(chunks)

    async def receive() -> bytes:
        return next(it, b"")

    return receive


@pytest.mark.anyio
async def test_line_reader_splits_and_reassembles() -> None:
    reader = LineReader(_receiver([b'{"a":1}\n{"b"', b":2}\n\n", b'{"c":3}']), 1024)
    assert await reader.next() == b'{"a":1}'
    assert await reader.next() == b'{"b":2}'
    assert await reader.next() == b'{"c":3}'  # final line without newline at EOF
    assert await reader.next() is None


@pytest.mark.anyio
async def test_line_reader_discards_oversized_lines_without_buffering_them() -> None:
    big = [b"x" * 600, b"x" * 600, b"x" * 600 + b"\nok\n"]
    reader = LineReader(_receiver(big), 1000)
    first = await reader.next()
    assert isinstance(first, Oversized) and first.size == 1800
    assert await reader.next() == b"ok"


@pytest.mark.anyio
async def test_line_reader_oversized_line_in_one_chunk() -> None:
    reader = LineReader(_receiver([b"y" * 50 + b"\nsmall\n"]), 10)
    assert isinstance(await reader.next(), Oversized)
    assert await reader.next() == b"small"
