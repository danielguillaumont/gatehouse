"""stdio transport: our stdin/stdout <-> the upstream server's stdin/stdout.

Only plumbing lives here; every decision is made by ``Router``.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from typing import BinaryIO, cast

import anyio
import anyio.abc
import psutil

from gatehouse.events.schema import Direction, EventAction, EventType, Severity
from gatehouse.proxy.framing import LineReader, Oversized
from gatehouse.proxy.router import Router, Send

SHUTDOWN_GRACE_S = 5.0
READ_CHUNK = 64 * 1024


def resolve_command(argv: Sequence[str]) -> list[str]:
    """Resolve the executable via PATH (and PATHEXT on Windows: `npx` -> `npx.cmd`)."""
    if not argv:
        raise ValueError("no upstream server command given")
    exe = shutil.which(argv[0]) or argv[0]
    return [exe, *argv[1:]]


def _binary_stdio() -> None:
    if sys.platform == "win32":
        import msvcrt

        for fd in (0, 1):
            msvcrt.setmode(fd, os.O_BINARY)  # no CRLF translation on protocol streams


def kill_tree(pid: int) -> None:
    """Terminate a process and all of its descendants (npx/uv spawn grandchildren)."""
    try:
        parent = psutil.Process(pid)
    except psutil.Error:
        return
    procs = [*parent.children(recursive=True), parent]
    for p in procs:
        try:
            p.terminate()
        except psutil.Error:
            pass
    _, alive = psutil.wait_procs(procs, timeout=2)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    for p in alive:
        try:
            p.kill()
        except psutil.Error:
            pass


class _ClientOut:
    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._lock = anyio.Lock()

    def _write(self, data: bytes) -> None:
        self._stream.write(data)
        self._stream.flush()

    async def send(self, data: bytes) -> None:
        async with self._lock:
            await anyio.to_thread.run_sync(self._write, data)


class _ServerIn:
    def __init__(self, stream: anyio.abc.ByteSendStream) -> None:
        self._stream = stream
        self._lock = anyio.Lock()
        self.closed = False

    async def send(self, data: bytes) -> None:
        if self.closed:
            return
        async with self._lock:
            try:
                await self._stream.send(data)
            except (anyio.BrokenResourceError, anyio.ClosedResourceError, OSError):
                self.closed = True  # upstream is gone; the server loop reports it

    async def close(self) -> None:
        self.closed = True
        try:
            await self._stream.aclose()
        except (anyio.BrokenResourceError, OSError):
            pass


async def run_stdio(
    command: Sequence[str],
    make_router: Callable[[Send, Send], Router],
    *,
    max_frame_bytes: int,
) -> int:
    """Spawn the upstream and pump both directions until either side ends."""
    _binary_stdio()
    stdin = cast(io.BufferedReader, sys.stdin.buffer)
    stdout: BinaryIO = sys.stdout.buffer
    # Anything that accidentally writes to sys.stdout now lands on stderr instead of
    # corrupting the protocol stream.
    sys.stdout = sys.stderr

    argv = resolve_command(command)
    process = await anyio.open_process(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None
    )
    assert process.stdin is not None and process.stdout is not None
    client_out = _ClientOut(stdout)
    server_in = _ServerIn(process.stdin)
    router = make_router(client_out.send, server_in.send)
    upstream_stdout = process.stdout
    returncode: int | None = None

    async def read_stdin() -> bytes:
        return await anyio.to_thread.run_sync(stdin.read1, READ_CHUNK, abandon_on_cancel=True)

    async def read_upstream() -> bytes:
        try:
            return await upstream_stdout.receive(READ_CHUNK)
        except (anyio.EndOfStream, anyio.ClosedResourceError, anyio.BrokenResourceError):
            return b""

    def oversized(direction: Direction, size: int) -> None:
        router.emit.emit(
            EventType.PROTOCOL_OVERSIZED_FRAME,
            severity=Severity.MEDIUM,
            action=EventAction.BLOCKED,
            direction=direction,
            reason=f"frame of {size} bytes exceeds limit of {max_frame_bytes}",
            details={"Bytes": size, "Limit": max_frame_bytes},
        )

    async with anyio.create_task_group() as tg:

        async def client_loop() -> None:
            reader = LineReader(read_stdin, max_frame_bytes)
            while (line := await reader.next()) is not None:
                if isinstance(line, Oversized):
                    oversized(Direction.CLIENT_TO_SERVER, line.size)
                    continue
                await router.handle_client_line(line)
            # client went away: let the server exit on stdin EOF, then make sure it does
            await server_in.close()
            with anyio.move_on_after(SHUTDOWN_GRACE_S):
                await process.wait()
            if process.returncode is None:
                kill_tree(process.pid)

        async def server_loop() -> None:
            nonlocal returncode
            reader = LineReader(read_upstream, max_frame_bytes)
            while (line := await reader.next()) is not None:
                if isinstance(line, Oversized):
                    oversized(Direction.SERVER_TO_CLIENT, line.size)
                    continue
                await router.handle_server_line(line)
            with anyio.move_on_after(SHUTDOWN_GRACE_S):
                await process.wait()
            if process.returncode is None:
                kill_tree(process.pid)
            returncode = process.returncode
            await router.upstream_exited(returncode)
            tg.cancel_scope.cancel()

        tg.start_soon(client_loop)
        tg.start_soon(server_loop)

    if process.returncode is None:
        kill_tree(process.pid)
    return returncode if returncode is not None else (process.returncode or 0)
