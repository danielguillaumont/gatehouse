"""A local fake of the Azure Queue Storage REST API, for tests and CI (never for real use).

    python -m attacks.fake_queue PORT SIG

Implements, for any queue name, on 127.0.0.1:

- ``POST /<queue>/messages`` with ``<QueueMessage><MessageText>…</MessageText></QueueMessage>``
  (Put Message, 201);
- ``GET /<queue>/messages?numofmessages=N&visibilitytimeout=S`` (Get Messages: the
  ``<QueueMessagesList>`` XML, each message hidden for S seconds, a new pop receipt and
  an incremented dequeue count);
- ``DELETE /<queue>/messages/<id>?popreceipt=R`` (204, or 404 for a stale receipt).

Every request must carry ``sig=SIG`` in its query string (403 otherwise), standing in
for a SAS token. ``FakeQueue`` is the same logic without a socket.
"""

from __future__ import annotations

import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from xml.sax.saxutils import escape


@dataclass
class _Msg:
    id: str
    text: str
    visible_at: float = 0.0
    pop: str = ""
    dequeues: int = 0


@dataclass
class FakeQueue:
    messages: dict[str, list[_Msg]] = field(default_factory=dict[str, list[_Msg]])
    lock: threading.Lock = field(default_factory=threading.Lock)

    def put(self, queue: str, text: str) -> str:
        with self.lock:
            msg = _Msg(str(uuid.uuid4()), text)
            self.messages.setdefault(queue, []).append(msg)
            return msg.id

    def get(self, queue: str, n: int, visibility: int) -> str:
        now = time.time()
        out: list[str] = []
        with self.lock:
            for msg in self.messages.get(queue, []):
                if len(out) >= n or msg.visible_at > now:
                    continue
                msg.visible_at = now + visibility
                msg.pop = uuid.uuid4().hex
                msg.dequeues += 1
                out.append(
                    "<QueueMessage>"
                    f"<MessageId>{msg.id}</MessageId>"
                    f"<PopReceipt>{msg.pop}</PopReceipt>"
                    f"<DequeueCount>{msg.dequeues}</DequeueCount>"
                    f"<MessageText>{escape(msg.text)}</MessageText>"
                    "</QueueMessage>"
                )
        return (
            '<?xml version="1.0" encoding="utf-8"?><QueueMessagesList>'
            + "".join(out)
            + ("</QueueMessagesList>")
        )

    def delete(self, queue: str, mid: str, pop: str) -> bool:
        with self.lock:
            msgs = self.messages.get(queue, [])
            for i, msg in enumerate(msgs):
                if msg.id == mid and msg.pop == pop:
                    del msgs[i]
                    return True
        return False

    def depth(self, queue: str) -> int:
        with self.lock:
            return len(self.messages.get(queue, []))


def serve(port: int, sig: str, store: FakeQueue | None = None) -> ThreadingHTTPServer:
    fake = store or FakeQueue()

    class Handler(BaseHTTPRequestHandler):
        def _route(self) -> tuple[list[str], dict[str, list[str]]] | None:
            parts = urlsplit(self.path)
            query = parse_qs(parts.query)
            if query.get("sig") != [sig]:
                self._send(403, b"")
                return None
            return [p for p in parts.path.split("/") if p], query

        def _send(self, status: int, body: bytes, ctype: str = "application/xml") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            route = self._route()
            if route is None:
                return
            segs, q = route
            if len(segs) != 2 or segs[1] != "messages":
                self._send(404, b"")
                return
            n = int((q.get("numofmessages") or ["1"])[0])
            vis = int((q.get("visibilitytimeout") or ["30"])[0])
            self._send(200, fake.get(segs[0], n, vis).encode())

        def do_POST(self) -> None:
            route = self._route()
            if route is None:
                return
            segs, _ = route
            n = min(int(self.headers.get("Content-Length") or 0), 64 * 1024)
            body = self.rfile.read(n)
            if len(segs) != 2 or segs[1] != "messages":
                self._send(404, b"")
                return
            text = ET.fromstring(body).findtext("MessageText") or ""  # noqa: S314 (test fake)
            fake.put(segs[0], text)
            self._send(201, b"")

        def do_DELETE(self) -> None:
            route = self._route()
            if route is None:
                return
            segs, q = route
            ok = len(segs) == 3 and fake.delete(segs[0], segs[2], (q.get("popreceipt") or [""])[0])
            self._send(204 if ok else 404, b"")

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.fake = fake  # type: ignore[attr-defined]
    return server


if __name__ == "__main__":
    serve(int(sys.argv[1]), sys.argv[2]).serve_forever()
