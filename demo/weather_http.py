"""The demo weather server over Streamable HTTP: ``python demo/weather_http.py PORT``.

Used by the ``gatehouse serve`` integration tests and as an HTTP demo upstream.
"""

from __future__ import annotations

import sys

import uvicorn
from weather_server import app

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    uvicorn.run(app.streamable_http_app(), host="127.0.0.1", port=port, log_level="warning")
