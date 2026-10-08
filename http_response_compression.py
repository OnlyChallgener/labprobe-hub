"""Compress large read-only JSON responses without changing their contents."""
import gzip

from flask import request


def install_json_compression(app):
    if app.extensions.get("labprobe_json_compression"):
        return
    app.extensions["labprobe_json_compression"] = True

    @app.after_request
    def compress_json(response):
        path = request.path
        eligible = path in {"/api/sync/snapshot", "/api/events", "/api/router/dashboard"} or (
            path.startswith("/api/router/child-guard/devices/") and path.endswith("/usage-report")
        )
        if (not eligible or request.method != "GET" or response.status_code != 200
                or response.is_streamed or response.direct_passthrough
                or response.mimetype != "application/json"
                or "Content-Encoding" in response.headers or "ETag" in response.headers
                or "Range" in request.headers or "no-transform" in response.cache_control):
            return response
        response.vary.add("Accept-Encoding")
        if request.accept_encodings["gzip"] <= 0:
            return response
        raw = response.get_data()
        if len(raw) < 2048:
            return response
        compressed = gzip.compress(raw, compresslevel=4, mtime=0)
        if len(compressed) >= len(raw) * 0.9:
            return response
        response.set_data(compressed)
        response.headers["Content-Encoding"] = "gzip"
        return response
