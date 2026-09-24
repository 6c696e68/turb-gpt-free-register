# -*- coding: utf-8 -*-
"""Thống kê lưu lượng mạng quy trình đăng ký trình duyệt.

Thống kê byte request/response HTTP quan sát được phía trình duyệt, không đọc hay lưu nội dung request.
Playwright dùng trực tiếp ``Request.sizes()``; Selenium/Roxy ưu tiên đọc Chrome
performance log, không đọc được thì fallback Resource Timing. Cả hai cách đều không gồm
chi phí giao thức thêm như TLS/IP/đường hầm proxy, nên không tương đương lưu lượng tính phí của nhà cung cấp proxy.
"""
from __future__ import annotations

import json
import ipaddress
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from typing import Any

from config import browser as _browser_cfg

logger = logging.getLogger(__name__)


_RESOURCE_TYPE_ALIASES = {
    "img": "image",
    "images": "image",
    "video": "media",
    "audio": "media",
    "videos": "media",
    "fonts": "font",
    "css": "stylesheet",
    "xmlhttprequest": "xhr",
}


def _normalize_resource_type(value: Any) -> str:
    """Thống nhất tên loại tài nguyên của Playwright/CDP/Resource Timing."""
    raw = str(value or "other").strip().lower()
    return _RESOURCE_TYPE_ALIASES.get(raw, raw or "other")


def _non_negative_int(value: Any) -> int:
    """Chuẩn hóa an toàn số do Playwright/CDP trả về thành số nguyên không âm."""
    try:
        value = int(float(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, value)


def _optional_size(value: Any) -> int | None:
    """Đọc trường kích thước có thể dùng -1 để biểu thị unknown."""
    if value is None:
        return None
    try:
        value = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return None
    return value if value >= 0 else None


def _payload_size(payload: Any) -> int:
    if isinstance(payload, (bytes, bytearray, memoryview)):
        return len(payload)
    return len(str(payload or "").encode("utf-8", errors="replace"))


def _value_size(value: Any) -> int:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return len(value)
    return len(str(value or "").encode("utf-8", errors="replace"))


def _size_field(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _safe_url_for_log(url: Any, *, max_length: int = 600) -> str:
    """Giữ host/path/khóa truy vấn, ẩn giá trị truy vấn URL, tránh ghi token nhạy cảm vào nhật ký chi tiết."""
    text = str(url or "")
    if not text:
        return "-"
    # data/blob URL có thể tự mang nội dung tài nguyên đầy đủ, không được ghi nguyên vào log.
    if text.lower().startswith(("data:", "blob:")):
        return text.split(":", 1)[0].lower() + ":<redacted>"
    try:
        parsed = urlsplit(text)
        query_keys = []
        for part in str(parsed.query or "").split("&"):
            if not part:
                continue
            key = part.split("=", 1)[0]
            query_keys.append(f"{key}=<redacted>")
        # userinfo trong URL cũng có thể là proxy/thông tin xác thực tạm thời; chỉ giữ host và port.
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[-1]
        safe = urlunsplit((parsed.scheme, netloc, parsed.path, "&".join(query_keys), ""))
    except Exception:
        safe = text.split("?", 1)[0]
    safe = safe.replace("\r", "").replace("\n", "")
    return safe[:max_length] + ("…" if len(safe) > max_length else "")


def _is_loopback_url(url: Any) -> bool:
    """Tài nguyên HTTP(S)/WS(S) loopback máy cục bộ không thuộc lưu lượng proxy hoặc đăng ký mạng công cộng."""
    try:
        parsed = urlsplit(str(url or ""))
        if parsed.scheme.lower() not in {"http", "https", "ws", "wss"}:
            return False
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if host == "localhost" or host.endswith(".localhost"):
            return True
        return bool(host and ipaddress.ip_address(host).is_loopback)
    except (TypeError, ValueError):
        return False


def _coverage_count(value: Any) -> int:
    """Chuẩn hóa count/offset trong độ phủ Profiler thành số nguyên không âm."""
    try:
        return max(0, int(float(value or 0)))
    except (TypeError, ValueError, OverflowError):
        return 0


def _safe_js_function_name(value: Any, *, max_length: int = 220) -> str:
    """Tên hàm chỉ dùng cho nhật ký chẩn đoán, loại bỏ ký tự điều khiển và giới hạn độ dài."""
    text = str(value or "<anonymous>")
    text = "".join(char if char >= " " and char != "\x7f" else " " for char in text)
    text = " ".join(text.split()) or "<anonymous>"
    return text[:max_length] + ("…" if len(text) > max_length else "")


def _is_blockable_script_url(url: Any) -> bool:
    """Chỉ liệt kê các script HTTP(S) có thể chặn bằng quy tắc URL làm ứng viên chặn."""
    try:
        parsed = urlsplit(str(url or ""))
        return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


class _TrafficAccumulator:
    """Lưu bộ đếm lưu lượng; lưu chi tiết tài nguyên đã ẩn danh khi cần, không lưu Header hoặc thân yêu cầu."""

    def __init__(self, *, label: str, method: str):
        self.label = label
        self.method = method
        self.started_at = _iso_now()
        self.started_perf = time.perf_counter()
        self._lock = threading.RLock()
        self._stopped = False
        self._final_snapshot: dict[str, Any] | None = None

        self.http_upload_bytes = 0
        self.http_download_bytes = 0
        self.websocket_upload_bytes = 0
        self.websocket_download_bytes = 0
        self.request_count = 0
        self.completed_request_count = 0
        self.failed_request_count = 0
        self.unfinished_request_count = 0
        self.unknown_size_request_count = 0
        self.websocket_count = 0
        self._reported = False
        self._data_saver: Any | None = None
        self._local_asset_cache: Any | None = None
        self._detail_log_enabled = bool(getattr(_browser_cfg, "BROWSER_TRAFFIC_DETAIL_LOG", False))
        try:
            configured_max = int(getattr(_browser_cfg, "BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES", 2000) or 2000)
        except (TypeError, ValueError):
            configured_max = 2000
        self._detail_log_max_entries = max(1, min(configured_max, 10000))
        self._request_details: list[dict[str, Any]] = []
        self._request_detail_index: dict[str, int] = {}
        self._request_detail_sequence = 0

        # Chrome Profiler precise coverage. Mặc định tắt; khi bật chỉ giữ tên hàm, số lần gọi,
        # offset và URL đã che, không đọc tham số hàm, giá trị trả về hoặc nội dung mã nguồn.
        self._js_coverage_log_enabled = bool(getattr(_browser_cfg, "BROWSER_JS_COVERAGE_LOG", False))
        try:
            coverage_max = int(getattr(_browser_cfg, "BROWSER_JS_COVERAGE_MAX_ENTRIES", 1000) or 1000)
        except (TypeError, ValueError):
            coverage_max = 1000
        self._js_coverage_max_entries = max(1, min(coverage_max, 10000))
        self._js_coverage_supported: bool | None = None
        self._js_coverage_target_count = 0
        self._js_coverage_started_target_count = 0
        self._js_coverage_collected = False
        self._js_coverage_error = ""
        self._js_coverage_scripts: dict[str, dict[str, Any]] = {}
        self._js_coverage_functions: list[dict[str, Any]] = []

    def attach_data_saver(self, data_saver: Any | None) -> None:
        """Gắn thêm bộ đếm của bộ chặn tiết kiệm lưu lượng vào ảnh chụp lưu lượng trình duyệt."""
        self._data_saver = data_saver

    def attach_local_asset_cache(self, cache: Any | None) -> None:
        """Để bộ thống kê loại nội dung cục bộ Fetch.fulfillRequest ra khỏi lưu lượng tải xuống qua proxy."""
        self._local_asset_cache = cache

    def _js_coverage_mark_target_attempt(self) -> None:
        if not self._js_coverage_log_enabled:
            return
        with self._lock:
            self._js_coverage_target_count += 1

    def _js_coverage_mark_started(self) -> None:
        if not self._js_coverage_log_enabled:
            return
        with self._lock:
            self._js_coverage_started_target_count += 1
            self._js_coverage_supported = True

    def _js_coverage_mark_start_failure(self, exc: Any) -> None:
        if not self._js_coverage_log_enabled:
            return
        message = f"{type(exc).__name__}: {str(exc)[:220]}" if isinstance(exc, Exception) else str(exc)[:220]
        with self._lock:
            if not self._js_coverage_error:
                self._js_coverage_error = message
            if self._js_coverage_started_target_count == 0:
                self._js_coverage_supported = False

    def _js_coverage_mark_take_failure(self, exc: Any) -> None:
        if not self._js_coverage_log_enabled:
            return
        message = f"{type(exc).__name__}: {str(exc)[:220]}" if isinstance(exc, Exception) else str(exc)[:220]
        with self._lock:
            self._js_coverage_error = message
            self._js_coverage_supported = False

    def _ingest_js_coverage(self, payload: Any, *, target: str = "") -> None:
        """Phân tích Profiler.takePreciseCoverage, chỉ giữ tóm tắt dùng cho chẩn đoán."""
        if not self._js_coverage_log_enabled:
            return
        if not isinstance(payload, dict):
            raise ValueError("Profiler không trả về object")
        scripts = payload.get("result")
        if not isinstance(scripts, list):
            raise ValueError("Profiler thiếu list result")

        raw_target = str(target or "-")
        target_text = (
            _safe_url_for_log(raw_target, max_length=180)
            if "://" in raw_target
            else raw_target.replace("\r", " ").replace("\n", " ")[:180]
        )
        for script_index, script in enumerate(scripts):
            if not isinstance(script, dict):
                continue
            script_id = str(script.get("scriptId") or "-").replace("\r", " ").replace("\n", " ")[:120]
            raw_url = str(script.get("url") or "")
            safe_url = _safe_url_for_log(raw_url)
            functions = script.get("functions")
            if not isinstance(functions, list):
                functions = []

            function_count = 0
            executed_function_count = 0
            range_count = 0
            executed_range_count = 0
            executed_functions: list[dict[str, Any]] = []
            for function_index, function in enumerate(functions):
                if not isinstance(function, dict):
                    continue
                function_count += 1
                raw_ranges = function.get("ranges")
                if not isinstance(raw_ranges, list):
                    raw_ranges = []
                normalized_ranges: list[tuple[int, int, int]] = []
                function_executed_ranges = 0
                function_call_count = 0
                for item in raw_ranges:
                    if not isinstance(item, dict):
                        continue
                    start = _coverage_count(item.get("startOffset"))
                    end = _coverage_count(item.get("endOffset"))
                    count = _coverage_count(item.get("count"))
                    normalized_ranges.append((start, end, count))
                    range_count += 1
                    if count > 0:
                        function_executed_ranges += 1
                        executed_range_count += 1
                        function_call_count = max(function_call_count, count)
                if function_executed_ranges <= 0:
                    continue
                executed_function_count += 1
                executed_functions.append(
                    {
                        "target": target_text,
                        "script_id": script_id,
                        "script_url": safe_url,
                        "function_name": _safe_js_function_name(function.get("functionName")),
                        "call_count": function_call_count,
                        "range_count": len(normalized_ranges),
                        "executed_range_count": function_executed_ranges,
                        # Chỉ lưu offset/count, tránh đưa mã nguồn hoặc tham số vào log/snapshot.
                        "ranges": normalized_ranges,
                        "function_index": function_index,
                    }
                )

            script_key = f"{target_text}|{script_id}|{raw_url}|{script_index}"
            summary = {
                "target": target_text,
                "script_id": script_id,
                "url": safe_url,
                "blockable_url": _is_blockable_script_url(raw_url),
                "executed": bool(executed_function_count),
                "function_count": function_count,
                "executed_function_count": executed_function_count,
                "range_count": range_count,
                "executed_range_count": executed_range_count,
            }
            with self._lock:
                self._js_coverage_scripts[script_key] = summary
                self._js_coverage_functions.extend(executed_functions)

    def _js_coverage_snapshot(self) -> dict[str, Any]:
        """Trả về tóm tắt độ phủ JS phù hợp để ghi vào network_traffic."""
        with self._lock:
            scripts = [dict(item) for item in self._js_coverage_scripts.values()]
            functions = list(self._js_coverage_functions)
            enabled = bool(self._js_coverage_log_enabled)
            supported = self._js_coverage_supported
            target_count = int(self._js_coverage_target_count)
            started_target_count = int(self._js_coverage_started_target_count)
            collected = bool(self._js_coverage_collected)
            error = self._js_coverage_error
            max_entries = int(self._js_coverage_max_entries)

        # Liên kết script coverage và chi tiết mạng theo URL đã che, tiện phán đoán trực tiếp “chưa thực thi nhưng tải rất lớn”
        # chunk. Khi chưa bật log chi tiết tài nguyên các field này tự nhiên là 0, không ảnh hưởng bản thân coverage.
        traffic_by_url: dict[str, dict[str, int]] = {}
        with self._lock:
            request_details = list(self._request_details)
        for detail in request_details:
            if detail.get("type") != "script":
                continue
            url = str(detail.get("url") or "")
            if not url:
                continue
            totals = traffic_by_url.setdefault(
                url,
                {"request_count": 0, "upload_bytes": 0, "download_bytes": 0, "failed": 0, "blocked": 0},
            )
            totals["request_count"] += 1
            totals["upload_bytes"] += _non_negative_int(detail.get("upload_bytes"))
            totals["download_bytes"] += _non_negative_int(detail.get("download_bytes"))
            totals["failed"] += int(bool(detail.get("failed")))
            totals["blocked"] += int(bool(detail.get("blocked")))
        for item in scripts:
            traffic = traffic_by_url.get(str(item.get("url") or ""), {})
            item["traffic_request_count"] = int(traffic.get("request_count", 0))
            item["traffic_upload_bytes"] = int(traffic.get("upload_bytes", 0))
            item["traffic_download_bytes"] = int(traffic.get("download_bytes", 0))
            item["traffic_failed"] = int(traffic.get("failed", 0))
            item["traffic_blocked"] = int(traffic.get("blocked", 0))

        scripts.sort(key=lambda item: (not bool(item.get("executed")), str(item.get("url") or "")))
        # Cùng một URL có thể xuất hiện ở nhiều Page/target; chỉ cần bất kỳ target nào đã thực thi thì không thể
        # Do một target khác chưa thực thi mà liệt kê nhầm URL này thành ứng viên.
        url_executed: dict[str, bool] = {}
        for item in scripts:
            url = str(item.get("url") or "")
            if item.get("blockable_url") and url:
                url_executed[url] = bool(url_executed.get(url, False) or item.get("executed"))
        candidate_urls = [url for url, executed in url_executed.items() if not executed]
        # Ảnh chụp nhanh chỉ lưu tóm tắt cấp script; offset từng hàm chỉ ghi nhật ký, tránh extra_json phình to.
        script_summaries = scripts[:max_entries]
        return {
            "enabled": enabled,
            "supported": supported if enabled else None,
            "target_count": target_count,
            "started_target_count": started_target_count,
            "collected": collected,
            "script_count": len(scripts),
            "executed_script_count": sum(1 for item in scripts if item.get("executed")),
            "candidate_script_count": len(candidate_urls),
            "function_count": sum(int(item.get("function_count", 0)) for item in scripts),
            "executed_function_count": len(functions),
            "logged_function_count": min(len(functions), max_entries),
            "max_entries": max_entries,
            "candidate_scripts": candidate_urls[:max_entries],
            "scripts": script_summaries,
            "error": error or None,
        }

    def _log_js_coverage(self) -> None:
        if not self._js_coverage_log_enabled:
            return
        report = self._js_coverage_snapshot()
        logger.info(
            """[%s] [tổng hợp thực thi JS] supported=%s collected=%s target=%s/%s scripts=%s executed_scripts=%s candidate_scripts=%s functions=%s executed_functions=%s logged_functions=%s""",
            self.label,
            report.get("supported"),
            report.get("collected"),
            report.get("started_target_count", 0),
            report.get("target_count", 0),
            report.get("script_count", 0),
            report.get("executed_script_count", 0),
            report.get("candidate_script_count", 0),
            report.get("function_count", 0),
            report.get("executed_function_count", 0),
            report.get("logged_function_count", 0),
        )
        if report.get("error"):
            logger.info("[%s] [độ phủ JS] ghi chú thu thập：%s", self.label, report["error"])

        scripts = list(report.get("scripts") or [])
        for index, item in enumerate(scripts, 1):
            logger.info(
                """[%s] [script JS] #%s executed=%s functions=%s executed_functions=%s ranges=%s executed_ranges=%s download=%sB requests=%s scriptId=%s target=%s url=%s""",
                self.label,
                index,
                int(bool(item.get("executed"))),
                item.get("function_count", 0),
                item.get("executed_function_count", 0),
                item.get("range_count", 0),
                item.get("executed_range_count", 0),
                item.get("traffic_download_bytes", 0),
                item.get("traffic_request_count", 0),
                item.get("script_id", "-"),
                item.get("target", "-"),
                item.get("url", "-"),
            )

        with self._lock:
            functions = list(self._js_coverage_functions)
        functions.sort(
            key=lambda item: (
                -int(item.get("call_count", 0)),
                str(item.get("script_url", "")),
                str(item.get("function_name", "")),
                int(item.get("function_index", 0)),
            )
        )
        for index, item in enumerate(functions[: self._js_coverage_max_entries], 1):
            ranges = list(item.get("ranges") or [])
            range_text = ",".join(f"{start}-{end}:{count}" for start, end, count in ranges[:20])
            if len(ranges) > 20:
                range_text += f",+{len(ranges) - 20} ranges"
            logger.info(
                "[%s] [thực thi JS] #%s url=%s function=%s count=%s ranges=%s target=%s scriptId=%s",
                self.label,
                index,
                item.get("script_url", "-"),
                item.get("function_name", "<anonymous>"),
                item.get("call_count", 0),
                range_text or "-",
                item.get("target", "-"),
                item.get("script_id", "-"),
            )

        script_by_url = {
            str(item.get("url") or ""): item
            for item in scripts
            if str(item.get("url") or "")
        }
        for index, url in enumerate(report.get("candidate_scripts") or [], 1):
            item = script_by_url.get(str(url), {})
            logger.info(
                """[%s] [ứng viên JS] #%s lần này không thấy phạm vi thực thi của script, chỉ để xác minh A/B, không có nghĩa chặn an toàn：download=%sB requests=%s failed=%s blocked=%s url=%s""",
                self.label,
                index,
                item.get("traffic_download_bytes", 0),
                item.get("traffic_request_count", 0),
                item.get("traffic_failed", 0),
                item.get("traffic_blocked", 0),
                url,
            )

    def _add_http(self, upload: int = 0, download: int = 0) -> None:
        with self._lock:
            self.http_upload_bytes += _non_negative_int(upload)
            self.http_download_bytes += _non_negative_int(download)

    def _prepare_request_details(self) -> None:
        """Bổ sung thông tin đặc thù tầng triển khai trước khi xuất chi tiết (ví dụ khung WebSocket)."""

    @staticmethod
    def _cache_status(*, cache_status: Any = None, from_cache: Any = None) -> str:
        raw = str(cache_status or "").strip().lower()
        if raw in {"hit", "miss", "unknown", "service_worker"}:
            return raw
        if from_cache is True:
            return "hit"
        return "unknown"

    def _record_request_detail(
        self,
        *,
        request_id: Any = None,
        resource_type: Any = "other",
        method: Any = "GET",
        url: Any = "",
        status: Any = None,
        upload_bytes: Any = 0,
        download_bytes: Any = 0,
        response_body_bytes: Any = 0,
        response_header_bytes: Any = 0,
        failed: bool = False,
        blocked: bool = False,
        unfinished: bool = False,
        from_cache: Any = None,
        cache_status: Any = None,
        mime_type: Any = "",
        websocket_payload_upload_bytes: Any = 0,
        websocket_payload_download_bytes: Any = 0,
        detail_key: Any = None,
    ) -> None:
        """Ghi chi tiết đã che của từng tài nguyên, để xuất log phân tích khi stop()."""
        if not self._detail_log_enabled:
            return
        try:
            status_value = int(float(status)) if status is not None and str(status) else None
        except (TypeError, ValueError, OverflowError):
            status_value = None
        cache_value = self._cache_status(cache_status=cache_status, from_cache=from_cache)
        with self._lock:
            self._request_detail_sequence += 1
            if detail_key is None:
                detail_key = f"anonymous:{self._request_detail_sequence}"
            else:
                detail_key = str(detail_key)
        detail = {
            "request_id": str(request_id) if request_id is not None else "-",
            "type": _normalize_resource_type(resource_type),
            "method": str(method or "GET").upper(),
            "status": status_value,
            "upload_bytes": _non_negative_int(upload_bytes),
            "download_bytes": _non_negative_int(download_bytes),
            "response_body_bytes": _non_negative_int(response_body_bytes),
            "response_header_bytes": _non_negative_int(response_header_bytes),
            "failed": bool(failed),
            "blocked": bool(blocked),
            "unfinished": bool(unfinished),
            "from_cache": cache_value == "hit",
            "cache_status": cache_value,
            "mime_type": str(mime_type or "").replace("\r", "").replace("\n", "")[:160],
            "websocket_payload_upload_bytes": _non_negative_int(websocket_payload_upload_bytes),
            "websocket_payload_download_bytes": _non_negative_int(websocket_payload_download_bytes),
            "url": _safe_url_for_log(url),
        }
        with self._lock:
            existing_index = self._request_detail_index.get(detail_key)
            if existing_index is None:
                self._request_detail_index[detail_key] = len(self._request_details)
                self._request_details.append(detail)
            else:
                self._request_details[existing_index] = detail

    def _update_request_detail(self, detail_key: Any, **updates: Any) -> None:
        """Cập nhật các trường có thể thay đổi của tài nguyên đã ghi, không đọc hoặc lưu nội dung request/response."""
        if not self._detail_log_enabled:
            return
        key = str(detail_key)
        with self._lock:
            index = self._request_detail_index.get(key)
            if index is None:
                return
            detail = self._request_details[index]
            for name in (
                "upload_bytes",
                "download_bytes",
                "response_body_bytes",
                "response_header_bytes",
                "websocket_payload_upload_bytes",
                "websocket_payload_download_bytes",
            ):
                if name in updates:
                    detail[name] = _non_negative_int(updates[name])
            if "cache_status" in updates:
                detail["cache_status"] = self._cache_status(cache_status=updates["cache_status"])
                detail["from_cache"] = detail["cache_status"] == "hit"
            for name in ("status", "failed", "blocked", "unfinished", "mime_type", "url"):
                if name not in updates:
                    continue
                if name == "status":
                    try:
                        detail[name] = int(float(updates[name])) if updates[name] is not None else None
                    except (TypeError, ValueError, OverflowError):
                        detail[name] = None
                elif name == "mime_type":
                    detail[name] = str(updates[name] or "").replace("\r", "").replace("\n", "")[:160]
                elif name == "url":
                    detail[name] = _safe_url_for_log(updates[name])
                else:
                    detail[name] = bool(updates[name])

    def _log_request_details(self) -> None:
        if not self._detail_log_enabled:
            return
        self._prepare_request_details()
        with self._lock:
            details = list(self._request_details)
        type_totals: dict[str, dict[str, int]] = defaultdict(
            lambda: {"count": 0, "upload_bytes": 0, "download_bytes": 0, "blocked": 0, "failed": 0}
        )
        for item in details:
            totals = type_totals[item["type"]]
            totals["count"] += 1
            totals["upload_bytes"] += int(item["upload_bytes"])
            totals["download_bytes"] += int(item["download_bytes"])
            totals["blocked"] += int(bool(item["blocked"]))
            totals["failed"] += int(bool(item["failed"]))
        logger.info(
            "[%s] tổng hợp chi tiết tài nguyên trình duyệt：bản ghi %s mục，theo loại=%s",
            self.label,
            len(details),
            json.dumps(dict(sorted(type_totals.items())), ensure_ascii=False, separators=(",", ":")),
        )
        ranked = sorted(
            details,
            key=lambda item: (
                int(item["download_bytes"]) + int(item["upload_bytes"]),
                int(item["download_bytes"]),
            ),
            reverse=True,
        )[: self._detail_log_max_entries]
        logger.info(
            "[%s] bắt đầu chi tiết tài nguyên trình duyệt：sắp xếp giảm dần theo tổng byte mỗi request，xuất %s/%s mục（giá trị query URL đã ẩn）",
            self.label,
            len(ranked),
            len(details),
        )
        for index, item in enumerate(ranked, 1):
            logger.info(
                """[%s] [chi tiết tài nguyên] #%s %s %s status=%s upload=%sB download=%sB body=%sB headers=%sB failed=%s blocked=%s unfinished=%s cache=%s mime=%s ws_upload=%sB ws_download=%sB url=%s""",
                self.label,
                index,
                item["type"],
                item["method"],
                item["status"] if item["status"] is not None else "-",
                item["upload_bytes"],
                item["download_bytes"],
                item["response_body_bytes"],
                item["response_header_bytes"],
                int(bool(item["failed"])),
                int(bool(item["blocked"])),
                int(bool(item["unfinished"])),
                item.get("cache_status", "unknown"),
                item.get("mime_type", ""),
                item.get("websocket_payload_upload_bytes", 0),
                item.get("websocket_payload_download_bytes", 0),
                item["url"],
            )
        logger.info("[%s] kết thúc chi tiết tài nguyên trình duyệt", self.label)

    def _build_snapshot(self) -> dict[str, Any]:
        with self._lock:
            total_upload = self.http_upload_bytes + self.websocket_upload_bytes
            total_download = self.http_download_bytes + self.websocket_download_bytes
            total = total_upload + total_download
            note = (
                """phía trình duyệt HTTP byte request/response（kèm lấy đượcheader và body request/response）；cộng thêm WebSocket payload khung；không gồm TLS/IP/proxyoverhead tunnel"""
            )
            if self.method == "selenium.resource_timing_fallback":
                note = (
                    """Chrome Resource Timing thấy đượcbyte truyền phản hồi；header/body upload không thấy，cộng thêmthấy được WebSocket payload khung；không gồm TLS/IP/proxyoverhead tunnel"""
                )
            result = {
                "available": True,
                "method": self.method,
                "label": self.label,
                "started_at": self.started_at,
                "finished_at": _iso_now(),
                "duration_seconds": round(max(0.0, time.perf_counter() - self.started_perf), 3),
                "upload_bytes": int(total_upload),
                "download_bytes": int(total_download),
                "total_bytes": int(total),
                "http_upload_bytes": int(self.http_upload_bytes),
                "http_download_bytes": int(self.http_download_bytes),
                "websocket_upload_bytes": int(self.websocket_upload_bytes),
                "websocket_download_bytes": int(self.websocket_download_bytes),
                "request_count": int(self.request_count),
                "completed_request_count": int(self.completed_request_count),
                "failed_request_count": int(self.failed_request_count),
                "unfinished_request_count": int(self.unfinished_request_count),
                "unknown_size_request_count": int(self.unknown_size_request_count),
                "websocket_count": int(self.websocket_count),
                "detail_log_enabled": bool(self._detail_log_enabled),
                "detail_log_max_entries": int(self._detail_log_max_entries),
                "detail_recorded_count": int(len(self._request_details)),
                "js_coverage": self._js_coverage_snapshot(),
                "note": note,
            }
            if self._data_saver is not None:
                try:
                    result.update(self._data_saver.snapshot())
                except Exception:
                    pass
            return result

    def _finish_snapshot(self) -> dict[str, Any]:
        with self._lock:
            if self._final_snapshot is None:
                self._final_snapshot = self._build_snapshot()
            return dict(self._final_snapshot)

    def _log_snapshot(self, snapshot: dict[str, Any]) -> None:
        if self._reported:
            return
        self._reported = True
        logger.info(
            """[%s] lưu lượng mạng trình duyệt đăng ký：upload %.2f KiB，download %.2f KiB，tổng %.2f KiB，request HTTP %s（thất bại %s，chưa xong %s）""",
            self.label,
            snapshot.get("upload_bytes", 0) / 1024,
            snapshot.get("download_bytes", 0) / 1024,
            snapshot.get("total_bytes", 0) / 1024,
            snapshot.get("request_count", 0),
            snapshot.get("failed_request_count", 0),
            snapshot.get("unfinished_request_count", 0),
        )
        if snapshot.get("data_saver_enabled"):
            logger.info(
                "[%s] tài nguyên thực tế bị chặn ở chế độ tiết lưu lượng：%s（theo loại=%s）",
                self.label,
                snapshot.get("data_saver_blocked_count", 0),
                snapshot.get("data_saver_blocked_by_type", {}) or {},
            )
            blocked_by_url_pattern = snapshot.get("data_saver_blocked_by_url_pattern", {}) or {}
            if blocked_by_url_pattern:
                logger.info(
                    "[%s] rule URL chế độ tiết lưu lượng khớp：%s",
                    self.label,
                    blocked_by_url_pattern,
                )
        self._log_request_details()
        self._log_js_coverage()


class PlaywrightTrafficTracker(_TrafficAccumulator):
    """Thống kê lưu lượng HTTP/WebSocket của tất cả Page trong một BrowserContext."""

    def __init__(self, context: Any, *, label: str = "BrowserUse"):
        super().__init__(label=label, method="playwright.request.sizes")
        self.context = context
        self._requests: dict[int, Any] = {}
        self._accounted_requests: set[int] = set()
        self._websockets: dict[int, Any] = {}
        self._websocket_stats: dict[int, dict[str, Any]] = {}
        self._js_coverage_sessions: dict[int, tuple[Any, Any, str]] = {}
        self._js_coverage_page_attempts: set[int] = set()
        self._listeners: list[tuple[Any, str, Any]] = []
        self._attach()

    def _listen(self, emitter: Any, event: str, callback: Any) -> None:
        try:
            emitter.on(event, callback)
            self._listeners.append((emitter, event, callback))
        except Exception as exc:
            logger.debug("[%s] lắng nghe lưu lượng đăng ký thất bại event=%s：%s", self.label, event, exc)

    def _attach(self) -> None:
        # Lắng nghe BrowserContext, không chỉ page hiện tại, đảm bảo cửa sổ popup/chuyển hướng cũng được tính.
        self._listen(self.context, "request", self._on_request)
        self._listen(self.context, "requestfinished", self._on_request_finished)
        self._listen(self.context, "requestfailed", self._on_request_failed)
        # websocket là sự kiện Page, không phải sự kiện BrowserContext; với trang đã có và popup sau này
        # Đều gắn trình lắng nghe.
        self._listen(self.context, "page", self._on_page)
        for page in list(getattr(self.context, "pages", []) or []):
            self._on_page(page)

    def _on_page(self, page: Any) -> None:
        self._listen(page, "websocket", self._on_websocket)
        self._start_playwright_js_coverage(page)

    def _start_playwright_js_coverage(self, page: Any) -> None:
        """Tạo CDP session độc lập cho mỗi Chromium Page và bật độ phủ chính xác."""
        if not self._js_coverage_log_enabled:
            return
        page_key = id(page)
        with self._lock:
            if page_key in self._js_coverage_page_attempts:
                return
            self._js_coverage_page_attempts.add(page_key)
        self._js_coverage_mark_target_attempt()
        try:
            session = self.context.new_cdp_session(page)
            session.send("Profiler.enable", {})
            session.send(
                "Profiler.startPreciseCoverage",
                {"callCount": True, "detailed": True},
            )
            try:
                page_url = str(getattr(page, "url", "") or "")
            except Exception:
                page_url = ""
            with self._lock:
                self._js_coverage_sessions[page_key] = (page, session, page_url)
            self._js_coverage_mark_started()
        except Exception as exc:
            self._js_coverage_mark_start_failure(exc)
            logger.debug("[%s] khởi động độ phủ JS chính xác của Page thất bại：%s: %s", self.label, type(exc).__name__, str(exc)[:180])

    def _on_request(self, request: Any) -> None:
        if self._stopped:
            return
        key = id(request)
        with self._lock:
            if key not in self._requests:
                self._requests[key] = request
                self.request_count += 1

    @staticmethod
    def _request_fallback_upload(request: Any) -> int:
        """Khi yêu cầu thất bại không có sizes(), cố gắng ước lượng header/body đã gửi."""
        try:
            method = str(getattr(request, "method", "GET") or "GET")
        except Exception:
            method = "GET"
        try:
            url = str(getattr(request, "url", "") or "")
        except Exception:
            url = ""
        header_bytes = len(f"{method} {url} HTTP/1.1\r\n".encode("utf-8"))
        try:
            headers = request.headers or {}
            header_bytes += sum(
                _value_size(name) + _value_size(value) + 4
                for name, value in headers.items()
            ) + 2
        except Exception:
            pass
        try:
            body = request.post_data
        except Exception:
            body = None
        return header_bytes + _payload_size(body) if body else header_bytes

    @staticmethod
    def _request_response(request: Any) -> Any | None:
        try:
            response = getattr(request, "response", None)
            if callable(response):
                response = response()
            return response
        except Exception:
            return None

    @classmethod
    def _request_metadata(cls, request: Any, *, include_response: bool = True) -> dict[str, Any]:
        """Đọc metadata công khai của request Playwright, không đọc response body.

        ``Request.response()`` là API đồng bộ, bên trong sẽ chờ event loop Playwright.
        Gọi nó trong callback ``requestfailed`` sẽ re-enter callback đang dispatch, có thể
        làm request failed đáng lẽ timeout bị nuốt/treo."""
        try:
            resource_type = getattr(request, "resource_type", "other")
        except Exception:
            resource_type = "other"
        try:
            method = getattr(request, "method", "GET")
        except Exception:
            method = "GET"
        try:
            url = getattr(request, "url", "")
        except Exception:
            url = ""
        response = cls._request_response(request) if include_response else None
        status = None
        mime_type = ""
        cache_status = "unknown"
        if response is not None:
            try:
                status = getattr(response, "status", None)
            except Exception:
                pass
            try:
                headers = getattr(response, "headers", {}) or {}
                if isinstance(headers, dict):
                    mime_type = headers.get("content-type") or ""
            except Exception:
                pass
            try:
                # Playwright có thể phơi bày rõ ràng là phản hồi Service Worker; HTTP thông thường
                # Cache hit không có Request API ổn định, không được báo nhầm unknown thành miss.
                if bool(getattr(response, "from_service_worker", False)):
                    cache_status = "service_worker"
            except Exception:
                pass
        return {
            "resource_type": _normalize_resource_type(resource_type),
            "method": str(method or "GET").upper(),
            "url": str(url or ""),
            "status": status,
            "mime_type": mime_type,
            "cache_status": cache_status,
        }

    @staticmethod
    def _request_size_values(request: Any) -> dict[str, int | None] | None:
        try:
            sizes = request.sizes()
        except Exception:
            return None
        return {
            name: _optional_size(_size_field(sizes, name))
            for name in (
                "requestBodySize",
                "requestHeadersSize",
                "responseBodySize",
                "responseHeadersSize",
            )
        }

    def _record_playwright_detail(
        self,
        request: Any,
        *,
        request_id: Any,
        upload_bytes: Any = 0,
        download_bytes: Any = 0,
        response_body_bytes: Any = 0,
        response_header_bytes: Any = 0,
        failed: bool = False,
        blocked: bool = False,
        unfinished: bool = False,
        include_response: bool = True,
    ) -> None:
        # Khi tắt nhật ký chi tiết không chạm phương thức đồng bộ của Request; đặc biệt không để logic chẩn đoán ảnh hưởng
        # Luồng chính của requestfailed/page.goto.
        if not self._detail_log_enabled:
            return
        metadata = self._request_metadata(request, include_response=include_response)
        self._record_request_detail(
            request_id=request_id,
            resource_type=metadata["resource_type"],
            method=metadata["method"],
            url=metadata["url"],
            status=metadata["status"],
            upload_bytes=upload_bytes,
            download_bytes=download_bytes,
            response_body_bytes=response_body_bytes,
            response_header_bytes=response_header_bytes,
            failed=failed,
            blocked=blocked,
            unfinished=unfinished,
            cache_status=metadata["cache_status"],
            mime_type=metadata["mime_type"],
            detail_key=f"playwright:{request_id}",
        )

    def _mark_request(self, request: Any, *, failed: bool) -> None:
        key = id(request)
        with self._lock:
            if key in self._accounted_requests:
                return
            self._accounted_requests.add(key)
            if key not in self._requests:
                self.request_count += 1
            self._requests[key] = request

        # Request của route.abort() không thực sự được gửi; không được ước lượng nó thành khi sizes() không dùng được
        # Header yêu cầu đã tải lên, nếu không lưu lượng tiết kiệm sẽ bị khẩu thống kê cộng lại.
        try:
            blocked = bool(self._data_saver and self._data_saver.was_playwright_blocked(request))
        except Exception:
            blocked = False
        if blocked:
            self._record_playwright_detail(
                request,
                request_id=key,
                blocked=True,
                include_response=False,
            )
            return

        # Tài liệu Playwright nêu rõ: Request.sizes() trên failed request sẽ ném lỗi, và
        # Bên trong nó gọi response() trước. Quan trọng hơn là ở đây đang trong callback sự kiện requestfailed,
        # Mọi lời gọi đồng bộ chờ Playwright đều có thể kích hoạt reentrancy API và phá page.goto().
        if failed:
            upload = self._request_fallback_upload(request)
            self._add_http(upload, 0)
            with self._lock:
                self.unknown_size_request_count += 1
                self.failed_request_count += 1
            self._record_playwright_detail(
                request,
                request_id=key,
                upload_bytes=upload,
                failed=True,
                include_response=False,
            )
            return

        values = self._request_size_values(request)
        if values is None:
            # Rất ít sự kiện hoàn thành cũng có thể không lấy được sizes(); lúc đó chỉ ước lượng upload, và không đọc nữa
            # response, tránh lan truyền ngoại lệ thống kê sang phân phối sự kiện Playwright.
            upload = self._request_fallback_upload(request)
            self._add_http(upload, 0)
            with self._lock:
                self.unknown_size_request_count += 1
                self.completed_request_count += 1
            self._record_playwright_detail(
                request,
                request_id=key,
                upload_bytes=upload,
                include_response=False,
            )
            return

        unknown = any(value is None for value in values.values())
        upload = (values["requestBodySize"] or 0) + (values["requestHeadersSize"] or 0)
        download = (values["responseBodySize"] or 0) + (values["responseHeadersSize"] or 0)
        self._add_http(upload, download)
        with self._lock:
            if unknown:
                self.unknown_size_request_count += 1
            if failed:
                self.failed_request_count += 1
            else:
                self.completed_request_count += 1
        self._record_playwright_detail(
            request,
            request_id=key,
            upload_bytes=upload,
            download_bytes=download,
            response_body_bytes=values["responseBodySize"] or 0,
            response_header_bytes=values["responseHeadersSize"] or 0,
            include_response=True,
        )

    def _on_request_finished(self, request: Any) -> None:
        self._mark_request(request, failed=False)

    def _on_request_failed(self, request: Any) -> None:
        self._mark_request(request, failed=True)

    def _on_websocket(self, websocket: Any) -> None:
        if self._stopped:
            return
        key = id(websocket)
        with self._lock:
            if key in self._websockets:
                return
            self._websockets[key] = websocket
            try:
                websocket_url = str(getattr(websocket, "url", "") or "")
            except Exception:
                websocket_url = ""
            self._websocket_stats[key] = {
                "url": websocket_url,
                "upload": 0,
                "download": 0,
            }
            self.websocket_count += 1
        self._listen(websocket, "framesent", lambda payload, key=key: self._on_websocket_sent(key, payload))
        self._listen(websocket, "framereceived", lambda payload, key=key: self._on_websocket_received(key, payload))

    def _on_websocket_sent(self, key: int, payload: Any) -> None:
        size = _payload_size(payload)
        with self._lock:
            self.websocket_upload_bytes += size
            if key in self._websocket_stats:
                self._websocket_stats[key]["upload"] += size

    def _on_websocket_received(self, key: int, payload: Any) -> None:
        size = _payload_size(payload)
        with self._lock:
            self.websocket_download_bytes += size
            if key in self._websocket_stats:
                self._websocket_stats[key]["download"] += size

    def _prepare_request_details(self) -> None:
        if not self._detail_log_enabled:
            return
        with self._lock:
            stats = {key: dict(value) for key, value in self._websocket_stats.items()}
        for key, item in stats.items():
            self._record_request_detail(
                request_id=f"ws-{key}",
                resource_type="websocket",
                method="GET",
                url=item.get("url", ""),
                upload_bytes=item.get("upload", 0),
                download_bytes=item.get("download", 0),
                websocket_payload_upload_bytes=item.get("upload", 0),
                websocket_payload_download_bytes=item.get("download", 0),
                cache_status="unknown",
                detail_key=f"playwright-websocket:{key}",
            )

    def _record_unfinished_playwright_requests(self) -> int:
        unfinished = 0
        for key, request in list(self._requests.items()):
            with self._lock:
                accounted = key in self._accounted_requests
            if accounted:
                continue
            try:
                blocked = bool(self._data_saver and self._data_saver.was_playwright_blocked(request))
            except Exception:
                blocked = False
            if blocked:
                with self._lock:
                    self._accounted_requests.add(key)
                self._record_playwright_detail(
                    request,
                    request_id=key,
                    blocked=True,
                    include_response=False,
                )
                continue

            values = self._request_size_values(request) or {}
            if values:
                upload = (values.get("requestBodySize") or 0) + (values.get("requestHeadersSize") or 0)
                download = (values.get("responseBodySize") or 0) + (values.get("responseHeadersSize") or 0)
                include_response = True
            else:
                upload = self._request_fallback_upload(request)
                download = 0
                include_response = False
            self._record_playwright_detail(
                request,
                request_id=key,
                upload_bytes=upload,
                download_bytes=download,
                response_body_bytes=values.get("responseBodySize") or 0,
                response_header_bytes=values.get("responseHeadersSize") or 0,
                unfinished=True,
                include_response=include_response,
            )
            unfinished += 1
        return unfinished

    def _collect_playwright_js_coverage(self) -> None:
        """Kết thúc session Profiler của từng Page và tổng hợp độ phủ."""
        if not self._js_coverage_log_enabled:
            return
        with self._lock:
            if self._js_coverage_collected:
                return
            self._js_coverage_collected = True
            sessions = list(self._js_coverage_sessions.values())
        with self._lock:
            no_started_target = self._js_coverage_started_target_count == 0
        if not sessions and no_started_target:
            self._js_coverage_mark_start_failure("Không có Chromium Page/CDP target khả dụng")
        for page, session, page_url in sessions:
            try:
                payload = session.send("Profiler.takePreciseCoverage", {})
                try:
                    final_page_url = str(getattr(page, "url", "") or "")
                except Exception:
                    final_page_url = ""
                self._ingest_js_coverage(payload, target=final_page_url or page_url or "page")
            except Exception as exc:
                self._js_coverage_mark_take_failure(exc)
                logger.debug("[%s] đọc độ phủ JS chính xác của Page thất bại：%s: %s", self.label, type(exc).__name__, str(exc)[:180])
            finally:
                for command in ("Profiler.stopPreciseCoverage", "Profiler.disable"):
                    try:
                        session.send(command, {})
                    except Exception:
                        pass
                try:
                    session.detach()
                except Exception:
                    pass
        with self._lock:
            self._js_coverage_sessions.clear()

    def _remove_listeners(self) -> None:
        for emitter, event, callback in self._listeners:
            try:
                emitter.remove_listener(event, callback)
            except Exception:
                pass
        self._listeners.clear()

    def stop(self) -> dict[str, Any]:
        if self._stopped:
            snapshot = self._finish_snapshot()
            self._log_snapshot(snapshot)
            return snapshot
        # Sự kiện đồng bộ Playwright sẽ hoàn thành trước khi gọi ở đây; request vẫn chưa xong đánh dấu riêng,
        # Không giả mạo byte phản hồi, tránh báo nhầm "giá trị ước tính" thành giá trị chính xác.
        with self._lock:
            self._stopped = True
        self.unfinished_request_count = self._record_unfinished_playwright_requests()
        self._remove_listeners()
        self._prepare_request_details()
        self._collect_playwright_js_coverage()
        snapshot = self._finish_snapshot()
        self._log_snapshot(snapshot)
        return snapshot


class SeleniumTrafficTracker(_TrafficAccumulator):
    """Thống kê lưu lượng Chrome performance log của Roxy/Selenium.

    Selenium không có API đăng ký sự kiện mạng thống nhất, ChromeDriver đưa sự kiện CDP Network
    vào performance log; lớp này lấy hàng loạt và parse tại checkpoint/stop.
    """

    def __init__(self, driver: Any, *, label: str = "Roxy"):
        super().__init__(label=label, method="selenium.chrome.performance_log")
        self.driver = driver
        self._log_supported: bool | None = None
        self._network_event_count = 0
        self._requests: dict[str, dict[str, Any]] = {}
        self._excluded_loopback_request_ids: set[str] = set()
        self._fallback_seen: set[tuple[Any, ...]] = set()
        self._request_generations: dict[str, int] = {}
        self._websocket_stats: dict[str, dict[str, Any]] = {}
        self._js_coverage_started = False
        try:
            # Với debuggerAddress đã kết nối trình duyệt fingerprint cũng cố bật domain Network hết mức;
            # Việc có đọc được performance log hay không vẫn do ChromeDriver tương ứng quyết định.
            self.driver.execute_cdp_cmd("Network.enable", {})
        except Exception as exc:
            logger.debug("[%s] Network.enable thất bại, sẽ thử đọc performance log sẵn có：%s", label, exc)
        self._start_selenium_js_coverage()

    def _start_selenium_js_coverage(self) -> None:
        """Bật Chrome Profiler coverage chính xác trên Selenium/CDP target hiện tại."""
        if not self._js_coverage_log_enabled:
            return
        self._js_coverage_mark_target_attempt()
        try:
            self.driver.execute_cdp_cmd("Profiler.enable", {})
            self.driver.execute_cdp_cmd(
                "Profiler.startPreciseCoverage",
                {"callCount": True, "detailed": True},
            )
            self._js_coverage_started = True
            self._js_coverage_mark_started()
            logger.info("[%s] đã bật ghi độ phủ JS chính xác（Profiler.startPreciseCoverage）", self.label)
        except Exception as exc:
            self._js_coverage_mark_start_failure(exc)
            logger.debug("[%s] khởi động độ phủ JS chính xác thất bại：%s: %s", self.label, type(exc).__name__, str(exc)[:180])

    def _collect_selenium_js_coverage(self) -> None:
        """Đọc và dừng độ phủ Profiler của Selenium target hiện tại."""
        if not self._js_coverage_log_enabled or not self._js_coverage_started:
            return
        with self._lock:
            if self._js_coverage_collected:
                return
            self._js_coverage_collected = True
        try:
            payload = self.driver.execute_cdp_cmd("Profiler.takePreciseCoverage", {})
            self._ingest_js_coverage(payload, target="selenium.current_target")
        except Exception as exc:
            self._js_coverage_mark_take_failure(exc)
            logger.debug("[%s] đọc độ phủ JS chính xác thất bại：%s: %s", self.label, type(exc).__name__, str(exc)[:180])
        finally:
            for command in ("Profiler.stopPreciseCoverage", "Profiler.disable"):
                try:
                    self.driver.execute_cdp_cmd(command, {})
                except Exception:
                    pass

    @staticmethod
    def _header_size(headers: Any, *, start_line: str = "", headers_text: Any = None) -> int:
        if headers_text:
            return _value_size(headers_text)
        size = _value_size(start_line) if start_line else 0
        if isinstance(headers, dict):
            size += sum(_value_size(k) + _value_size(v) + 4 for k, v in headers.items())
        return size + 2

    @classmethod
    def _request_upload_size(cls, request: dict[str, Any]) -> int:
        if not isinstance(request, dict):
            request = {}
        method = str(request.get("method") or "GET")
        url = str(request.get("url") or "")
        try:
            parsed = urlsplit(url)
            target = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        except Exception:
            target = url
        headers = request.get("headers") or {}
        header_size = cls._header_size(
            headers,
            start_line=f"{method} {target} HTTP/1.1\r\n",
            headers_text=request.get("headersText"),
        )
        body = request.get("postData")
        if body is None and request.get("postDataEntries"):
            body = "".join(str(item.get("bytes") or "") for item in request["postDataEntries"] if isinstance(item, dict))
        return header_size + _payload_size(body) if body else header_size

    @classmethod
    def _response_header_size(cls, response: dict[str, Any] | None) -> int:
        if not response:
            return 0
        status = response.get("status")
        status_text = str(response.get("statusText") or "")
        start_line = f"HTTP/1.1 {status or 0} {status_text}\r\n"
        return cls._header_size(
            response.get("headers") or {},
            start_line=start_line,
            headers_text=response.get("headersText"),
        )

    @staticmethod
    def _record_cache_status(record: dict[str, Any]) -> str:
        response = record.get("response") or {}
        if response.get("fromServiceWorker"):
            return "service_worker"
        if record.get("served_from_cache"):
            return "hit"
        if response:
            return "miss"
        return "unknown"

    @staticmethod
    def _record_url(record: dict[str, Any]) -> str:
        request = record.get("request") or {}
        return str(request.get("url") or "") if isinstance(request, dict) else ""

    def _record_cdp_detail(
        self,
        record: dict[str, Any],
        *,
        body_size: Any = 0,
        failed: bool = False,
        blocked: bool = False,
        unfinished: bool = False,
    ) -> None:
        if not self._detail_log_enabled:
            return
        request = record.get("request") or {}
        response = record.get("response") or {}
        cache_status = self._record_cache_status(record)
        cached = cache_status == "hit"
        if cached or blocked:
            upload = download = body = header = 0
        else:
            upload = _non_negative_int(record.get("upload_size"))
            body = max(_non_negative_int(body_size), _non_negative_int(record.get("received_body_bytes")))
            header = self._response_header_size(response)
            download = body + header
        ws = self._websocket_stats.get(str(record.get("request_id") or ""), {})
        ws_upload = _non_negative_int(ws.get("upload"))
        ws_download = _non_negative_int(ws.get("download"))
        self._record_request_detail(
            request_id=record.get("request_id"),
            resource_type=record.get("resource_type") or "other",
            method=request.get("method") if isinstance(request, dict) else "GET",
            url=self._record_url(record),
            status=response.get("status") if isinstance(response, dict) else None,
            upload_bytes=upload + ws_upload,
            download_bytes=download + ws_download,
            response_body_bytes=body,
            response_header_bytes=header,
            failed=failed,
            blocked=blocked,
            unfinished=unfinished,
            cache_status=cache_status,
            mime_type=response.get("mimeType") if isinstance(response, dict) else "",
            websocket_payload_upload_bytes=ws_upload,
            websocket_payload_download_bytes=ws_download,
            detail_key=record.get("detail_key"),
        )

    def _finish_cdp_request(self, record: dict[str, Any], *, body_size: Any = 0, failed: bool = False) -> None:
        if record.get("finished"):
            return
        record["finished"] = True
        record["failed"] = bool(failed)
        cache_status = self._record_cache_status(record)
        if cache_status != "hit":
            if not record.get("upload_added"):
                self._add_http(record.get("upload_size", 0), 0)
                record["upload_added"] = True
            body_size = max(_non_negative_int(body_size), _non_negative_int(record.get("received_body_bytes")))
            record["body_size"] = body_size
            download = self._response_header_size(record.get("response")) + body_size
            self._add_http(0, download)
        else:
            body_size = 0
            record["body_size"] = 0
        with self._lock:
            if failed:
                self.failed_request_count += 1
            else:
                self.completed_request_count += 1
        self._record_cdp_detail(record, body_size=body_size, failed=failed)

    def _handle_cdp_event(self, method: str, params: dict[str, Any]) -> None:
        self._network_event_count += 1

        event_request_id = str(params.get("requestId") or "")
        if method == "Network.webSocketCreated" and _is_loopback_url(params.get("url")):
            if event_request_id:
                self._excluded_loopback_request_ids.add(event_request_id)
            return
        if (
            method != "Network.requestWillBeSent"
            and event_request_id
            and event_request_id in self._excluded_loopback_request_ids
        ):
            return

        def is_local_asset(request_id: str) -> bool:
            cache = self._local_asset_cache
            if cache is None:
                return False
            try:
                return bool(cache.was_fulfilled_network_request(request_id))
            except Exception:
                return False

        if method == "Network.requestWillBeSent":
            request_id = str(params.get("requestId") or "")
            if not request_id:
                return
            previous = self._requests.get(request_id)
            redirect = params.get("redirectResponse")
            if previous is not None and not previous.get("finished"):
                # Redirect cùng một requestId sẽ kích hoạt lại requestWillBeSent.
                redirect_body = (redirect or {}).get("encodedDataLength", 0) if isinstance(redirect, dict) else 0
                if isinstance(redirect, dict):
                    previous["response"] = redirect
                self._finish_cdp_request(previous, body_size=redirect_body)
            request = params.get("request") or {}
            resource_type = _normalize_resource_type(params.get("type") or "")
            request_url = str(request.get("url") or "") if isinstance(request, dict) else ""
            if _is_loopback_url(request_url):
                self._excluded_loopback_request_ids.add(request_id)
                self._requests.pop(request_id, None)
                return
            self._excluded_loopback_request_ids.discard(request_id)
            if resource_type == "other" and request_url.lower().startswith(("ws:", "wss:")):
                resource_type = "websocket"
            generation = self._request_generations.get(request_id, 0) + 1
            self._request_generations[request_id] = generation
            record = {
                "request_id": request_id,
                "request": request,
                "resource_type": resource_type,
                "response": None,
                "finished": False,
                "served_from_cache": False,
                "upload_size": self._request_upload_size(request),
                "upload_added": False,
                "received_body_bytes": 0,
                "body_size": 0,
                "detail_key": f"selenium:{request_id}:{generation}",
            }
            self._requests[request_id] = record
            with self._lock:
                self.request_count += 1
            return

        if method == "Network.responseReceived":
            request_id = str(params.get("requestId") or "")
            record = self._requests.get(request_id)
            if record is not None:
                response = params.get("response") or {}
                record["response"] = response
                if response.get("fromDiskCache") or response.get("fromMemoryCache"):
                    record["served_from_cache"] = True
                if is_local_asset(request_id):
                    record["served_from_cache"] = True
                    record["served_from_local_asset_cache"] = True
            return

        if method == "Network.webSocketHandshakeResponseReceived":
            request_id = str(params.get("requestId") or "")
            record = self._requests.get(request_id)
            if record is not None:
                record["response"] = params.get("response") or {}
                self._finish_cdp_request(record)
            return

        if method == "Network.requestServedFromCache":
            request_id = str(params.get("requestId") or "")
            record = self._requests.get(request_id)
            if record is not None:
                record["served_from_cache"] = True
            return

        if method == "Network.loadingFinished":
            request_id = str(params.get("requestId") or "")
            record = self._requests.get(request_id)
            if record is not None:
                if is_local_asset(request_id):
                    record["served_from_cache"] = True
                    record["served_from_local_asset_cache"] = True
                self._finish_cdp_request(record, body_size=params.get("encodedDataLength", 0))
            return

        if method == "Network.dataReceived":
            request_id = str(params.get("requestId") or "")
            record = self._requests.get(request_id)
            if record is not None and is_local_asset(request_id):
                record["served_from_cache"] = True
                record["served_from_local_asset_cache"] = True
            if record is not None and not record.get("served_from_cache"):
                record["received_body_bytes"] = (
                    _non_negative_int(record.get("received_body_bytes"))
                    + _non_negative_int(params.get("encodedDataLength", 0))
                )
            return

        if method == "Network.loadingFailed":
            request_id = str(params.get("requestId") or "")
            record = self._requests.get(request_id)
            blocked_by_data_saver = False
            if self._data_saver is not None:
                try:
                    request = dict(record.get("request") or {}) if record is not None else {}
                    if record is not None and record.get("resource_type"):
                        request["resourceType"] = record.get("resource_type")
                    blocked_by_data_saver = bool(self._data_saver.observe_cdp_event(method, params, request))
                except Exception:
                    pass
            if record is not None:
                if blocked_by_data_saver:
                    record["finished"] = True
                    record["blocked_by_data_saver"] = True
                    self._record_cdp_detail(record, blocked=True)
                else:
                    self._finish_cdp_request(record, failed=True)
            return

        if method == "Network.webSocketCreated":
            request_id = str(params.get("requestId") or "")
            record = self._requests.get(request_id)
            with self._lock:
                self._websocket_stats.setdefault(
                    request_id,
                    {"url": self._record_url(record) if record is not None else "", "upload": 0, "download": 0},
                )
                if record is not None:
                    record["resource_type"] = "websocket"
                self.websocket_count += 1
            return

        if method == "Network.webSocketFrameSent":
            request_id = str(params.get("requestId") or "")
            frame = params.get("response") or {}
            size = _payload_size(frame.get("payloadData"))
            with self._lock:
                stats = self._websocket_stats.setdefault(
                    request_id, {"url": "", "upload": 0, "download": 0}
                )
                stats["upload"] += size
                self.websocket_upload_bytes += size
            record = self._requests.get(request_id)
            if record is not None:
                self._update_request_detail(
                    record.get("detail_key"),
                    upload_bytes=_non_negative_int(record.get("upload_size")) + _non_negative_int(stats.get("upload")),
                    websocket_payload_upload_bytes=stats.get("upload"),
                )
            return

        if method == "Network.webSocketFrameReceived":
            request_id = str(params.get("requestId") or "")
            frame = params.get("response") or {}
            size = _payload_size(frame.get("payloadData"))
            with self._lock:
                stats = self._websocket_stats.setdefault(
                    request_id, {"url": "", "upload": 0, "download": 0}
                )
                stats["download"] += size
                self.websocket_download_bytes += size
            record = self._requests.get(request_id)
            if record is not None:
                self._update_request_detail(
                    record.get("detail_key"),
                    download_bytes=self._response_header_size(record.get("response"))
                    + _non_negative_int(record.get("body_size"))
                    + _non_negative_int(stats.get("download")),
                    websocket_payload_download_bytes=stats.get("download"),
                )

    def _prepare_request_details(self) -> None:
        if not self._detail_log_enabled:
            return
        with self._lock:
            websocket_stats = {key: dict(value) for key, value in self._websocket_stats.items()}
            records = {key: dict(value) for key, value in self._requests.items()}
        for request_id, stats in websocket_stats.items():
            record = records.get(request_id)
            if record is None:
                self._record_request_detail(
                    request_id=request_id or "-",
                    resource_type="websocket",
                    method="GET",
                    url=stats.get("url", ""),
                    upload_bytes=stats.get("upload", 0),
                    download_bytes=stats.get("download", 0),
                    websocket_payload_upload_bytes=stats.get("upload", 0),
                    websocket_payload_download_bytes=stats.get("download", 0),
                    cache_status="unknown",
                    detail_key=f"selenium-websocket:{request_id}",
                )
                continue

            # Bắt tay WebSocket bản thân đã được tính theo yêu cầu HTTP, payload khung được gộp vào đây
            # Cùng một dòng, tránh khi phân tích bỏ sót lưu lượng kênh thời gian thực của trang đăng ký.
            response = record.get("response") or {}
            cache_status = self._record_cache_status(record)
            cached = cache_status == "hit"
            handshake_upload = 0 if cached else _non_negative_int(record.get("upload_size"))
            handshake_body = 0 if cached else _non_negative_int(record.get("body_size"))
            handshake_headers = 0 if cached else self._response_header_size(response)
            request = record.get("request") or {}
            method = request.get("method", "GET") if isinstance(request, dict) else "GET"
            self._record_request_detail(
                request_id=request_id,
                resource_type="websocket",
                method=method,
                url=self._record_url(record),
                status=response.get("status"),
                upload_bytes=handshake_upload + _non_negative_int(stats.get("upload")),
                download_bytes=handshake_body + handshake_headers + _non_negative_int(stats.get("download")),
                response_body_bytes=handshake_body,
                response_header_bytes=handshake_headers,
                failed=bool(record.get("failed")),
                blocked=bool(record.get("blocked_by_data_saver")),
                unfinished=not bool(record.get("finished")),
                cache_status=cache_status,
                mime_type=response.get("mimeType", ""),
                websocket_payload_upload_bytes=stats.get("upload", 0),
                websocket_payload_download_bytes=stats.get("download", 0),
                detail_key=record.get("detail_key"),
            )

    def drain(self) -> int:
        """Đọc bộ đệm performance log hiện tại, trả về số bản ghi đã phân tích."""
        try:
            entries = self.driver.get_log("performance")
            self._log_supported = True
        except Exception as exc:
            if self._log_supported is not False:
                logger.debug("[%s] không đọc được performance log：%s", self.label, exc)
            self._log_supported = False
            return 0

        parsed = 0
        for entry in entries or []:
            try:
                raw = entry.get("message") if isinstance(entry, dict) else entry
                outer = json.loads(raw) if isinstance(raw, str) else raw
                message = outer.get("message") if isinstance(outer, dict) else None
                if not isinstance(message, dict):
                    continue
                method = str(message.get("method") or "")
                if not method.startswith("Network."):
                    continue
                self._handle_cdp_event(method, message.get("params") or {})
                parsed += 1
            except Exception:
                continue
        return parsed

    def _collect_resource_timing_fallback(self) -> None:
        """Khi performance log không khả dụng, thống kê số byte truyền phản hồi đã lộ của tài liệu hiện tại."""
        if self._network_event_count:
            return
        script = """
        return (() => ({
          href: location.href,
          timeOrigin: performance.timeOrigin || 0,
          resources: performance.getEntriesByType('resource').map(e => ({
            name: e.name,
            initiatorType: e.initiatorType || '',
            startTime: e.startTime,
            duration: e.duration,
            transferSize: e.transferSize || 0,
            encodedBodySize: e.encodedBodySize || 0
          })),
          navigation: performance.getEntriesByType('navigation').map(e => ({
            name: e.name,
            initiatorType: 'document',
            startTime: e.startTime,
            duration: e.duration,
            transferSize: e.transferSize || 0,
            encodedBodySize: e.encodedBodySize || 0
          }))
        }))();
        """
        try:
            data = self.driver.execute_script(script)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        document = str(data.get("href") or "")
        time_origin = _non_negative_int(data.get("timeOrigin"))
        self.method = "selenium.resource_timing_fallback"
        entries = list(data.get("resources") or []) + list(data.get("navigation") or [])
        for item in entries:
            if not isinstance(item, dict):
                continue
            if _is_loopback_url(item.get("name")):
                continue
            key = (
                document,
                time_origin,
                str(item.get("name") or ""),
                _non_negative_int(item.get("startTime")),
                _non_negative_int(item.get("duration")),
                _non_negative_int(item.get("transferSize")),
                _non_negative_int(item.get("encodedBodySize")),
            )
            if key in self._fallback_seen:
                continue
            self._fallback_seen.add(key)
            raw_transfer = _non_negative_int(item.get("transferSize"))
            encoded_body = _non_negative_int(item.get("encodedBodySize"))
            transfer = raw_transfer or encoded_body
            if transfer:
                self._add_http(0, transfer)
            with self._lock:
                self.request_count += 1
                self.completed_request_count += 1
            self._record_request_detail(
                request_id=f"timing-{len(self._fallback_seen)}",
                resource_type=_normalize_resource_type(item.get("initiatorType") or "other"),
                method="GET",
                url=item.get("name") or "",
                upload_bytes=0,
                download_bytes=transfer,
                response_body_bytes=encoded_body,
                response_header_bytes=max(0, transfer - encoded_body),
                cache_status="miss" if raw_transfer else "unknown",
                detail_key=f"timing:{key}",
            )

    def checkpoint(self) -> None:
        if not self._stopped:
            self.drain()
            self._collect_resource_timing_fallback()

    def stop(self) -> dict[str, Any]:
        if not self._stopped:
            self.drain()
            self._collect_resource_timing_fallback()
            self._collect_selenium_js_coverage()
            with self._lock:
                self._stopped = True
                unfinished_records = [record for record in self._requests.values() if not record.get("finished")]
                # Trước khi dừng, tính phần phản hồi đã thấy từ CDP dataReceived; phần còn lại chưa biết không bịa.
                for record in unfinished_records:
                    partial_body = 0
                    if not record.get("served_from_cache") and not record.get("partial_accounted"):
                        if not record.get("upload_added"):
                            self.http_upload_bytes += _non_negative_int(record.get("upload_size"))
                            record["upload_added"] = True
                        partial_body = _non_negative_int(record.get("received_body_bytes"))
                        self.http_download_bytes += self._response_header_size(record.get("response")) + partial_body
                        record["body_size"] = partial_body
                        record["partial_accounted"] = True
                        self.unknown_size_request_count += 1
                    elif not record.get("served_from_cache"):
                        partial_body = _non_negative_int(record.get("body_size"))
                    record["stopped_unfinished"] = True
                    self._record_cdp_detail(record, body_size=partial_body, unfinished=True)
                unfinished = len(unfinished_records)
                self.unfinished_request_count = unfinished
            self._prepare_request_details()
        snapshot = self._finish_snapshot()
        self._log_snapshot(snapshot)
        return snapshot
