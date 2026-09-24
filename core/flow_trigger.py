# -*- coding: utf-8 -*-
"\nđăng ký thành công sau \"tự động kích hoạt flow\"module. \n\nchính quy trình ở main.py / registration_service.py lấy được access_token sau gọi: \n  trigger_flow(access_token)\nkhông bàn kích hoạt thành công thất bại, đăng ký chính quy trình đều xem là thành công. \n"
import json
import logging

# Đây là HTTP API nội bộ (156.225.31.95), không có chặn Cloudflare,
# Không cần mô phỏng dấu vân tay TLS của curl_cffi, dùng trực tiếp thư viện requests tiêu chuẩn.
import requests

# Đọc config theo thuộc tính module, hỗ trợ hot-reload WebUI (config.reload_all()).
from config import flow_trigger as _cfg
from config.browser import USER_AGENT, ACCEPT_LANGUAGE  # Fingerprint trình duyệt cố định, không cần hot-reload

logger = logging.getLogger(__name__)


def _flow_result(
    *,
    status: str,
    ok: bool = False,
    http_status: int | None = None,
    flow_id: str | None = None,
    message: str = "",
) -> dict:
    return {
        "status": status,
        "ok": ok,
        "http_status": http_status,
        "flow_id": flow_id,
        "message": message,
    }


def _build_headers() -> dict:
    return {
        "Accept": "*/*",
        "Accept-Language": ACCEPT_LANGUAGE,
        "Authorization": f"Bearer {_cfg.FLOW_TRIGGER_BEARER}",
        "Cache-Control": "no-cache",
        "Content-Type": "application/json",
        "Origin": "http://162.211.183.196:8888",
        "Pragma": "no-cache",
        "Referer": "http://162.211.183.196:8888/",
        "User-Agent": USER_AGENT,
        "Cookie": _cfg.FLOW_TRIGGER_COOKIE,
    }


def _send_sync(access_token: str) -> dict:
    "thực tế đồng bộ thực thi HTTP POST, và trả về có thể thống kê kết quả. "
    if not access_token:
        return _flow_result(status="skipped", message="access_token trống")

    body = dict(_cfg.FLOW_TRIGGER_PAYLOAD)
    body["access_token"] = access_token

    try:
        resp = requests.post(
            _cfg.FLOW_TRIGGER_URL,
            headers=_build_headers(),
            json=body,
            timeout=_cfg.FLOW_TRIGGER_TIMEOUT,
            verify=False,
        )
    except Exception as exc:
        return _flow_result(status="failed", message=f"{type(exc).__name__}: {exc}")

    # Phân tích đơn giản flow_id ghi log, kết quả kích hoạt không ảnh hưởng luồng chính
    flow_id = ""
    response_preview = (resp.text or "")[:200]
    try:
        data = resp.json()
        flow_id = (data.get("flow") or {}).get("flow_id", "")
    except Exception:
        pass

    if resp.status_code == 200:
        return _flow_result(
            status="success",
            ok=True,
            http_status=resp.status_code,
            flow_id=flow_id or None,
            message=response_preview,
        )

    return _flow_result(
        status="failed",
        http_status=resp.status_code,
        flow_id=flow_id or None,
        message=response_preview,
    )


def trigger_flow(access_token: str) -> dict:
    "\n  kích hoạt 156.225 flow API và trả về kết quả. \n\n  Args:\n  access_token: lần này đăng ký lấy được  ChatGPT access_token\n  "
    if not _cfg.ENABLE_FLOW_TRIGGER:
        return _flow_result(status="skipped", message="ENABLE_FLOW_TRIGGER=False")

    if not access_token:
        return _flow_result(status="skipped", message="access_token trống")

    return _send_sync(access_token)
