# -*- coding: utf-8 -*-
"""Client email Remail Open API.

Open API của Remail khác các dịch vụ "sinh email ngẫu nhiên" đã có trong dự án:

1. Dùng API Key đặt một đơn ``code`` hoặc ``purchase`` theo dự án;
2. Đơn trả email giao hàng và service token chỉ thuộc đơn đó;
3. Lấy mã dùng ``/v1/pickup``, không gửi API Key, chỉ gửi email và service token.

Vì vậy service token phải lưu cùng email trong ngữ cảnh process hiện tại, không thể
chỉ dựa vào địa chỉ email để ghép lại yêu cầu lấy thư.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit, urlunsplit

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

DEFAULT_API_BASE = "https://remail.aishop6.com"
REQUEST_TIMEOUT = 20
_CODE_RE = re.compile(r"\b(\d{6})\b")
_FINAL_ORDER_STATUSES = {"failed", "refunded", "closed"}


class RemailError(RuntimeError):
    """Lỗi yêu cầu Remail API, đặt đơn hoặc lấy mã."""


# 兼容调用方可能使用的命名。
RemailClientError = RemailError


@dataclass
class RemailAccount:
    """Ngữ cảnh lấy thư của một đơn Remail."""

    email: str
    service_token: str
    order_no: str
    project_id: int
    email_suffix: str


_CONTEXT_CACHE: dict[str, RemailAccount] = {}
_CONTEXT_LOCK = threading.RLock()


def _cache_key(email: str) -> str:
    return str(email or "").strip().lower()


def _base_url(value: str | None = None) -> str:
    """Trả gốc API, cũng chấp nhận người dùng dán nhầm địa chỉ tài liệu ``.../docs``."""
    raw = str(
        value if value is not None else getattr(_email_cfg, "REMAIL_API_BASE", DEFAULT_API_BASE) or DEFAULT_API_BASE
    ).strip()
    if not raw:
        raw = DEFAULT_API_BASE
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw

    parsed = urlsplit(raw.rstrip("/"))
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise RemailError("Địa chỉ Remail API không hợp lệ, hãy điền https://remail.aishop6.com (đừng điền path API)")

    path = parsed.path.rstrip("/")
    # 文档链接可直接粘贴到配置页；API 实际位于同一域名根路径。
    if path.lower() == "/docs":
        path = ""
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", "")).rstrip("/")


def _request_timeout() -> int:
    try:
        value = int(getattr(_email_cfg, "REMAIL_REQUEST_TIMEOUT", REQUEST_TIMEOUT) or REQUEST_TIMEOUT)
    except (TypeError, ValueError):
        value = REQUEST_TIMEOUT
    return max(1, min(120, value))


def _api_key() -> str:
    value = str(getattr(_email_cfg, "REMAIL_API_KEY", "") or "").strip()
    if not value:
        raise RemailError("Remail API Key chưa cấu hình, hãy điền REMAIL_API_KEY ở Cấu hình → Email / OTP")
    return value


def _auth_headers() -> dict[str, str]:
    return {"Accept": "application/json", "Authorization": f"Bearer {_api_key()}"}


def _error_message(payload, response) -> str:
    if isinstance(payload, dict):
        message = payload.get("message") or payload.get("error") or payload.get("detail")
        request_id = payload.get("requestId") or payload.get("request_id")
        if message:
            return f"{message} (requestId={request_id})" if request_id else str(message)
    text = str(getattr(response, "text", "") or "").strip()
    return text[:240] if text else "Server không trả thông tin lỗi"


def _request(
    method: str,
    path: str,
    *,
    params: dict | None = None,
    json_body: dict | None = None,
    headers: dict[str, str] | None = None,
    authenticated: bool = True,
):
    """Gọi Remail API và trả JSON payload.

    ``authenticated=False`` chỉ dùng cho API pickup. Service token không ghi vào log và text exception.
    """
    request_headers = {"Accept": "application/json"}
    if authenticated:
        request_headers.update(_auth_headers())
    if headers:
        request_headers.update(headers)

    url = _base_url() + (path if str(path).startswith("/") else f"/{path}")
    try:
        response = requests.request(
            method.upper(),
            url,
            params=params,
            json=json_body,
            headers=request_headers,
            timeout=_request_timeout(),
        )
    except requests.RequestException as exc:
        raise RemailError(f"Yêu cầu Remail thất bại ({method.upper()} {path}): {type(exc).__name__}: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        if response.status_code >= 400:
            raise RemailError(
                f"Yêu cầu Remail thất bại ({method.upper()} {path}): HTTP {response.status_code}; "
                f"{_error_message(None, response)}"
            ) from exc
        raise RemailError(f"Phản hồi Remail không phải JSON ({method.upper()} {path})") from exc

    if response.status_code >= 400:
        if response.status_code == 401 and authenticated:
            raise RemailError(f"Remail API Key không hợp lệ hoặc đã hết hạn ({path})")
        raise RemailError(
            f"Yêu cầu Remail thất bại ({method.upper()} {path}): HTTP {response.status_code}; "
            f"{_error_message(payload, response)}"
        )
    return payload


def _first_value(data: dict, *keys: str):
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value
    return None


def _unwrap_order(payload) -> dict:
    """Đọc Order theo định nghĩa OpenAPI, và tương thích một số gateway bọc data/order."""
    if not isinstance(payload, dict):
        raise RemailError("Phản hồi đặt đơn Remail không phải object")
    if any(
        k in payload
        for k in ("orderNo", "order_no", "deliveryEmail", "delivery_email", "serviceToken", "service_token")
    ):
        return payload
    for key in ("data", "order"):
        value = payload.get(key)
        if isinstance(value, dict):
            return value
    raise RemailError("Phản hồi đặt đơn Remail thiếu dữ liệu đơn")


def _project_id() -> int:
    raw = getattr(_email_cfg, "REMAIL_PROJECT_ID", 2)
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        value = 0
    if value <= 0:
        raise RemailError(
            "ID dự án Remail chưa cấu hình, hãy truy vấn dự án qua Remail API rồi điền REMAIL_PROJECT_ID"
        )
    return value


def _email_suffix() -> str:
    suffix = str(getattr(_email_cfg, "REMAIL_EMAIL_SUFFIX", "outlook.com") or "").strip().lstrip("@")
    if not suffix or "@" in suffix or any(ch.isspace() for ch in suffix):
        raise RemailError("Hậu tố email Remail không hợp lệ, hãy điền domain như outlook.com (đừng điền cả email)")
    return suffix


def _supply_policy() -> str:
    value = str(getattr(_email_cfg, "REMAIL_SUPPLY_POLICY", "public_only") or "public_only").strip().lower()
    if value not in {"private_first", "public_only"}:
        raise RemailError("Chiến lược tồn kho Remail không hợp lệ, chỉ hỗ trợ private_first hoặc public_only")
    return value


def _service_mode() -> str:
    value = str(getattr(_email_cfg, "REMAIL_SERVICE_MODE", "purchase") or "purchase").strip().lower()
    if value not in {"code", "purchase"}:
        raise RemailError("Chế độ dịch vụ Remail không hợp lệ, chỉ hỗ trợ code hoặc purchase")
    return value


def _order_wait_seconds() -> int:
    try:
        value = int(getattr(_email_cfg, "REMAIL_ORDER_WAIT_SECONDS", 30) or 30)
    except (TypeError, ValueError):
        value = 30
    return max(0, min(180, value))


def _order_credentials(order: dict) -> tuple[str, str, str] | None:
    email = str(_first_value(order, "deliveryEmail", "delivery_email") or "").strip()
    token = str(_first_value(order, "serviceToken", "service_token") or "").strip()
    order_no = str(_first_value(order, "orderNo", "order_no") or "").strip()
    if email and "@" in email and token:
        return email, token, order_no
    return None


def _cache_context(account: RemailAccount) -> RemailAccount:
    """Cache ngữ cảnh lấy thư của đơn và trả object."""
    with _CONTEXT_LOCK:
        _CONTEXT_CACHE[_cache_key(account.email)] = account
    return account


def _context_from_order(order: dict, target_email: str) -> RemailAccount | None:
    """Tạo ngữ cảnh từ object đơn, và bắt email giao hàng khớp hoàn toàn."""
    credentials = _order_credentials(order)
    if not credentials:
        return None
    email, service_token, order_no = credentials
    if email.casefold() != str(target_email or "").strip().casefold():
        return None

    raw_project_id = _first_value(order, "projectId", "project_id")
    try:
        project_id = int(str(raw_project_id).strip()) if raw_project_id is not None else _project_id()
    except (TypeError, ValueError, RemailError):
        # 订单详情理论上一定有 projectId；历史接口缺失时不影响取件，保留
        # 当前配置值作为展示/兼容字段。
        try:
            project_id = _project_id()
        except RemailError:
            project_id = 0

    suffix = str(
        _first_value(order, "emailSuffix", "email_suffix")
        or email.rsplit("@", 1)[-1]
        or getattr(_email_cfg, "REMAIL_EMAIL_SUFFIX", "outlook.com")
    ).strip().lstrip("@")
    return RemailAccount(
        email=email,
        service_token=service_token,
        order_no=order_no,
        project_id=project_id,
        email_suffix=suffix,
    )


def _order_list_items(payload) -> list[dict]:
    """Đọc phản hồi danh sách đơn, tương thích gateway bọc data/items."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    data = payload.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def _saved_context_metadata(email: str) -> dict:
    """Đọc credential đơn Remail đã lưu trên tài khoản, không đẩy lỗi parse vào luồng kiểm tra sống."""
    try:
        from core import db

        row = db.get_account_by_email(email)
    except Exception as exc:
        logger.debug("[Remail] Đọc thông tin đơn của tài khoản đã đăng ký thất bại: %s: %s", type(exc).__name__, exc)
        return {}
    if not row:
        return {}

    raw = row.get("extra_json")
    if isinstance(raw, str) and raw.strip():
        try:
            extra = json.loads(raw)
        except (TypeError, ValueError):
            extra = {}
    elif isinstance(raw, dict):
        extra = raw
    else:
        extra = {}
    if not isinstance(extra, dict):
        return {}

    # 新字段使用 email_service；同时兼容早期开发版本可能使用 remail。
    for key in ("email_service", "remail"):
        value = extra.get(key)
        if isinstance(value, dict):
            source = str(value.get("source") or "remail").strip().lower()
            if source == "remail":
                return dict(value)
    return {}


def get_account_context_metadata(email: str) -> dict | None:
    """Trả ngữ cảnh đơn Remail có thể lưu, dùng khi ghi tài khoản đăng ký.

    service token là credential lấy thư, không ghi log; chỉ tầng lưu tài khoản gọi hàm này, API danh sách
    thường không trả thẳng ``extra_json``.
    """
    account = get_account_context(email)
    if account is None:
        return None
    return {
        "source": "remail",
        "email": account.email,
        "service_token": account.service_token,
        "order_no": account.order_no,
        "project_id": account.project_id,
        "email_suffix": account.email_suffix,
    }


def restore_account_context(email: str) -> RemailAccount | None:
    """Khôi phục ngữ cảnh lấy thư Remail của tài khoản đã đăng ký.

    Sau khi process khởi động lại, ``_CONTEXT_CACHE`` mất. Ưu tiên service token đã lưu trên tài khoản,
    sau đó tra chi tiết theo số đơn đã lưu, cuối cùng dùng API Key tìm đơn theo email. Mọi đơn ứng viên
    phải khớp hoàn toàn email đích, không phân biệt hoa thường, để khỏi lấy nhầm mã OTP email khác.
    """
    target = str(email or "").strip()
    if not target:
        return None
    cached = get_account_context(target)
    if cached is not None:
        return cached

    metadata = _saved_context_metadata(target)
    saved_email = str(metadata.get("email") or "").strip()
    if saved_email and saved_email.casefold() != target.casefold():
        metadata = {}

    saved_token = str(metadata.get("service_token") or metadata.get("serviceToken") or "").strip()
    if saved_token:
        order = {
            "deliveryEmail": saved_email or target,
            "serviceToken": saved_token,
            "orderNo": str(metadata.get("order_no") or metadata.get("orderNo") or "").strip(),
            "projectId": metadata.get("project_id") or metadata.get("projectId"),
            "emailSuffix": metadata.get("email_suffix") or metadata.get("emailSuffix"),
        }
        account = _context_from_order(order, target)
        if account is not None:
            logger.info(
                "[Remail] Đã khôi phục ngữ cảnh lấy thư từ thông tin lưu trên tài khoản: %s order=%s",
                target,
                account.order_no or "-",
            )
            return _cache_context(account)

    saved_order_no = str(metadata.get("order_no") or metadata.get("orderNo") or "").strip()
    if saved_order_no:
        try:
            detail = _unwrap_order(
                _request("GET", f"/v1/open/orders/{quote(saved_order_no, safe='')}")
            )
        except RemailError as exc:
            logger.debug("[Remail] Khôi phục theo số đơn đã lưu thất bại: order=%s error=%s", saved_order_no, exc)
        else:
            account = _context_from_order(detail, target)
            if account is not None:
                logger.info(
                    "[Remail] Đã khôi phục ngữ cảnh lấy thư theo số đơn: %s order=%s",
                    target,
                    account.order_no or saved_order_no,
                )
                return _cache_context(account)

    # 没有可用的持久化凭证时，通过 API Key 查询用户自己的订单。列表接口的
    # search 是服务端过滤；仍需在客户端做完整邮箱匹配，不能接受模糊命中。
    try:
        payload = _request(
            "GET",
            "/v1/open/orders",
            params={"search": target},
        )
    except RemailError as exc:
        logger.debug("[Remail] Tìm đơn theo email thất bại: email=%s error=%s", target, exc)
        return None

    candidates = [
        item
        for item in _order_list_items(payload)
        if str(_first_value(item, "deliveryEmail", "delivery_email") or "").strip().casefold()
        == target.casefold()
    ]
    candidates.sort(
        key=lambda item: _parse_timestamp(
            _first_value(item, "updatedAt", "updated_at", "createdAt", "created_at")
        )
        or float("-inf"),
        reverse=True,
    )

    # 列表响应通常直接带 serviceToken；若网关出于安全策略隐藏 token，
    # 再逐个请求订单详情（优先最新订单）。
    for order in candidates:
        account = _context_from_order(order, target)
        if account is not None:
            logger.info(
                "[Remail] Đã khôi phục ngữ cảnh lấy thư bằng tìm theo email: %s order=%s",
                target,
                account.order_no or "-",
            )
            return _cache_context(account)

    for order in candidates[:5]:
        order_no = str(_first_value(order, "orderNo", "order_no") or "").strip()
        if not order_no:
            continue
        try:
            detail = _unwrap_order(
                _request("GET", f"/v1/open/orders/{quote(order_no, safe='')}")
            )
        except RemailError:
            continue
        account = _context_from_order(detail, target)
        if account is not None:
            logger.info(
                "[Remail] Đã khôi phục ngữ cảnh lấy thư từ chi tiết đơn: %s order=%s",
                target,
                account.order_no or order_no,
            )
            return _cache_context(account)
    return None


def _order_status_error(order: dict) -> str | None:
    status = str(order.get("status") or "").strip().lower()
    if status in _FINAL_ORDER_STATUSES:
        failure = str(order.get("failureCode") or order.get("failure_code") or "").strip()
        return f"Đơn Remail chưa sẵn sàng: status={status}" + (f", failure={failure}" if failure else "")
    return None


def _wait_for_order_credentials(order: dict) -> tuple[str, str, str]:
    credentials = _order_credentials(order)
    if credentials:
        return credentials

    order_no = str(_first_value(order, "orderNo", "order_no") or "").strip()
    if not order_no:
        raise RemailError("Đặt đơn Remail thành công nhưng phản hồi thiếu service token hoặc số đơn")

    error = _order_status_error(order)
    if error:
        raise RemailError(error)

    deadline = time.monotonic() + _order_wait_seconds()
    latest = order
    while time.monotonic() <= deadline:
        try:
            latest = _unwrap_order(_request("GET", f"/v1/open/orders/{order_no}"))
        except RemailError:
            # 订单已创建，短暂的详情接口错误不应重新下单，继续等待到截止时间。
            if time.monotonic() >= deadline:
                raise
        else:
            credentials = _order_credentials(latest)
            if credentials:
                return credentials
            error = _order_status_error(latest)
            if error:
                raise RemailError(error)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1, remaining))

    status = str(latest.get("status") or "unknown")
    raise RemailError(f"Chờ service token đơn Remail quá hạn: order={order_no}, status={status}")


def pick_account() -> RemailAccount:
    """Tạo một đơn Remail nhận mã/mua dài hạn theo cấu hình và trả email giao hàng."""
    project_id = _project_id()
    email_suffix = _email_suffix()
    service_mode = _service_mode()
    supply = _supply_policy()
    idempotency_key = f"turb-gpt-free-register-{uuid.uuid4()}"

    payload = _request(
        "POST",
        "/v1/open/orders",
        params={"serviceMode": service_mode, "supply": supply},
        json_body={"projectId": project_id, "emailSuffix": email_suffix},
        headers={"Idempotency-Key": idempotency_key},
    )
    order = _unwrap_order(payload)
    email, service_token, order_no = _wait_for_order_credentials(order)
    account = RemailAccount(
        email=email,
        service_token=service_token,
        order_no=order_no,
        project_id=project_id,
        email_suffix=email_suffix,
    )
    _cache_context(account)
    logger.info("[Remail] Đã tạo đơn email: %s order=%s project=%s", email, order_no or "-", project_id)
    return account


def get_email() -> str:
    """Tương thích entry cũ của các client email tạm khác."""
    return pick_account().email


def get_account_context(email: str) -> RemailAccount | None:
    with _CONTEXT_LOCK:
        return _CONTEXT_CACHE.get(_cache_key(email))


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    """Giải phóng ngữ cảnh lấy thư cục bộ; vòng đời đơn do server Remail quản lý."""
    with _CONTEXT_LOCK:
        account = _CONTEXT_CACHE.pop(_cache_key(email), None)
    if account:
        logger.info(
            "[Remail] Đã giải phóng ngữ cảnh lấy thư: %s order=%s status=%s note=%s",
            email,
            account.order_no or "-",
            status,
            note or "",
        )


def _parse_timestamp(raw) -> float | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
        return value / 1000.0 if value > 10_000_000_000 else value

    text = str(raw).strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        value = float(text)
        return value / 1000.0 if value > 10_000_000_000 else value
    try:
        iso = text[:-1] + "+00:00" if text.endswith("Z") else text
        parsed = datetime.fromisoformat(iso)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _pickup_items(payload) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict):
        payload = data
    elif isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    items = payload.get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _message_code(message: dict) -> str | None:
    direct = _first_value(message, "verificationCode", "verification_code", "code", "otp")
    if direct is not None:
        match = _CODE_RE.search(str(direct))
        if match:
            return match.group(1)

    preview = str(_first_value(message, "bodyPreview", "body_preview", "body", "text", "content") or "")
    return extract_otp(
        {
            "from": str(_first_value(message, "sender", "from", "fromEmail") or ""),
            "subject": str(message.get("subject") or ""),
            "text": preview,
            "content": preview,
        }
    )


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """Poll Remail pickup, trả mã OTP 6 số mới nhất sau thời điểm nhận."""
    target = str(email or "").strip()
    if not target:
        raise RemailError("Lấy mã Remail thiếu địa chỉ email")
    account = get_account_context(target) or restore_account_context(target)
    if account is None:
        raise RemailError(
            """Remail không tìm thấy service token của email này, và không khôi phục được từ đơn đã lưu;hãy xác nhận nguồn đăng ký là Remail, đơn vẫn lấy thư được, và đã cấu hình Remail API Key"""
        )

    try:
        wait_seconds = int(max_wait if max_wait is not None else getattr(_email_cfg, "OTP_MAX_WAIT", 90))
    except (TypeError, ValueError):
        wait_seconds = 90
    try:
        interval = int(poll_interval if poll_interval is not None else getattr(_email_cfg, "OTP_POLL_INTERVAL", 3))
    except (TypeError, ValueError):
        interval = 3
    try:
        settle = int(settle_seconds if settle_seconds is not None else getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5))
    except (TypeError, ValueError):
        settle = 5
    interval = max(1, interval)
    settle = max(0, settle)
    deadline = time.monotonic() + max(0, wait_seconds)
    best_otp: str | None = None
    best_timestamp = float("-inf")
    settle_until: float | None = None
    last_error = "Hộp thư trống hoặc chưa có mã OTP mới"

    logger.info("[Remail] Bắt đầu poll email %s, tối đa %ss", target, wait_seconds)
    while time.monotonic() <= deadline:
        try:
            payload = _request(
                "GET",
                "/v1/pickup",
                params={"email": target, "token": account.service_token},
                authenticated=False,
            )
            items = _pickup_items(payload)
            messages = []
            for message in items:
                received_at = _first_value(
                    message, "receivedAt", "received_at", "timestamp", "createdAt", "created_at"
                )
                timestamp = _parse_timestamp(received_at)
                if after_ts is not None and timestamp is not None and timestamp < after_ts - 30:
                    continue
                code = _message_code(message)
                if code:
                    messages.append((timestamp, code))

            messages.sort(
                key=lambda value: value[0] if value[0] is not None else float("-inf"),
                reverse=True,
            )
            for timestamp, code in messages:
                candidate_time = float("-inf") if timestamp is None else timestamp
                if (
                    best_otp is None
                    or candidate_time > best_timestamp
                    or (candidate_time == best_timestamp and code != best_otp)
                ):
                    best_otp = code
                    best_timestamp = candidate_time
                    settle_until = time.monotonic() + settle
                    logger.info("[Remail] Khoá OTP ứng viên, chờ %ss để xác nhận", settle)

            if best_otp and settle_until is not None and time.monotonic() >= settle_until:
                return best_otp
        except RemailError as exc:
            last_error = str(exc)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))

    if best_otp:
        return best_otp
    raise RemailError(f"Chờ mã OTP Remail quá hạn: {target}; {last_error}")


def list_projects(*, search: str | None = None, product_type: str | None = "microsoft") -> list[dict]:
    """Liệt kê dự án mà API Key hiện tại thấy, dùng cho cấu hình/chẩn đoán."""
    params = {"offset": 0, "limit": 100}
    if search:
        params["search"] = str(search).strip()
    if product_type:
        params["productType"] = str(product_type).strip()
    payload = _request("GET", "/v1/open/projects", params=params)
    if isinstance(payload, dict):
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        items = data.get("items") if isinstance(data, dict) else None
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []
