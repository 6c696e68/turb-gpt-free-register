# -*- coding: utf-8 -*-
"""Client email tạm Cloudflare Worker (tương thích cloudflare_temp_email).

Khớp grokRegister-cpa/email_providers/cloudflare.py:
  - POST new_address / admin/new_address tự tạo email, nhận jwt
  - GET mails poll hộp thư, rút OTP OpenAI 6 số
"""
from __future__ import annotations

import logging
import re
import secrets
import string
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from typing import Any

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp, looks_like_openai_email

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 20
_DOMAIN_COUNTER = 0
_DOMAIN_LOCK = threading.Lock()


class CFTempMailError(RuntimeError):
    """Lỗi yêu cầu email tạm Cloudflare Worker hoặc lấy mã."""


@dataclass
class CFTempMailAccount:
    email: str
    jwt: str
    domain: str = ""
    created_at: float = 0.0


_CONTEXT_CACHE: dict[str, CFTempMailAccount] = {}


def _cache_key(email: str) -> str:
    return str(email or "").strip().lower()


def _cfg_str(name: str, default: str = "") -> str:
    return str(getattr(_email_cfg, name, default) or default).strip()


def _cfg_int(name: str, default: int) -> int:
    try:
        return int(getattr(_email_cfg, name, default) or default)
    except (TypeError, ValueError):
        return default


def _normalize_path(path: str, default: str) -> str:
    raw = str(path or default or "").strip() or default
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def _base_url() -> str:
    base = _cfg_str("CLOUDFLARE_API_BASE")
    if not base:
        raise CFTempMailError(
            "Địa chỉ Cloudflare API chưa cấu hình, hãy điền CLOUDFLARE_API_BASE (WebUI «Cấu hình → Email / OTP»)."
        )
    if not re.match(r"^https?://", base, re.I):
        base = "https://" + base
    return base.rstrip("/")


def _timeout() -> int:
    return max(5, _cfg_int("CLOUDFLARE_REQUEST_TIMEOUT", DEFAULT_TIMEOUT))


def _auth_mode() -> str:
    return _cfg_str("CLOUDFLARE_AUTH_MODE", "none").lower() or "none"


def _api_key() -> str:
    return _cfg_str("CLOUDFLARE_API_KEY")


def _custom_auth() -> str:
    return _cfg_str("CLOUDFLARE_CUSTOM_AUTH")


def _apply_custom_auth(headers: dict[str, str]) -> dict[str, str]:
    custom = _custom_auth()
    if custom:
        headers["x-custom-auth"] = custom
    return headers


def _build_headers(*, content_type: bool = False, bearer_jwt: str | None = None) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = "application/json"
    if bearer_jwt:
        headers["Authorization"] = f"Bearer {bearer_jwt}"
    else:
        key = _api_key()
        mode = _auth_mode()
        if key:
            if mode == "x-api-key":
                headers["X-API-Key"] = key
            elif mode == "x-admin-auth":
                headers["x-admin-auth"] = key
            elif mode == "bearer":
                headers["Authorization"] = f"Bearer {key}"
            elif mode not in ("none", "query-key"):
                headers["Authorization"] = f"Bearer {key}"
    return _apply_custom_auth(headers)


def _auth_params(params: dict | None = None) -> dict:
    merged = dict(params or {})
    key = _api_key()
    if key and _auth_mode() == "query-key":
        merged["key"] = key
    return merged


def _is_admin_create_path(path: str) -> bool:
    return str(path or "").rstrip("/").lower().endswith("/admin/new_address")


def _normalize_domains(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = raw.replace(";", "\n").replace(",", "\n").splitlines()
    else:
        try:
            parts = list(raw)
        except TypeError:
            parts = [raw]
    out: list[str] = []
    for item in parts:
        domain = str(item or "").strip().lower().lstrip("@")
        if domain and "." in domain and " " not in domain and domain not in out:
            out.append(domain)
    return out


def _default_domains() -> list[str]:
    return _normalize_domains(getattr(_email_cfg, "CLOUDFLARE_DEFAULT_DOMAINS", []) or [])


def _next_domain() -> str:
    domains = _default_domains()
    if not domains:
        return ""
    global _DOMAIN_COUNTER
    with _DOMAIN_LOCK:
        domain = domains[_DOMAIN_COUNTER % len(domains)]
        _DOMAIN_COUNTER += 1
    return domain


def _generate_local(length: int | None = None) -> str:
    n = max(3, int(length if length is not None else _cfg_int("CLOUDFLARE_NAME_LENGTH", 10)))
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _request(
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
    params: dict | None = None,
    bearer_jwt: str | None = None,
    content_type: bool = False,
) -> Any:
    url = _base_url() + _normalize_path(path, path or "/")
    headers = _build_headers(content_type=content_type or json_body is not None, bearer_jwt=bearer_jwt)
    query = _auth_params(params)
    try:
        response = requests.request(
            method.upper(),
            url,
            headers=headers,
            json=json_body,
            params=query or None,
            timeout=_timeout(),
        )
    except requests.RequestException as exc:
        raise CFTempMailError(f"Yêu cầu Cloudflare thất bại ({path}): {type(exc).__name__}: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        text = (getattr(response, "text", "") or "")[:200]
        if response.status_code >= 400:
            raise CFTempMailError(
                f"Yêu cầu Cloudflare thất bại ({path}): HTTP {response.status_code}; {text}"
            ) from exc
        raise CFTempMailError(
            f"Phản hồi Cloudflare không phải JSON ({path}): HTTP {response.status_code}; {text}"
        ) from exc

    if response.status_code >= 400:
        message = ""
        if isinstance(payload, dict):
            message = str(payload.get("message") or payload.get("error") or payload.get("msg") or "")
        if not message:
            message = str(payload)[:200]
        hint = ""
        if response.status_code in (401, 403) and "turnstile" in message.lower():
            hint = "; tạo ẩn danh có thể bị Turnstile chặn, hãy đổi sang x-admin-auth + /admin/new_address"
        elif response.status_code in (401, 403) and _auth_mode() == "none":
            hint = "; có thể thử CLOUDFLARE_AUTH_MODE=x-admin-auth và điền ADMIN_PASSWORD"
        raise CFTempMailError(
            f"Yêu cầu Cloudflare thất bại ({path}): HTTP {response.status_code}; {message}{hint}"
        )
    return payload


def _pick_list_payload(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("results", "hydra:member", "data", "messages", "mails", "emails"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            for nested_key in ("messages", "mails", "emails", "results", "list"):
                nested = value.get(nested_key)
                if isinstance(nested, list):
                    return [item for item in nested if isinstance(item, dict)]
    return []


def create_address(domain: str | None = None) -> CFTempMailAccount:
    """Gọi Worker tạo email tạm, trả address + jwt."""
    accounts_path = _normalize_path(
        _cfg_str("CLOUDFLARE_PATH_ACCOUNTS", "/api/new_address"),
        "/api/new_address",
    )
    selected_domain = str(domain or "").strip().lstrip("@") or _next_domain()
    mode = _auth_mode()
    key = _api_key()
    admin_create = _is_admin_create_path(accounts_path)

    if admin_create or mode in ("x-admin-auth", "bearer", "x-api-key", "query-key"):
        if not key:
            raise CFTempMailError(
                "Chế độ admin/xác thực Cloudflare cần CLOUDFLARE_API_KEY (ADMIN_PASSWORD)."
            )

    if admin_create:
        payload: dict[str, Any] = {
            "name": _generate_local(),
            "enablePrefix": True,
        }
        if selected_domain:
            payload["domain"] = selected_domain
    else:
        # /api/new_address ẩn danh: chỉ domain; header xác thực vẫn inject theo AUTH_MODE (nếu đã cấu hình Key)
        payload = {}
        if selected_domain:
            payload["domain"] = selected_domain

    data = _request("POST", accounts_path, json_body=payload, content_type=True)
    if not isinstance(data, dict):
        raise CFTempMailError(f"Phản hồi tạo email Cloudflare sai định dạng: {str(data)[:200]}")

    nested = data.get("data") if isinstance(data.get("data"), dict) else {}
    address = str(data.get("address") or nested.get("address") or nested.get("email") or data.get("email") or "").strip()
    jwt = str(data.get("jwt") or nested.get("jwt") or nested.get("token") or data.get("token") or "").strip()
    if not address or "@" not in address:
        raise CFTempMailError(f"Phản hồi tạo email Cloudflare thiếu address: {str(data)[:200]}")
    if not jwt:
        raise CFTempMailError(f"Phản hồi tạo email Cloudflare thiếu jwt: {str(data)[:200]}")

    domain_part = address.split("@", 1)[-1].lower()
    account = CFTempMailAccount(
        email=address,
        jwt=jwt,
        domain=domain_part,
        created_at=time.time(),
    )
    logger.info("[Cloudflare] Đã tạo email tạm: %s (domain=%s)", address, domain_part)
    return account


def pick_account() -> CFTempMailAccount:
    """Tạo và cache một email tạm Cloudflare."""
    account = create_address()
    _CONTEXT_CACHE[_cache_key(account.email)] = account
    return account


def get_account_context(email: str) -> CFTempMailAccount | None:
    return _CONTEXT_CACHE.get(_cache_key(email))


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    _CONTEXT_CACHE.pop(_cache_key(email), None)
    logger.info(
        "[Cloudflare] Đã giải phóng email tạm: %s (status=%s, note=%s)",
        email,
        status,
        note or "",
    )


def _message_timestamp(item: dict) -> float | None:
    """Parse thời gian thư. created_at của Worker thường là UTC và không có hậu tố múi giờ, phải hiểu là UTC."""
    for key in ("timestamp", "created_at", "createdAt", "date", "receivedAt", "time"):
        raw = item.get(key)
        if raw is None or raw == "":
            continue
        if isinstance(raw, (int, float)):
            value = float(raw)
            if value > 1e12:
                value = value / 1000.0
            return value
        text = str(raw).strip()
        if not text:
            continue
        try:
            if text.isdigit():
                value = float(text)
                if value > 1e12:
                    value /= 1000.0
                return value
            # Tương thích "2026-07-19 12:57:38" / ISO
            normalized = text.replace("Z", "+00:00")
            if "T" not in normalized and " " in normalized and "+" not in normalized[10:]:
                # Thời gian phân tách bằng khoảng trắng không múi giờ: xử lý theo UTC (cloudflare_temp_email thường gặp)
                dt = datetime.fromisoformat(normalized).replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(normalized)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
        try:
            dt = parsedate_to_datetime(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            continue
    return None


def _strip_html(value: str) -> str:
    return re.sub(r"<[^>]+>", " ", value or "")


def _message_text(item: dict) -> str:
    parts: list[str] = []
    for field in ("text", "raw", "content", "intro", "body", "snippet", "bodyText", "bodyPreview"):
        value = item.get(field)
        if isinstance(value, str) and value.strip():
            parts.append(value)
    html = item.get("html") or item.get("html_content") or item.get("bodyHtml")
    if isinstance(html, str) and html.strip():
        parts.append(_strip_html(html))
    elif isinstance(html, list):
        for chunk in html:
            if isinstance(chunk, str) and chunk.strip():
                parts.append(_strip_html(chunk))
    return "\n".join(parts)


def _message_addresses(item: dict) -> list[str]:
    out: list[str] = []
    for key in ("address", "to", "recipient", "recipients"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip().lower())
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, str) and entry.strip():
                    out.append(entry.strip().lower())
                elif isinstance(entry, dict):
                    addr = entry.get("address") or entry.get("email") or entry.get("addr")
                    if addr:
                        out.append(str(addr).strip().lower())
    return out


def _decode_mime_header(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    out: list[str] = []
    for part, charset in parts:
        if isinstance(part, bytes):
            out.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            out.append(str(part))
    return "".join(out).strip()


def _parse_raw_email(raw: str) -> dict[str, str]:
    """Parse raw MIME của cloudflare_temp_email thành subject/from/text/html."""
    result = {"subject": "", "from": "", "text": "", "html": ""}
    if not (raw or "").strip():
        return result
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw.encode("utf-8", errors="replace"))
    except Exception:
        # Dự phòng: ít nhất trích Subject/From từ header
        for line in raw.splitlines():
            low = line.lower()
            if low.startswith("subject:") and not result["subject"]:
                result["subject"] = _decode_mime_header(line.split(":", 1)[1].strip())
            elif low.startswith("from:") and not result["from"]:
                result["from"] = line.split(":", 1)[1].strip()
        result["text"] = raw
        return result

    result["subject"] = _decode_mime_header(str(msg.get("subject") or ""))
    result["from"] = str(msg.get("from") or "").strip()
    texts: list[str] = []
    htmls: list[str] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="replace")
        if not isinstance(body, str):
            body = str(body)
        if ctype == "text/plain":
            texts.append(body)
        else:
            htmls.append(body)
    result["text"] = "\n".join(texts).strip()
    result["html"] = "\n".join(htmls).strip()
    if not result["text"] and not result["html"]:
        result["text"] = raw
    return result


def _standalone_otp_from_html(html: str) -> str | None:
    """Thư OpenAI thường gặp: mã OTP đứng một dòng/ô, ví dụ >449759<."""
    if not html:
        return None
    # Bỏ style, giảm nhầm màu kiểu #353740
    cleaned = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.I | re.S)
    for pattern in (
        r">\s*(\d{6})\s*<",
        r"(?m)^\s*(\d{6})\s*$",
    ):
        matches = re.findall(pattern, cleaned)
        # Lọc ngữ cảnh màu sắc/mã theo dõi rõ ràng ở tầng trên; ở đây lấy mã độc lập cuối cùng gần OTP trong nội dung hơn
        if matches:
            return matches[-1]
    return None


def _otp_item(item: dict) -> dict:
    raw = item.get("raw") if isinstance(item.get("raw"), str) else ""
    parsed = _parse_raw_email(raw) if raw else {"subject": "", "from": "", "text": "", "html": ""}

    sender = (
        item.get("from")
        or item.get("from_address")
        or item.get("sender")
        or item.get("source")  # Field list cloudflare_temp_email
        or parsed.get("from")
        or ""
    )
    subject = item.get("subject") or parsed.get("subject") or ""
    text = item.get("text") or parsed.get("text") or ""
    html = item.get("html") if isinstance(item.get("html"), str) else ""
    if not html:
        html = parsed.get("html") or ""

    # Nếu chỉ có raw và parse MIME thất bại, giữ văn bản không phải header làm dự phòng
    if not text and not html and raw:
        text = raw

    # Ưu tiên nhét mã 6 số độc lập vào đầu text, giúp extract_otp trúng OTP trong nội dung chứ không phải nhiễu header email
    standalone = _standalone_otp_from_html(html) or _standalone_otp_from_html(text)
    if standalone:
        text = f"verification code {standalone}\n{text}"

    return {
        "id": item.get("id") or item.get("msgid") or item.get("mail_id"),
        "from": sender,
        "subject": subject,
        "text": text,
        "html": html,
        "to": ", ".join(_message_addresses(item)),
    }


def _message_id(item: dict) -> str:
    return str(item.get("id") or item.get("msgid") or item.get("mail_id") or "").strip()


def list_messages(jwt: str, *, limit: int = 20, offset: int = 0) -> list[dict]:
    """Kéo hộp thư. /api/mails của cloudflare_temp_email bắt buộc limit hợp lệ (nếu không HTTP 400 Invalid limit)."""
    path = _normalize_path(
        _cfg_str("CLOUDFLARE_PATH_MESSAGES", "/api/mails"),
        "/api/mails",
    )
    # Căn chỉnh với grokRegister-cpa: limit/offset là query param bắt buộc
    safe_limit = max(1, min(100, int(limit or 20)))
    safe_offset = max(0, int(offset or 0))
    payload = _request(
        "GET",
        path,
        bearer_jwt=jwt,
        params={"limit": safe_limit, "offset": safe_offset},
    )
    return _pick_list_payload(payload)


def get_message_detail(jwt: str, message_id: str) -> dict:
    if not message_id:
        return {}
    messages_path = _normalize_path(
        _cfg_str("CLOUDFLARE_PATH_MESSAGES", "/api/mails"),
        "/api/mails",
    )
    candidates = [
        f"/api/mail/{message_id}",
        f"{messages_path}/{message_id}",
    ]
    last_error: Exception | None = None
    for path in candidates:
        try:
            payload = _request("GET", path, bearer_jwt=jwt)
            if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
                return payload["data"]
            if isinstance(payload, dict):
                return payload
        except CFTempMailError as exc:
            last_error = exc
            continue
    if last_error:
        logger.debug("[Cloudflare] Lấy chi tiết thư thất bại id=%s: %s", message_id, last_error)
    return {}


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """Poll email Cloudflare, trả mã OTP OpenAI 6 số mới nhất sau thời điểm nhận."""
    target = str(email or "").strip()
    if not target:
        raise CFTempMailError("Lấy mã Cloudflare thiếu địa chỉ email")

    account = get_account_context(target)
    if account is None or not account.jwt:
        raise CFTempMailError(
            f"Thiếu ngữ cảnh email Cloudflare: {target}. Hãy xác nhận địa chỉ này do nguồn cloudflare của process hiện tại tạo."
        )

    wait_seconds = int(max_wait if max_wait is not None else _email_cfg.OTP_MAX_WAIT)
    interval = max(1, int(poll_interval if poll_interval is not None else _email_cfg.OTP_POLL_INTERVAL))
    settle = max(0, int(settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS))
    after = float(after_ts if after_ts is not None else time.time()) - 30
    deadline = time.monotonic() + max(0, wait_seconds)

    best_otp: str | None = None
    best_timestamp = float("-inf")
    best_message_key = ""
    settle_until: float | None = None
    last_error = "Hộp thư trống hoặc chưa có mã OTP OpenAI mới"
    target_lower = target.lower()

    logger.info("[Cloudflare] Bắt đầu poll email %s, tối đa %ss", target, wait_seconds)

    while time.monotonic() < deadline:
        try:
            messages = list_messages(account.jwt)
        except CFTempMailError as exc:
            last_error = str(exc)
            logger.warning("[Cloudflare] Kéo thư thất bại: %s", exc)
            time.sleep(interval)
            continue

        if messages:
            logger.debug("[Cloudflare] Vòng này nhận %s thư", len(messages))

        for item in messages:
            addresses = _message_addresses(item)
            if addresses and not any(target_lower == a or target_lower in a for a in addresses):
                continue

            detail = item
            msg_id = _message_id(item)
            otp_probe = _otp_item(detail)
            # Khi trường danh sách không đủ thì thử chi tiết
            if (not otp_probe.get("text") and not otp_probe.get("html")) or not looks_like_openai_email(otp_probe):
                if msg_id:
                    fetched = get_message_detail(account.jwt, msg_id)
                    if fetched:
                        merged = dict(item)
                        merged.update(fetched)
                        detail = merged
                        otp_probe = _otp_item(detail)

            otp_item = otp_probe
            if not looks_like_openai_email(otp_item):
                logger.debug(
                    "[Cloudflare] Bỏ qua thư không phải OpenAI id=%s from=%s subject=%s",
                    msg_id,
                    str(otp_item.get("from") or "")[:80],
                    str(otp_item.get("subject") or "")[:80],
                )
                continue

            ts = _message_timestamp(detail)
            if ts is not None and ts < after:
                logger.info(
                    "[Cloudflare] Bỏ qua thư quá cũ id=%s ts=%s after=%s subject=%s",
                    msg_id,
                    int(ts),
                    int(after),
                    str(otp_item.get("subject") or "")[:60],
                )
                continue

            otp = extract_otp(otp_item)
            if not otp:
                logger.info(
                    "[Cloudflare] Thư OpenAI không rút được mã 6 số id=%s subject=%s",
                    msg_id,
                    str(otp_item.get("subject") or "")[:80],
                )
                continue

            message_key = msg_id or f"{otp_item.get('subject')}|{otp}|{ts}"
            effective_ts = ts if ts is not None else time.time()
            if effective_ts > best_timestamp or (
                effective_ts == best_timestamp and message_key != best_message_key and best_otp != otp
            ):
                if best_otp and best_otp != otp:
                    logger.info("[Cloudflare] Thấy OTP muộn hơn=%s, thay %s", otp, best_otp)
                elif not best_otp:
                    logger.info("[Cloudflare] Khoá OTP ứng viên %s, chờ settle=%ss", otp, settle)
                best_otp = otp
                best_timestamp = effective_ts
                best_message_key = message_key
                settle_until = time.monotonic() + settle
            elif message_key == best_message_key and best_otp == otp:
                # Cùng một email không reset settle
                pass

        now = time.monotonic()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info("[Cloudflare] settle xong, trả OTP=%s", best_otp)
            return best_otp

        remaining = max(0, int(deadline - now))
        if best_otp and settle_until is not None:
            logger.info(
                "[Cloudflare] Đã có OTP ứng viên=%s, settle còn ~%ss, tổng còn %ss",
                best_otp,
                max(0, int(settle_until - now)),
                remaining,
            )
        else:
            logger.info(
                "[Cloudflare] Chưa khớp OTP dùng được, thử lại sau %ss (còn %ss; số thư vòng này=%s)",
                interval,
                remaining,
                len(messages),
            )
        if remaining <= 0:
            break
        time.sleep(min(interval, max(1, remaining)))

    if best_otp:
        logger.warning("[Cloudflare] Hết hạn tổng nhưng đã có ứng viên, trả OTP=%s", best_otp)
        return best_otp

    raise CFTempMailError(f"Chờ mã OTP Cloudflare quá hạn: {target}; {last_error}")
