# -*- coding: utf-8 -*-
"""
Client email lấy mã qua API chung.

Định dạng nhập kho email:
    email----code_url

Lúc đăng ký nhận email; lúc lấy mã GET thẳng code_url và rút mã OTP 6 số từ phản hồi.
Phản hồi có thể là văn bản thuần, HTML hoặc JSON, miễn là chứa mã OTP 6 số.
"""
import json
import logging
import re
import time
import base64
import html as html_lib
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, urlunparse, parse_qsl, urlencode

import requests

from config import email as _email_cfg
from config import proxy as _proxy_cfg  # 兼容旧调用方及可测试的代理池回退
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

_CODE_REGEX = re.compile(r"\b(\d{6})\b")
_CONTEXT_WORDS = ("code", "verify", "verification", "验证码", "代码", "确认码", "認証", "コード")
_CONTEXT_CACHE: dict[str, "GenericApiEmailAccount"] = {}
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ACCOUNTS_FILE = _PROJECT_ROOT / "用于注册的API邮箱.txt"
_YANGYANG_MESSAGES_RE = re.compile(r"/messages/([^/]+)/([^/?#]+)", re.IGNORECASE)
_PUBLIC_INBOX_LINK_RE = re.compile(r"^/i/([^/?#]+)/*$", re.IGNORECASE)
_PUBLIC_INBOX_API_RE = re.compile(
    r"^/api/public/inboxes/([^/?#]+)/latest-code/*$", re.IGNORECASE,
)
_YANGYANG_OPENAI_SUBJECT_HINTS = (
    "temporary chatgpt",
    "chatgpt verification code",
    "chatgpt login code",
    "临时 chatgpt",
    "chatgpt 登录代码",
    "chatgpt 验证码",
    "一時的な認証コード",
    "一時ログインコード",
)


class GenericApiMailError(RuntimeError):
    """Lỗi email lấy mã qua API chung."""


def _redact_proxy_url(proxy_url: str) -> str:
    """Log giữ địa chỉ và giao thức proxy, nhưng ẩn thông tin xác thực."""
    raw = str(proxy_url or "").strip()
    if not raw:
        return "direct"
    try:
        parsed = urlparse(raw)
        if not parsed.hostname:
            return "configured-proxy"
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        auth = "***@" if parsed.username or parsed.password else ""
        return f"{parsed.scheme}://{auth}{host}{port}"
    except Exception:
        return "configured-proxy"


def _new_http_session(proxy_url: str = "") -> requests.Session:
    """Tạo phiên lấy mã không kế thừa proxy hệ thống; có proxy thì HTTP/HTTPS đều đi proxy đó."""
    session = requests.Session()
    session.trust_env = False
    proxy_url = str(proxy_url or "").strip()
    if proxy_url:
        session.proxies.update({"http": proxy_url, "https": proxy_url})
    return session


def _cache_busted_url(url: str, attempt: int) -> str:
    """Thêm tham số phá cache cho API lấy mã, tránh CDN/reverse proxy cứ trả mã OTP thư trước."""
    try:
        parsed = urlparse(str(url))
        query = parse_qsl(parsed.query, keep_blank_values=True)
        query.append(("_otp_poll", f"{int(time.time() * 1000)}-{attempt}"))
        return urlunparse(parsed._replace(query=urlencode(query)))
    except Exception:
        return url


@dataclass
class GenericApiEmailAccount:
    email: str
    code_url: str


def _public_inbox_latest_code_url(code_url: str) -> str | None:
    """Đổi link hộp thư công khai /i/{token} thành /api/public/inboxes/{token}/latest-code."""
    try:
        parsed = urlparse(str(code_url or "").strip())
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    match = _PUBLIC_INBOX_LINK_RE.match(parsed.path or "")
    if not match:
        # 也接受用户直接导入 latest-code API 地址。
        match = _PUBLIC_INBOX_API_RE.match(parsed.path or "")
    if not match:
        return None
    token = unquote(match.group(1)).strip()
    if not token or "/" in token:
        return None
    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")
    return f"{origin}/api/public/inboxes/{quote(token, safe='')}/latest-code"


def _public_inbox_page_api_url(code_url: str) -> str | None:
    """Trả API danh sách hộp thư mà trang hộp thư công khai thực sự dùng."""
    latest_url = _public_inbox_latest_code_url(code_url)
    if not latest_url:
        return None
    return latest_url.rsplit("/latest-code", 1)[0]


def _fetch_public_inbox_page_otp(
    session: requests.Session,
    api_url: str,
    email: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """Theo inbox API mà trang /i/{token} dùng, rút mã OTP từ preview/thân thư mới nhất."""
    resp = session.get(
        api_url,
        headers={**headers, "Accept": "application/json"},
        timeout=20,
        verify=False,
    )
    if resp.status_code != 200:
        logger.debug("[GenericAPI] API trang public inbox HTTP %s: %s", resp.status_code, (resp.text or "")[:160])
        return None
    try:
        data = resp.json()
    except Exception:
        try:
            data = json.loads(resp.text or "")
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    mailbox = data.get("mailbox") or {}
    actual_email = str(mailbox.get("address") if isinstance(mailbox, dict) else mailbox or "").strip()
    if actual_email and actual_email.lower() != email.lower():
        raise GenericApiMailError(
            f"Email link hộp thư công khai không khớp: expected={email}, actual={actual_email}"
        )
    items = [x for x in (data.get("messages") or []) if isinstance(x, dict)]
    items.sort(
        key=lambda x: _parse_generic_api_ts(x.get("receivedAt") or x.get("received_at")) or 0,
        reverse=True,
    )
    origin = api_url.split("/api/public/inboxes/", 1)[0]
    token_path = api_url.split("/api/public/inboxes/", 1)[1].split("?", 1)[0].strip("/")
    for item in items:
        received_at = item.get("receivedAt") or item.get("received_at")
        msg_ts = _parse_generic_api_ts(received_at)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            continue
        raw_codes = item.get("verificationCodes") or item.get("verification_codes") or []
        code = next(
            (m.group(1) for value in raw_codes if (m := _CODE_REGEX.search(str(value)))),
            None,
        )
        subject = str(item.get("subject") or "")
        preview = str(item.get("preview") or "")
        if not code:
            code = _extract_yangyang_openai_code(subject, preview)
        msg_id = str(item.get("id") or "").strip()
        # 页面列表预览仍未抽到时，读取页面点击邮件时使用的详情 API。
        if not code and msg_id:
            detail_url = (
                f"{origin}/api/public/inboxes/{quote(unquote(token_path), safe='')}"
                f"/messages/{quote(msg_id, safe='')}"
            )
            try:
                detail_resp = session.get(
                    detail_url,
                    headers={**headers, "Accept": "application/json"},
                    timeout=20,
                    verify=False,
                )
                if detail_resp.status_code == 200:
                    detail = detail_resp.json()
                    detail_text = "\n".join([
                        str(detail.get("subject") or subject),
                        str(detail.get("preview") or preview),
                        str(detail.get("textBody") or ""),
                        str(detail.get("htmlBody") or ""),
                    ])
                    code = _extract_yangyang_openai_code(subject, detail_text)
            except Exception as exc:
                logger.debug("[GenericAPI] đọc chi tiết thư public inbox thất bại: %s: %s", type(exc).__name__, exc)
        if code:
            return code, {
                "source": "public_inbox_page",
                "mail_id": msg_id,
                "received_at": received_at,
                "msg_ts": msg_ts,
                "subject": subject,
                "from": item.get("fromAddress") or item.get("sender"),
            }
    return None


def _flatten_json(obj) -> str:
    parts: list[str] = []
    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif x is not None:
            parts.append(str(x))
    walk(obj)
    return "\n".join(parts)


def _decode_data_uri(text: str) -> str:
    """Giải mã thân data:text/html;base64,... thành HTML/văn bản để rút OTP."""
    if not isinstance(text, str):
        return ""
    if not text.startswith("data:"):
        return text
    try:
        _meta, payload = text.split(",", 1)
    except ValueError:
        return text
    if ";base64" in _meta.lower():
        try:
            return base64.b64decode(payload).decode("utf-8", errors="replace")
        except Exception:
            return text
    try:
        from urllib.parse import unquote_to_bytes
        return unquote_to_bytes(payload).decode("utf-8", errors="replace")
    except Exception:
        return text


def _extract_code(text: str) -> str | None:
    """Rút OTP 6 số từ văn bản thuần/HTML/JSON."""
    if not text:
        return None

    # 兼容 JSON：优先把所有 value 拉平再抽取。
    candidates_text = [_decode_data_uri(text), text]
    try:
        parsed = json.loads(text)
        candidates_text.insert(0, _decode_data_uri(_flatten_json(parsed)))
    except Exception:
        pass

    for body in candidates_text:
        # 复用邮件 OTP 抽取逻辑。
        code = extract_otp({"text": body, "content": body, "subject": body[:200]})
        if code:
            return code

        codes = _CODE_REGEX.findall(body)
        if not codes:
            continue
        lower = body.lower()
        for code in codes:
            idx = lower.find(code)
            window = lower[max(0, idx - 80): idx + 86]
            if any(w.lower() in window for w in _CONTEXT_WORDS):
                return code
        return codes[-1]
    return None


def _extract_yangyang_openai_code(subject: str, body: str) -> str | None:
    """
    Chi tiết thư yangyang: template OpenAI thường trộn nhiều số 6 chữ số:
    - 202123 / 353740 là số CSS/template
    - OTP thật nằm gần “Your code is / code:”, thường là số nghiệp vụ 6 chữ số cuối thân thư
    nên không được tái sử dụng “khớp ngữ cảnh đầu tiên” của _extract_code chung.
    """
    body = _decode_data_uri(body or "")
    subject_l = (subject or "").lower()
    text = "\n".join([subject or "", body])

    # 去掉 style/script，减少 CSS 颜色、宽高等 6 位数字干扰。
    clean = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<script[^>]*>.*?</script>", " ", clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"#[0-9a-fA-F]{6}\b", " ", clean)
    clean = re.sub(r"(?:color|background|border|width|height|font-size|line-height)\s*:\s*[^;\"']+", " ", clean, flags=re.IGNORECASE)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()

    codes = _CODE_REGEX.findall(clean)
    if not codes:
        return None

    # 过滤已知模板噪声；保留其它 6 位候选。
    noise = {"000000", "202123", "353740"}
    candidates = [c for c in codes if c not in noise]
    if not candidates:
        candidates = codes

    lower = clean.lower()
    patterns = (
        r"(?:code is|code:|verification code is|login code is|your code is)\D{0,80}(\d{6})",
        r"(?:验证码|驗證碼|登录代码|登入代碼|確認コード|認証コード|ログインコード)\D{0,80}(\d{6})",
        r"(\d{6})\D{0,80}(?:code|验证码|驗證碼|確認コード|認証コード)",
    )
    for pat in patterns:
        matches = re.findall(pat, clean, flags=re.IGNORECASE)
        matches = [m for m in matches if m not in noise]
        if matches:
            return matches[-1]

    # OpenAI 临时代码邮件：清理噪声后最后一个业务 6 位数最稳定。
    if any(h in subject_l for h in _YANGYANG_OPENAI_SUBJECT_HINTS) or "openai" in lower or "chatgpt" in lower:
        return candidates[-1]

    return _extract_code(clean)


def _parse_yangyang_code_url(code_url: str) -> tuple[str, str, str] | None:
    """
    Parse trang email kiểu yangyang.website:
        /messages/{token}/{email}
    Trả (origin, token, email).
    """
    try:
        parsed = urlparse(code_url)
    except Exception:
        return None
    m = _YANGYANG_MESSAGES_RE.search(parsed.path or "")
    if not m:
        return None
    origin = urlunparse((parsed.scheme or "http", parsed.netloc, "", "", "", ""))
    token = unquote(m.group(1))
    email = unquote(m.group(2))
    if not origin or not token or not email:
        return None
    return origin.rstrip("/"), token, email


def _parse_yangyang_ts(value: str | None) -> float | None:
    if not value:
        return None
    raw = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _parse_generic_api_ts(value) -> float | None:
    """Parse trường thời gian API chung trả, tương thích ISO8601/Z và định dạng giờ địa phương thường gặp."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # 数字时间戳：秒 / 毫秒
    if re.fullmatch(r"\d+(?:\.\d+)?", raw):
        try:
            ts = float(raw)
            return ts / 1000.0 if ts > 10_000_000_000 else ts
        except Exception:
            return None
    # ISO8601: 2026-08-05T01:10:17.000Z
    try:
        iso = raw
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            return dt.timestamp()
        return dt.timestamp()
    except Exception:
        pass
    # 常见字符串格式
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _extract_structured_api_code(text: str, after_ts: float | None = None) -> tuple[str, dict] | None:
    """
    Tương thích API lấy mã kiểu newzoe trả thẳng JSON:
      {"code":"784207","from":"...","subject":"Your temporary ChatGPT login code","time":"2026-08-05T01:10:17.000Z"}

    Nếu phản hồi có time/date/received_at, lọc mã cũ theo after_ts, tránh lấy mã OTP cache lần trước.
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    # 常见字段优先级：code / otp / verification_code；没有再回退从拉平文本提取。
    raw_code = (
        data.get("code")
        or data.get("otp")
        or data.get("verification_code")
        or data.get("verificationCode")
        or data.get("email_code")
        or data.get("emailCode")
    )
    code = None
    if raw_code is not None:
        m = _CODE_REGEX.search(str(raw_code))
        if m:
            code = m.group(1)
    if not code:
        code = _extract_code(_flatten_json(data))
    if not code:
        return None

    ts_raw = (
        data.get("time")
        or data.get("date")
        or data.get("received_at")
        or data.get("receivedAt")
        or data.get("created_at")
        or data.get("createdAt")
        or data.get("timestamp")
    )
    msg_ts = _parse_generic_api_ts(ts_raw)
    if after_ts and msg_ts and msg_ts + 2 < after_ts:
        logger.debug(
            "[GenericAPI] structured API bỏ qua mã OTP cũ: code=%s ts=%s after=%s subject=%r",
            code,
            ts_raw,
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
            str(data.get("subject") or "")[:80],
        )
        return None

    return code, {
        "source": "structured_api",
        "received_at": ts_raw,
        "msg_ts": msg_ts,
        "subject": data.get("subject"),
        "from": data.get("from") or data.get("fromAddress") or data.get("sender"),
    }


def _fetch_yangyang_otp(
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """Rút mã OTP 6 số mới nhất từ API danh sách + API chi tiết của trang email yangyang."""
    parsed = _parse_yangyang_code_url(code_url)
    if not parsed:
        return None
    origin, token, email = parsed
    token_q = quote(token, safe="")
    email_q = quote(email, safe="@._+-")
    api_url = f"{origin}/api/messages/{token_q}/{email_q}"

    items: list[dict] = []
    cursor: str | None = None
    # 一般第一页足够；保守支持最多翻 5 页。
    for _ in range(5):
        url = api_url if not cursor else f"{api_url}?cursor={quote(str(cursor), safe='')}"
        resp = session.get(url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=False)
        if resp.status_code != 200:
            if resp.status_code == 404:
                # 兼容 mail.ai1998.xyz 这类同样是 /messages/{token}/{email}，
                # 但没有 /api/messages，邮件直接内嵌在 HTML 页面中的实现。
                return _fetch_inline_messages_page_otp(
                    session=session,
                    code_url=code_url,
                    headers=headers,
                    after_ts=after_ts,
                )
            logger.debug(f"[GenericAPI] danh sách thư yangyang HTTP {resp.status_code}: {resp.text[:160]}")
            return None
        data = resp.json()
        page_items = data.get("items") or []
        if isinstance(page_items, list):
            items.extend([x for x in page_items if isinstance(x, dict)])
        if not data.get("has_more") or not data.get("next_cursor"):
            break
        cursor = str(data.get("next_cursor"))

    # API 默认新邮件在前；再次按时间倒序，尽量取最新验证码。
    items.sort(key=lambda x: _parse_yangyang_ts(x.get("received_at") or x.get("receivedAt")) or 0, reverse=True)
    for item in items:
        msg_ts_raw = item.get("received_at") or item.get("receivedAt")
        msg_ts = _parse_yangyang_ts(msg_ts_raw)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] yangyang bỏ qua thư cũ: id=%s ts=%s after=%s subject=%r",
                item.get("id"), msg_ts_raw, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        msg_id = item.get("id")
        if not msg_id:
            continue
        detail_url = f"{origin}/message/{quote(str(msg_id), safe='')}/{token_q}/{email_q}"
        try:
            detail_resp = session.get(detail_url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=False)
            if detail_resp.status_code != 200:
                continue
            detail = detail_resp.json()
        except Exception as exc:
            logger.debug(f"[GenericAPI] đọc chi tiết thư yangyang thất bại: {type(exc).__name__}: {exc}")
            continue

        raw_body = str(detail.get("body") or "")
        body = _decode_data_uri(raw_body)
        subject = str(detail.get("subject") or item.get("subject") or "")
        text = "\n".join([
            subject,
            str(detail.get("fromAddress") or item.get("from_address") or ""),
            str(detail.get("receivedAt") or item.get("received_at") or ""),
            body,
        ])
        code = _extract_yangyang_openai_code(subject, body)
        if code:
            logger.info(
                f"[GenericAPI] trang yangyang rút được OTP={code}, "
                f"mail_id={msg_id}, ts={detail.get('receivedAt') or item.get('received_at')}, subject={subject[:80]!r}"
            )
            return code, {
                "mail_id": msg_id,
                "received_at": detail.get("receivedAt") or item.get("received_at"),
                "subject": subject,
                "msg_ts": msg_ts,
            }
    return None


def _strip_html_fragment(value: str) -> str:
    value = str(value or "")
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html_lib.unescape(value)
    value = re.sub(r"[ \t\r\f\v]+", " ", value)
    value = re.sub(r"\n\s+", "\n", value)
    return value.strip()


def _fetch_inline_messages_page_otp(
    *,
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """Parse trang /messages không có JSON API, render thẳng thẻ thư trong HTML."""
    try:
        resp = session.get(
            code_url,
            headers={**headers, "Accept": "text/html,application/xhtml+xml,text/plain,*/*"},
            timeout=20,
            verify=False,
        )
        if resp.status_code != 200:
            logger.debug("[GenericAPI] trang inline messages HTTP %s: %s", resp.status_code, (resp.text or "")[:160])
            return None
        html = resp.text or ""
    except Exception as exc:
        logger.debug("[GenericAPI] đọc trang inline messages thất bại: %s: %s", type(exc).__name__, exc)
        return None

    cards = re.findall(r"<article\b[^>]*class=[\"'][^\"']*mail-card[^\"']*[\"'][^>]*>(.*?)</article>", html, flags=re.DOTALL | re.IGNORECASE)
    # 没有 article 时退一步按 details 分块，避免 class 名细微变化。
    if not cards:
        cards = re.findall(r"<details\b[^>]*>(.*?)</details>", html, flags=re.DOTALL | re.IGNORECASE)

    items: list[dict] = []
    for idx, card in enumerate(cards):
        subject_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*subject[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        date_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*date[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        from_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*meta[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)
        body_m = re.search(r"<pre\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</pre>", card, flags=re.DOTALL | re.IGNORECASE)
        if not body_m:
            body_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)

        subject = _strip_html_fragment(subject_m.group(1) if subject_m else "")
        received_at = _strip_html_fragment(date_m.group(1) if date_m else "")
        from_addr = _strip_html_fragment(from_m.group(1) if from_m else "")
        body = _strip_html_fragment(body_m.group(1) if body_m else card)
        msg_ts = _parse_yangyang_ts(received_at)
        items.append({
            "mail_id": f"inline-{idx}",
            "subject": subject,
            "received_at": received_at,
            "from": from_addr,
            "body": body,
            "msg_ts": msg_ts or 0.0,
        })

    items.sort(key=lambda x: float(x.get("msg_ts") or 0.0), reverse=True)
    for item in items:
        msg_ts = float(item.get("msg_ts") or 0.0)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] inline messages bỏ qua thư cũ: id=%s ts=%s after=%s subject=%r",
                item.get("mail_id"), item.get("received_at"),
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        code = _extract_yangyang_openai_code(str(item.get("subject") or ""), str(item.get("body") or ""))
        if code:
            logger.info(
                "[GenericAPI] trang inline messages rút được OTP=%s, mail_id=%s, ts=%s, subject=%r",
                code, item.get("mail_id"), item.get("received_at"), str(item.get("subject") or "")[:80],
            )
            return code, {
                "mail_id": item.get("mail_id"),
                "received_at": item.get("received_at"),
                "subject": item.get("subject"),
                "msg_ts": msg_ts,
            }
    return None


def pick_account() -> GenericApiEmailAccount:
    """Nhận thẳng một email API chung còn dùng từ kho email SQLite."""
    from core.db import claim_next_generic_api_email, generic_api_email_pool_summary

    row = claim_next_generic_api_email()
    if row is None:
        summary = generic_api_email_pool_summary()
        raise GenericApiMailError(
            f"Kho email API chung không còn tài khoản: {summary}. Hãy nhập vào kho email WebUI: email----địa chỉ lấy mã"
        )
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[account.email] = account
    logger.info(f"[GenericAPI] Đã chọn email: {account.email}（DB id={row.get('id')}）")
    return account


def import_from_file(path: str | Path | None = None) -> tuple[int, int]:
    """Nhập email API chung từ file văn bản, mỗi dòng: email----code_url hoặc email====code_url."""
    from core.db import import_generic_api_emails
    p = Path(path) if path else _ACCOUNTS_FILE
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    if not p.exists():
        return 0, 0
    records = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----") if "----" in line else line.split("====")
        parts = [x.strip() for x in parts]
        if len(parts) < 2:
            continue
        records.append({"email": parts[0], "code_url": parts[1]})
    return import_generic_api_emails(records)


def get_account_context(email: str) -> GenericApiEmailAccount | None:
    if email in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[email]
    from core.db import get_generic_api_email_by_email
    row = get_generic_api_email_by_email(email)
    if row is None:
        return None
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[email] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    from core.db import release_generic_api_email
    release_generic_api_email(email, status=status, note=note)
    _CONTEXT_CACHE.pop(email, None)


def _fetch_poll_payload(
    *,
    proxy_url: str,
    poll_url: str,
    email: str,
    headers: dict,
    after_ts: float | None,
    is_yangyang: bool,
    public_inbox_api_url: str | None,
):
    """Thực hiện một yêu cầu lấy mã, đường mạng do caller chỉ định."""
    session = _new_http_session(proxy_url)
    yy_result = (
        _fetch_yangyang_otp(session, poll_url, headers, after_ts=after_ts)
        if is_yangyang else None
    )
    public_result = (
        _fetch_public_inbox_page_otp(
            session, poll_url, email, headers, after_ts=after_ts,
        )
        if public_inbox_api_url else None
    )
    page_result = yy_result or public_result
    if page_result or is_yangyang or public_inbox_api_url:
        return page_result, yy_result, None, ""
    resp = session.get(poll_url, headers=headers, timeout=20, verify=False)
    return None, None, resp, resp.text or ""


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    Poll code_url đã cấu hình của email này đến khi rút được mã OTP 6 số hoặc quá hạn.

    Cơ chế settle: lần đầu có mã không trả ngay, tiếp tục chờ OTP_SETTLE_SECONDS giây.
    Nếu trong lúc đó địa chỉ lấy mã trả mã khác thì thay ứng viên và đặt lại đếm ngược settle;
    hết settle giây không đổi mới trả, tránh lấy mã cũ trong cache API.
    """
    account = get_account_context(email)
    if account is None:
        raise GenericApiMailError(f"Email API chung không tồn tại hoặc chưa nhập: {email}")

    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    headers = {
        "Accept": "application/json,text/plain,*/*",
        "User-Agent": "Mozilla/5.0 (compatible; gpt-register/1.0)",
        "Cache-Control": "no-cache, no-store, max-age=0",
        "Pragma": "no-cache",
    }
    last_error = ""
    best_otp: str | None = None
    best_seen_at: float = 0.0
    settle_until: float | None = None
    logger.info(
        f"[GenericAPI] Bắt đầu poll địa chỉ lấy mã: {email}，"
        f"tối đa {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s"
    )
    is_yangyang = _parse_yangyang_code_url(account.code_url) is not None
    public_inbox_api_url = _public_inbox_page_api_url(account.code_url)
    if public_inbox_api_url:
        logger.info(
            "[GenericAPI] Đã nhận trang hộp thư công khai, dùng inbox API của trang: host=%s email=%s",
            urlparse(public_inbox_api_url).netloc,
            email,
        )

    selected_proxy = str(getattr(_email_cfg, "GENERIC_API_PROXY", "") or "").strip()
    # 兼容旧版配置：未设置通用 API 专用代理时沿用代理池；专用代理优先。
    if not selected_proxy:
        selected_proxy = str(_proxy_cfg.pick_proxy() or "").strip()
    routes: list[tuple[str, str]] = []
    if selected_proxy:
        routes.append(("generic_api_local_proxy", selected_proxy))
    routes.append(("direct", ""))
    logger.info(
        "[GenericAPI] Tuyến HTTP: proxy=%s, khi lỗi mạng %s",
        _redact_proxy_url(selected_proxy),
        "lùi về đi thẳng" if selected_proxy else "đi thẳng",
    )

    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            # 不修改 yangyang 的路径型 URL；其列表接口本身按邮件 ID 返回数据。
            base_poll_url = public_inbox_api_url or account.code_url
            poll_url = base_poll_url if is_yangyang else _cache_busted_url(base_poll_url, attempt)
            route_error: Exception | None = None
            page_result = yy_result = resp = None
            text = ""
            for route_index, (_route_name, route_proxy) in enumerate(routes):
                relay = None
                try:
                    effective_proxy = route_proxy
                    page_result, yy_result, resp, text = _fetch_poll_payload(
                        proxy_url=effective_proxy,
                        poll_url=poll_url,
                        email=email,
                        headers=headers,
                        after_ts=after_ts,
                        is_yangyang=is_yangyang,
                        public_inbox_api_url=public_inbox_api_url,
                    )
                    route_error = None
                    break
                except requests.RequestException as exc:
                    route_error = exc
                    last_error = f"{type(exc).__name__}: {exc}"
                    has_fallback = route_index + 1 < len(routes)
                    logger.warning(
                        "[GenericAPI] yêu cầu trang/API thất bại: route=%s %s: %s%s",
                        _redact_proxy_url(route_proxy),
                        type(exc).__name__,
                        exc,
                        ", chuyển đi thẳng rồi thử lại" if has_fallback else "",
                    )
                finally:
                    if relay is not None:
                        relay.close()
            if route_error is not None:
                raise route_error

            if page_result:
                code, yy_meta = page_result
                result_source = str(yy_meta.get("source") or ("yangyang" if yy_result else "public_inbox_page"))
                now_seen = time.time()
                if not best_otp:
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                    logger.info(
                        f"[GenericAPI] Khoá OTP lần đầu={code}, source={result_source} mail_id={yy_meta.get('mail_id')} ts={yy_meta.get('received_at')}, "
                        f"chờ {settle}s xem API lấy mã có mã OTP mới hơn không..."
                    )
                elif code != best_otp:
                    logger.info(
                        f"[GenericAPI] Thấy OTP cập nhật={code}, source={result_source} mail_id={yy_meta.get('mail_id')} ts={yy_meta.get('received_at')}，"
                        f"thay mã trước đó {best_otp}, đặt lại đồng hồ settle"
                    )
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                else:
                    logger.debug(f"[GenericAPI] API lấy mã vẫn trả OTP ứng viên={best_otp}")
                resp = None
                text = ""
            else:
                if is_yangyang or public_inbox_api_url:
                    last_error = (
                        "danh sách yangyang chưa có thư mã OTP mới sau after_ts"
                        if is_yangyang else
                        "trang hộp thư công khai chưa có thư mã OTP mới sau after_ts"
                    )
                    resp = None
                    text = ""
            if resp is None:
                pass
            elif resp.status_code == 200:
                public_payload = None
                if public_inbox_api_url:
                    try:
                        public_payload = json.loads(text)
                    except Exception:
                        public_payload = None
                mailbox = str((public_payload or {}).get("mailbox") or "").strip()
                mailbox_mismatch = bool(mailbox and mailbox.lower() != email.lower())
                if mailbox_mismatch:
                    structured = None
                    last_error = f"latest-code trả email không khớp: expected={email}, actual={mailbox}"
                else:
                    # 此类公开 latest-code 服务的 receivedAt 可能使用独立服务器时间，
                    # 与运行机器相差数小时甚至跨日。它只返回“最新一封”，因此这里
                    # 把时间字段作为诊断信息，不作为硬过滤条件；候选更新仍由
                    # code/messageId 变化及 settle 机制负责。
                    structured = _extract_structured_api_code(
                        text,
                        after_ts=None if public_inbox_api_url else after_ts,
                    )
                structured_meta = structured[1] if structured else {}
                code = structured[0] if structured else _extract_code(text)
                if mailbox_mismatch:
                    code = None
                if code:
                    if (
                        public_inbox_api_url
                        and after_ts
                        and structured_meta.get("msg_ts")
                        and float(structured_meta["msg_ts"]) + 2 < after_ts
                    ):
                        logger.warning(
                            """[GenericAPI] receivedAt của latest-code sớm hơn mốc lấy mã,vẫn lấy thư mới nhất phía server làm ứng viên: receivedAt=%s after=%s messageId=%s""",
                            structured_meta.get("received_at"),
                            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                            (public_payload or {}).get("messageId"),
                        )
                    now_seen = time.time()
                    if not best_otp:
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                        if structured_meta:
                            logger.info(
                                f"[GenericAPI] Khoá OTP lần đầu={code}, source=structured_api "
                                f"ts={structured_meta.get('received_at')} subject={str(structured_meta.get('subject') or '')[:80]!r}, "
                                f"chờ {settle}s xem API lấy mã có mã OTP mới hơn không..."
                            )
                        else:
                            logger.info(
                                f"[GenericAPI] Khoá OTP lần đầu={code}, "
                                f"chờ {settle}s xem API lấy mã có mã OTP mới hơn không..."
                            )
                    elif code != best_otp:
                        if structured_meta:
                            logger.info(
                                f"[GenericAPI] Thấy OTP cập nhật={code}, source=structured_api "
                                f"ts={structured_meta.get('received_at')} subject={str(structured_meta.get('subject') or '')[:80]!r}，"
                                f"thay mã trước đó {best_otp}, đặt lại đồng hồ settle"
                            )
                        else:
                            logger.info(
                                f"[GenericAPI] Thấy OTP cập nhật={code}，"
                                f"thay mã trước đó {best_otp}, đặt lại đồng hồ settle"
                            )
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                    else:
                        logger.debug(f"[GenericAPI] API lấy mã vẫn trả OTP ứng viên={best_otp}")
                else:
                    if not mailbox_mismatch:
                        if public_inbox_api_url and isinstance(public_payload, dict) and public_payload.get("code") is None:
                            last_error = "latest-code trả code=null, email chưa nhận mã OTP"
                        else:
                            last_error = f"HTTP 200 nhưng không rút được mã OTP 6 số, preview phản hồi: {text[:160]}"
            else:
                last_error = f"HTTP {resp.status_code}: {text[:160]}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[GenericAPI] settle xong, trả OTP={best_otp}, "
                f"thời điểm khoá ứng viên={time.strftime('%H:%M:%S', time.localtime(best_seen_at))}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp and settle_until is not None:
            logger.info(
                f"[GenericAPI] Đã khoá OTP ứng viên={best_otp}, đang chờ settle"
                f" (settle còn ~{max(0, int(settle_until - now))}s, tổng còn {remaining}s)..."
            )
        else:
            logger.info(
                f"[GenericAPI] Chưa lấy được mã OTP từ API lấy mã, "
                f"{interval}s nữa thử lại (còn {remaining}s)..."
            )
        time.sleep(interval)

    if best_otp:
        logger.warning(f"[GenericAPI] Hết hạn tổng nhưng đã có ứng viên, trả OTP={best_otp}")
        return best_otp

    raise GenericApiMailError(f"Chờ mã OTP API chung quá hạn: {email}; {last_error}")
