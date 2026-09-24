# -*- coding: utf-8 -*-
"""
Client IMAP email QQ (chế độ email domain Cloudflare)

Luồng:
    1. pick_domain_email()    sinh email domain random@domain và ghi DB
    2. fetch_latest_otp()     poll OTP qua IMAP email QQ

Phụ thuộc: thư viện chuẩn Python (imaplib, email, ssl), không thêm package bên thứ ba.
"""
import imaplib
import email as email_lib
import logging
import random
import string
import time
from datetime import datetime, timezone
from email.header import decode_header
from pathlib import Path

from config import email as _email_cfg
from core.otp_utils import looks_like_openai_email, extract_otp

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class QQMailClientError(RuntimeError):
    """Lỗi dịch vụ email QQ."""


# ============================================================
# Công cụ parse thư
# ============================================================

def _decode_email_header(header_value: str | None) -> str:
    """Giải mã header thư (xử lý encoding kiểu =?UTF-8?B?...?=)."""
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            try:
                result.append(part.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                result.append(part.decode("utf-8", errors="replace"))
        else:
            result.append(str(part))
    return " ".join(result)


def _parse_email_date(msg) -> float | None:
    """Parse ngày từ email.message thành timestamp UTC."""
    date_str = msg.get("Date") or msg.get("date")
    if not date_str:
        return None
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        pass
    try:
        parsed = email_lib.utils.parsedate(date_str)
        if parsed:
            import calendar
            return calendar.timegm(parsed)
    except Exception:
        pass
    return None


def _get_msg_text(msg) -> str:
    """Rút thân thư đệ quy (ưu tiên plain text)."""
    if msg.is_multipart():
        text_parts = []
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp:
                continue
            if ctype == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text_parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    pass
        if text_parts:
            return "\n".join(text_parts)

        # fallback: text/html
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp:
                continue
            if ctype == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
                except Exception:
                    pass
        return ""

    # not multipart
    try:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
    except Exception:
        pass
    return ""


def _msg_to_dict(msg) -> dict:
    """Chuyển email.message thành dict thống nhất (tương thích outlook_client)."""
    subject = _decode_email_header(msg.get("Subject") or msg.get("subject") or "")
    from_ = _decode_email_header(msg.get("From") or msg.get("from") or "")
    to_ = _decode_email_header(msg.get("To") or msg.get("to") or "")
    delivered_to = _decode_email_header(msg.get("Delivered-To") or "")
    original_to = _decode_email_header(msg.get("X-Original-To") or "")
    body_text = _get_msg_text(msg)
    ts = _parse_email_date(msg)
    ts_str = (
        datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if ts else ""
    )
    return {
        "subject": subject,
        "from": from_,
        "to": to_,
        "deliveredTo": delivered_to,
        "xOriginalTo": original_to,
        "sendEmail": from_,
        "text": body_text,
        "bodyPreview": body_text,
        "bodyText": body_text,
        "date": ts_str,
        "receivedDateTime": ts_str,
    }


# ============================================================
# Kết nối và tìm IMAP
# ============================================================

def _connect_imap() -> imaplib.IMAP4_SSL:
    """Kết nối server IMAP email QQ và trả object kết nối."""
    server = _email_cfg.QQ_IMAP_SERVER
    port = _email_cfg.QQ_IMAP_PORT
    qq_email = _email_cfg.QQ_EMAIL
    password = _email_cfg.QQ_IMAP_PASSWORD

    if not qq_email or not password:
        raise QQMailClientError(
            "IMAP email QQ chưa cấu hình, hãy đặt QQ_EMAIL và QQ_IMAP_PASSWORD trong config/email.py"
        )

    try:
        mail = imaplib.IMAP4_SSL(server, port)
        mail.login(qq_email, password)
        mail.select("INBOX")
        return mail
    except imaplib.IMAP4.error as exc:
        raise QQMailClientError(f"Đăng nhập IMAP email QQ thất bại: {exc}")
    except Exception as exc:
        raise QQMailClientError(f"Kết nối IMAP email QQ thất bại: {exc}")


def _search_messages(mail: imaplib.IMAP4_SSL, after_dt: datetime | None = None) -> list[dict]:
    """Tìm thư trong hộp thư sau after_dt, trả danh sách dict."""
    search_criteria = "ALL"
    if after_dt is not None:
        date_str = after_dt.strftime("%d-%b-%Y")
        search_criteria = f'(SINCE {date_str})'

    status, msg_ids = mail.search(None, search_criteria)
    if status != "OK":
        logger.warning(f"[QQMail] IMAP search thất bại: {status}")
        return []

    ids = msg_ids[0].split() if msg_ids[0] else []
    if not ids:
        return []

    # Chỉ lấy 15 thư gần nhất (tránh inbox quá lớn, vẫn đủ dùng)
    recent_ids = ids[-15:]

    messages = []
    for mid in recent_ids:
        status, data = mail.fetch(mid, "(RFC822)")
        if status != "OK":
            continue
        raw_email = data[0][1]
        try:
            msg = email_lib.message_from_bytes(raw_email)
            item = _msg_to_dict(msg)
            messages.append(item)
        except Exception as exc:
            logger.debug(f"[QQMail] Parse thư {mid} thất bại: {exc}")
            continue

    return messages


# ============================================================
# API công khai
# ============================================================

def pick_domain_email() -> str:
    """
    Sinh một địa chỉ email domain ngẫu nhiên và ghi vào DB.
    Định dạng: {8 chữ/số ngẫu nhiên}@{EMAIL_DOMAIN}
    """
    from core.db import claim_next_domain_email

    domain = _email_cfg.EMAIL_DOMAIN
    if not domain:
        raise QQMailClientError(
            "EMAIL_DOMAIN chưa cấu hình, hãy đặt domain Cloudflare của bạn trong config/email.py"
        )

    prefix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    email = f"{prefix}@{domain}"

    claim_next_domain_email(email)
    logger.info(f"[QQMail] Sinh email domain: {email}")
    return email


def release_domain_email(email: str, status: str = "available", note: str | None = None) -> None:
    """Cập nhật trạng thái email domain."""
    from core.db import release_domain_email as _release
    _release(email, status=status, note=note)


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    Poll OTP qua IMAP email QQ.

    Mỗi vòng poll:
        1. Kết nối IMAP email QQ, tìm thư sau mốc after_ts
        2. Lọc thư có địa chỉ TO khớp email
        3. Dùng otp_utils nhận thư mã OTP OpenAI và rút OTP 6 số
        4. Cơ chế settle: sau thư đầu chờ thêm OTP_SETTLE_SECONDS giây,
           xác nhận không có thư muộn hơn mới trả, tránh lấy OTP cũ giữa chừng

    Args:
        email: địa chỉ email domain dùng đăng ký (cũng dùng lọc địa chỉ TO của IMAP)
        after_ts: timestamp UTC, chỉ xem thư mới hơn mốc này
        max_wait / poll_interval: mặc định lấy từ config
    """
    if not after_ts:
        after_ts = time.time()
    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    # Dung sai lệch đồng hồ 30s
    after_dt = datetime.fromtimestamp(after_ts - 30, tz=timezone.utc)

    logger.info(
        f"[QQMail] Bắt đầu poll hộp thư email QQ (domain: {email}），"
        f"tối đa {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s..."
    )

    target_lower = email.lower()

    best_otp: str | None = None
    best_ts: float = 0.0
    best_subject: str = ""
    settle_until: float | None = None

    while time.time() < deadline:
        mail = None
        try:
            mail = _connect_imap()
            messages = _search_messages(mail, after_dt=after_dt)
        except QQMailClientError as exc:
            logger.warning(f"[QQMail] Kết nối IMAP thất bại: {exc}")
            messages = []
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

        # Sắp thời gian giảm dần
        messages.sort(key=lambda m: m.get("date") or "", reverse=True)

        # Tìm thư OpenAI mới nhất
        for item in messages:
            if not looks_like_openai_email(item):
                continue

            # Phải khớp địa chỉ nhận (tránh nhặt mã OTP cũ của địa chỉ domain khác)
            to_field = (item.get("to") or "").lower()
            if target_lower not in to_field:
                continue

            subject = item.get("subject") or ""
            otp = extract_otp(item)
            if not otp:
                continue

            # Parse timestamp
            ts = 0.0
            raw_ts = item.get("date") or item.get("receivedDateTime") or ""
            if raw_ts:
                try:
                    ts = (
                        datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        .timestamp()
                    )
                except Exception:
                    ts = 0.0

            if after_ts and ts < after_ts - 30:
                continue

            if ts > best_ts:
                if best_otp:
                    logger.info(
                        f"[QQMail] Thấy OTP muộn hơn={otp} (ts={raw_ts}), "
                        f"thay OTP trước {best_otp}, đặt lại đồng hồ settle"
                    )
                else:
                    logger.info(
                        f"[QQMail] Khoá OTP lần đầu={otp}, ts={raw_ts}, "
                        f"subject={subject!r}, chờ {settle}s xem có thư muộn hơn không..."
                    )
                best_otp = otp
                best_ts = ts
                best_subject = subject
                settle_until = time.time() + settle
            break  # Chỉ quan tâm thư mới nhất

        # Phán đoán settle
        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[QQMail] settle xong, trả OTP={best_otp}, subject={best_subject!r}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp:
            logger.info(
                f"[QQMail] Đã khoá OTP ứng viên={best_otp}, đang chờ settle"
                f"(settle còn ~{int(settle_until - now)}s, tổng còn {remaining}s)..."
            )
        else:
            logger.info(
                f"[QQMail] Chưa nhận thư OpenAI, {interval}s nữa thử lại (còn {remaining}s）..."
            )
        time.sleep(interval)

    # Hết hạn nhưng đã có ứng viên
    if best_otp:
        logger.warning(
            f"[QQMail] Hết hạn tổng nhưng đã có ứng viên, trả OTP={best_otp} (subject={best_subject!r})"
        )
        return best_otp

    raise QQMailClientError(
        f"Chờ {email} OTP quá hạn (>{max_wait or _email_cfg.OTP_MAX_WAIT}s）。"
        f"Có thể: cấu hình IMAP email QQ sai / chuyển tiếp Cloudflare chưa có hiệu lực / thư OpenAI chưa tới."
    )
