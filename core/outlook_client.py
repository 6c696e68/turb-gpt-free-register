# -*- coding: utf-8 -*-
"""
Client email Outlook (mail.chatai.codes, hai giao thức)

Định dạng file tài khoản cũ (chỉ để migrate lần đầu / nhập tay tương thích, mỗi dòng một tài khoản):
    # 4 đoạn (cơ bản)
    email----password----clientId----refreshToken
    Ví dụ: SorenBarrett5150@outlook.com----oc621409----9e5f94bc-...----M.C529_...

    # 6 đoạn (có thông tin khôi phục)
    email----password----clientId----refreshToken----recoveryEmail----recoveryCode
    Ví dụ: ChristinLeno5020@outlook.com----3qP3kEjF----9e5f94bc-...----M.C506_...----Dy9bOAnUd@wmhotmail.com----zf4rBS

Luồng:
    1. pick_account()       lấy một tài khoản chưa dùng từ kho email SQLite
    2. fetch_latest_otp()   poll OTP qua hai giao thức (Graph / IMAP)
    3. Đăng ký thành công thì ghi vào bảng tài khoản SQLite

Chỉ dùng refresh_token do Outlook cung cấp để gọi dịch vụ mail.chatai.codes từ xa,
không nối thẳng Microsoft Graph, vì Graph cần access_token và giao thức OAuth phức tạp.
"""
import base64
import email as email_lib
import hashlib
import hmac as hmac_mod
import imaplib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.header import decode_header
from urllib.parse import urlencode
from pathlib import Path

from curl_cffi.requests import Session as CurlSession

from config import (
    OUTLOOK_ACCOUNTS_FILE,
    OUTLOOK_API_BASE,
    OTP_SETTLE_SECONDS,
    USER_AGENT,
    IMPERSONATE,
)
# OTP_POLL_INTERVAL / OTP_MAX_WAIT 是 WebUI 可热改的，从模块读
from config import email as _email_cfg
from core.otp_utils import looks_like_openai_email, extract_otp

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 邮箱 → account 上下文的内存缓存，fetch_latest_otp 用
_CONTEXT_CACHE: dict[str, "OutlookAccount"] = {}

# 远端 mail.chatai.codes 被禁用时，本进程内直接跳过远端，走 Microsoft Graph 直连。
_REMOTE_DISABLED = False
_MS_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_MS_TOKEN_FATAL_CACHE: dict[str, tuple[str, float]] = {}


@dataclass
class OutlookAccount:
    email: str
    password: str
    client_id: str
    refresh_token: str
    recovery_email: str = ""  # 可选：恢复邮箱
    recovery_code: str = ""   # 可选：恢复码


class OutlookClientError(RuntimeError):
    """Lỗi dịch vụ email Outlook."""


def _cache_key(email: str) -> str:
    """Tạo key cache ngữ cảnh email, chuẩn hoá bằng cách bỏ khoảng trắng và chuyển thường."""
    return str(email or "").strip().lower()


def _http_session() -> CurlSession:
    s = CurlSession(impersonate=IMPERSONATE)
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Origin": OUTLOOK_API_BASE.rstrip("/"),
        "Referer": OUTLOOK_API_BASE.rstrip("/") + "/",
        "Accept": "*/*",
    })
    s.timeout = 30
    return s


# ============================================================
# mail.chatai.codes 安全签名层（AES-GCM + HMAC-SHA256）
#
# 流程（与前端 JS 完全对应）：
#   1. POST /api/security-session {} → { sessionId, sessionToken, sessionKey, expiresAt }
#   2. 每次 API 请求前构建 secure envelope：
#      iv(12B) 随机 + nonce(16B) 随机
#      ciphertext = AES-GCM(key, iv, JSON(payload))   ← key = base64url(sessionKey)
#      signedText = "{sessionId}.{nonce}.{timestamp}.{iv}.{ciphertext}"
#      signature  = HMAC-SHA256(key, signedText)
#   3. 发送 envelope 代替原始 payload
# ============================================================

def _b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_dec(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (0 if pad == 4 else pad))


def _aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Mã hoá AES-GCM, trả ciphertext || auth_tag (cùng hành vi WebCrypto)."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).encrypt(iv, plaintext, None)
    except ImportError:
        pass
    # fallback: pycryptodome
    from Crypto.Cipher import AES  # type: ignore
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct + tag


# 模块级安全 session 缓存（线程安全）
_sec_session: dict | None = None
_sec_session_lock = threading.Lock()


def _get_security_session(http: CurlSession) -> dict:
    """Lấy hoặc làm mới phiên bảo mật (tái sử dụng khi còn hạn, hết hạn thì gia hạn)."""
    global _sec_session
    now_ms = int(time.time() * 1000)
    with _sec_session_lock:
        if _sec_session and _sec_session["expiresAtMs"] - now_ms > 60_000:
            return _sec_session
        resp = http.post(
            f"{OUTLOOK_API_BASE.rstrip('/')}/api/security-session",
            headers={"Content-Type": "application/json"},
            data="{}",
        )
        if resp.status_code != 200:
            raise OutlookClientError(
                f"Khởi tạo security-session thất bại HTTP {resp.status_code}: {resp.text[:200]}"
            )
        data = resp.json()
        if not data.get("success"):
            raise OutlookClientError(f"security-session trả success=False: {data}")
        import datetime
        expires_ms = int(
            datetime.datetime.fromisoformat(
                data["expiresAt"].replace("Z", "+00:00")
            ).timestamp() * 1000
        )
        _sec_session = {
            "sessionId":    data["sessionId"],
            "sessionToken": data["sessionToken"],
            "sessionKey":   data["sessionKey"],
            "expiresAtMs":  expires_ms,
        }
        logger.debug(f"[Outlook] Đã làm mới phiên bảo mật sessionId={data['sessionId'][:8]}…")
        return _sec_session


def _secure_post(http: CurlSession, url: str, payload: dict, retry: int = 0) -> dict:
    """
    Mã hoá body bằng AES-GCM + HMAC-SHA256 rồi gửi tới mail.chatai.codes,
    trả dict JSON đã parse. 401/403 thì tự làm mới session và thử lại một lần.
    """
    global _sec_session
    session = _get_security_session(http)
    key = _b64url_dec(session["sessionKey"])

    iv    = os.urandom(12)
    nonce = _b64url_enc(os.urandom(16))
    ts    = int(time.time() * 1000)
    plain = json.dumps(payload, separators=(",", ":")).encode()

    ct_bytes  = _aes_gcm_encrypt(key, iv, plain)
    iv_b64    = _b64url_enc(iv)
    ct_b64    = _b64url_enc(ct_bytes)

    signed_text = f"{session['sessionId']}.{nonce}.{ts}.{iv_b64}.{ct_b64}"
    sig = _b64url_enc(
        hmac_mod.new(key, signed_text.encode(), hashlib.sha256).digest()
    )

    envelope = {
        "secure":       True,
        "sessionId":    session["sessionId"],
        "sessionToken": session["sessionToken"],
        "nonce":        nonce,
        "timestamp":    ts,
        "iv":           iv_b64,
        "ciphertext":   ct_b64,
        "signature":    sig,
    }

    resp = http.post(
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(envelope),
    )

    if resp.status_code in (401, 403) and retry < 1:
        logger.warning(f"[Outlook] {resp.status_code}, làm mới phiên bảo mật rồi thử lại...")
        with _sec_session_lock:
            _sec_session = None
        return _secure_post(http, url, payload, retry + 1)

    if resp.status_code != 200:
        raise OutlookClientError(
            f"secure_post {url} HTTP {resp.status_code}: {resp.text[:200]}"
        )
    return resp.json()


# ============================================================
# 账号文件读写
# ============================================================

def _parse_accounts_file(path: Path) -> list[OutlookAccount]:
    """Parse tài khoản từ file văn bản thuần, chỉ dùng khi import_to_db."""
    if not path.exists():
        return []
    accounts: list[OutlookAccount] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----")
        # 支持 4 段或 6 段格式
        if len(parts) == 4:
            email, password, client_id, refresh_token = (p.strip() for p in parts)
            accounts.append(OutlookAccount(email, password, client_id, refresh_token))
        elif len(parts) == 6:
            email, password, client_id, refresh_token, recovery_email, recovery_code = (p.strip() for p in parts)
            accounts.append(OutlookAccount(email, password, client_id, refresh_token, recovery_email, recovery_code))
        else:
            logger.warning(
                f"[Outlook] {path.name} dòng {lineno} không đúng định dạng (mong 4 hoặc 6 đoạn, thực tế {len(parts)}), đã bỏ qua"
            )
            continue
    return accounts


# ============================================================
# 公共接口：挑账号 / 取 OTP（统一走 DB）
# ============================================================

def pick_account() -> OutlookAccount:
    """
    Chọn nguyên tử một tài khoản Outlook status='available' và đánh dấu 'used' (giao dịch DB).
    An toàn khi nhiều luồng đồng thời.
    """
    from core.db import claim_next_outlook, outlook_pool_summary

    row = claim_next_outlook()
    if row is None:
        summary = outlook_pool_summary()
        raise OutlookClientError(
            f"Kho tài khoản Outlook không còn tài khoản: {summary}. "
            "Hãy nhập email mới trong kho email của WebUI."
        )

    account = OutlookAccount(
        email=row["email"],
        password=row["password"],
        client_id=row["client_id"],
        refresh_token=row["refresh_token"],
    )
    _CONTEXT_CACHE[_cache_key(account.email)] = account
    logger.info(f"[Outlook] Đã chọn tài khoản: {account.email}（DB id={row['id']}）")
    return account


def get_account_context(email: str) -> OutlookAccount | None:
    """Tra ngữ cảnh OutlookAccount theo email.

    Ưu tiên bản ghi kho email; tài khoản đã đăng ký nếu bản ghi kho bị xoá/chuyển thì khôi phục
    từ credential vật liệu Outlook đã lưu trên tài khoản. Nhờ đó kiểm tra sống và Codex Auth sau khi
    khởi động lại vẫn lấy OTP từ nguồn Outlook lúc đăng ký.
    """
    cache_key = _cache_key(email)
    if not cache_key:
        return None
    if cache_key in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[cache_key]
    from core.db import get_account_by_email, get_outlook_by_email

    pool_row = get_outlook_by_email(email)
    # 已注册账号的来源是权威值。即使本地 Outlook 池里残留了同名记录，
    # 也不能让一个实际来自 Remail/其它来源的账号误走 Outlook 取码。
    registered = get_account_by_email(email)
    registered_source = str((registered or {}).get("email_source") or "").strip().lower()
    registered_source = registered_source.replace(";", ",").replace("|", ",").split(",", 1)[0].strip()
    if registered_source and registered_source != "outlook":
        return None

    # 正常情况下优先使用邮箱池记录；邮箱池被清理、迁移，或记录不完整时，
    # 用已注册账号保存的同一份 Outlook 素材补齐。注册成功时 insert_account
    # 会把 password/client_id/refresh_token 持久化在账号记录里。
    row = pool_row or registered
    if row is None:
        return None

    def _first_value(*keys: str) -> str:
        for source_row in (row, registered if row is not registered else None):
            if not source_row:
                continue
            for key in keys:
                value = str(source_row.get(key) or "").strip()
                if value:
                    return value
        return ""

    email_value = _first_value("email") or str(email or "").strip()
    password = _first_value("password")
    client_id = _first_value("client_id", "clientId")
    refresh_token = _first_value("refresh_token", "refreshToken")
    if not (email_value and password and client_id and refresh_token):
        return None
    account = OutlookAccount(
        email=email_value,
        password=password,
        client_id=client_id,
        refresh_token=refresh_token,
        recovery_email=_first_value("recovery_email"),
        recovery_code=_first_value("recovery_code"),
    )
    _CONTEXT_CACHE[cache_key] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    """Cập nhật trạng thái tài khoản Outlook theo kết quả giai đoạn đăng ký: còn thử lại thì về available, đã tiêu thụ thì đánh dấu failed."""
    from core.db import release_outlook
    release_outlook(email, status=status, note=note)
    _CONTEXT_CACHE.pop(_cache_key(email), None)


def import_outlook_from_file(path: str | Path | None = None) -> tuple[int, int]:
    """Đọc một file văn bản tài khoản, nhập toàn bộ vào DB, trả (mới, đã có thì bỏ qua)."""
    from core.db import import_outlook_accounts
    p = Path(path or OUTLOOK_ACCOUNTS_FILE)
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    accounts = _parse_accounts_file(p)
    records = [
        {"email": a.email, "password": a.password, "client_id": a.client_id, "refresh_token": a.refresh_token}
        for a in accounts
    ]
    return import_outlook_accounts(records)


def import_outlook_from_text(text: str) -> tuple[int, int]:
    """Nhận một đoạn văn bản nhiều dòng (dán), nhập vào DB."""
    from core.db import import_outlook_accounts
    records = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("====")
        if len(parts) != 4:
            continue
        email, password, client_id, refresh_token = (p.strip() for p in parts)
        records.append({
            "email": email, "password": password,
            "client_id": client_id, "refresh_token": refresh_token,
        })
    return import_outlook_accounts(records)


# ============================================================
# 抓取邮件：Graph 失败回退 IMAP
# ============================================================


def _outlook_fetch_mode() -> str:
    return str(getattr(_email_cfg, "OUTLOOK_FETCH_MODE", "auto") or "auto").strip().lower()


def _is_remote_disabled_error(exc: Exception | str) -> bool:
    text = str(exc or "")
    return "DEPLOYMENT_DISABLED" in text or "HTTP 402" in text or "Payment required" in text


def _ms_http() -> CurlSession:
    s = CurlSession(impersonate=IMPERSONATE)
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })
    s.timeout = 30
    return s


def _token_looks_jwt(token: str) -> bool:
    return str(token or "").count(".") >= 2


def _ms_token_cache_key(account: OutlookAccount) -> str:
    return f"{account.email}|{account.client_id}|{account.refresh_token[:24]}"


def _is_oauth_fatal_error(text: str) -> bool:
    s = str(text or "")
    return (
        "invalid_grant" in s
        and (
            "AADSTS70000" in s
            or "AADSTS65001" in s
            or "unauthorized or expired" in s
            or "has not consented" in s
        )
    )


def _compact_oauth_error(text: str) -> str:
    s = str(text or "").replace("\\n", " ").strip()
    if "AADSTS70000" in s:
        return "AADSTS70000: refresh_token chưa uỷ quyền hoặc uỷ quyền đã hết hạn, không đổi được scope đọc thư Graph/IMAP đã yêu cầu"
    if "AADSTS65001" in s:
        return "AADSTS65001: client_id hiện tại chưa được người dùng uỷ quyền, không truy cập được tài nguyên này"
    return s[:240]


def _ms_token_fatal_reason(account: OutlookAccount) -> str | None:
    key = _ms_token_cache_key(account)
    cached = _MS_TOKEN_FATAL_CACHE.get(key)
    if not cached:
        return None
    reason, expires_at = cached
    if expires_at > time.time():
        return reason
    _MS_TOKEN_FATAL_CACHE.pop(key, None)
    return None


def _decode_email_header(header_value: str | None) -> str:
    if not header_value:
        return ""
    out = []
    for part, charset in decode_header(header_value):
        if isinstance(part, bytes):
            try:
                out.append(part.decode(charset or "utf-8", errors="replace"))
            except Exception:
                out.append(part.decode("utf-8", errors="replace"))
        else:
            out.append(str(part))
    return " ".join(out)


def _get_msg_text(msg) -> str:
    if msg.is_multipart():
        text_parts = []
        html_part = ""
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp:
                continue
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ctype == "text/plain":
                text_parts.append(text)
            elif ctype == "text/html" and not html_part:
                html_part = text
        return "\n".join(text_parts) if text_parts else html_part

    try:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
    except Exception:
        pass
    return str(msg.get_payload() or "")


def _imap_msg_to_dict(msg) -> dict:
    subject = _decode_email_header(msg.get("Subject") or msg.get("subject") or "")
    from_ = _decode_email_header(msg.get("From") or msg.get("from") or "")
    to_ = _decode_email_header(msg.get("To") or msg.get("to") or "")
    body = _get_msg_text(msg)
    date_raw = msg.get("Date") or msg.get("date") or ""
    ts_str = ""
    if date_raw:
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts_str = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            ts_str = str(date_raw)
    return {
        "id": msg.get("Message-ID") or msg.get("Message-Id") or "",
        "subject": subject,
        "from": from_,
        "to": to_,
        "fromEmail": from_,
        "fromName": from_,
        "sendEmail": from_,
        "receivedDateTime": ts_str,
        "date": ts_str,
        "bodyPreview": body,
        "content": body,
        "body": body,
        "html": body,
        "text": body,
    }


def _ms_access_token(
    account: OutlookAccount,
    http: CurlSession | None = None,
    preferred_kind: str | None = None,
) -> tuple[str, str]:
    """Đổi refresh_token lấy access_token đọc được thư.

    Trả (token, kind):
      - kind="graph": truy cập được graph.microsoft.com (tài khoản Outlook cá nhân đôi khi trả opaque token, không nhất thiết là JWT)
      - kind="outlook": token Outlook REST, truy cập được outlook.office.com/api/v2.0
    """
    preferred_kind = str(preferred_kind or "").strip().lower() or None
    if preferred_kind not in (None, "graph", "outlook"):
        preferred_kind = None
    cache_key = _ms_token_cache_key(account)
    fatal_reason = _ms_token_fatal_reason(account)
    if fatal_reason:
        raise OutlookClientError(f"Microsoft OAuth đổi refresh_token lấy token thất bại: {fatal_reason}")
    cached = _MS_TOKEN_CACHE.get(cache_key)
    now = time.time()
    if cached and cached[1] - now > 120:
        token_kind, token = cached[0].split(":", 1) if ":" in cached[0] else ("graph", cached[0])
        if preferred_kind is None or token_kind == preferred_kind:
            return token, token_kind

    own_http = http is None
    http = http or _ms_http()
    try:
        attempts = [
            (
                "graph",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                {
                    "client_id": account.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": account.refresh_token,
                    "scope": "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read offline_access",
                },
            ),
            (
                "graph",
                "https://login.microsoftonline.com/common/oauth2/token",
                {
                    "client_id": account.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": account.refresh_token,
                    "resource": "https://graph.microsoft.com",
                },
            ),
            (
                "outlook",
                "https://login.microsoftonline.com/common/oauth2/token",
                {
                    "client_id": account.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": account.refresh_token,
                    "resource": "https://outlook.office.com",
                },
            ),
            (
                "outlook",
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                {
                    "client_id": account.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": account.refresh_token,
                    "scope": "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access",
                },
            ),
        ]
        if preferred_kind:
            attempts = [item for item in attempts if item[0] == preferred_kind]
        last_text = ""
        for kind, url, payload in attempts:
            resp = http.post(
                url,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                data=urlencode(payload),
            )
            text = resp.text or ""
            last_text = text[:500]
            data = {}
            try:
                data = resp.json()
            except Exception:
                pass
            if resp.status_code == 200 and isinstance(data, dict) and data.get("access_token"):
                expires_in = int(data.get("expires_in") or 3600)
                token = str(data["access_token"])
                # Microsoft Graph 对个人 Outlook/MSA 账号可能返回 opaque access_token，
                # 不一定是 JWT；Graph 仍然接受。不能用是否包含 "." 判断是否可用。
                _MS_TOKEN_CACHE[cache_key] = (f"{kind}:{token}", now + max(300, expires_in - 60))
                logger.debug("[Outlook] Lấy token Microsoft thành công kind=%s jwt=%s", kind, _token_looks_jwt(token))
                return token, kind
        if _is_oauth_fatal_error(last_text):
            reason = _compact_oauth_error(last_text)
            _MS_TOKEN_FATAL_CACHE[cache_key] = (reason, time.time() + 600)
            raise OutlookClientError(f"Microsoft OAuth đổi refresh_token lấy token thất bại: {reason}")
        raise OutlookClientError(f"Microsoft OAuth đổi refresh_token lấy token thất bại: {last_text}")
    finally:
        if own_http:
            http.close()


def _live_imap_access_token(account: OutlookAccount, http: CurlSession | None = None) -> str:
    """Làm mới access_token IMAP(New) qua endpoint OAuth Outlook/Live.

    Một số refresh_token vật liệu Outlook mua ngoài không đổi được
    scope Graph/IMAP tại login.microsoftonline.com, nhưng có thể qua login.live.com/oauth20_token.srf không kèm scope
    để lấy token IMAP.AccessAsUser.All; nhiều công cụ gọi là "IMAP (New)".
    """
    cache_key = _ms_token_cache_key(account) + "|live_imap"
    cached = _MS_TOKEN_CACHE.get(cache_key)
    now = time.time()
    if cached and cached[1] - now > 120:
        token_kind, token = cached[0].split(":", 1) if ":" in cached[0] else ("live_imap", cached[0])
        if token_kind == "live_imap":
            return token

    own_http = http is None
    http = http or _ms_http()
    try:
        resp = http.post(
            "https://login.live.com/oauth20_token.srf",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            data=urlencode({
                "client_id": account.client_id,
                "grant_type": "refresh_token",
                "refresh_token": account.refresh_token,
            }),
        )
        text = resp.text or ""
        data = {}
        try:
            data = resp.json()
        except Exception:
            pass
        token = str((data or {}).get("access_token") or "")
        if resp.status_code == 200 and token:
            expires_in = int((data or {}).get("expires_in") or 3600)
            _MS_TOKEN_CACHE[cache_key] = (f"live_imap:{token}", now + max(300, expires_in - 60))
            scope = str((data or {}).get("scope") or "")
            logger.debug("[Outlook] Lấy token Live IMAP(New) thành công scope=%s", scope[:160])
            return token
        raise OutlookClientError(f"Live IMAP(New) đổi refresh_token lấy token thất bại: {text[:500]}")
    finally:
        if own_http:
            http.close()


def _normalize_ms_message(m: dict) -> dict:
    sender = (((m.get("from") or {}).get("emailAddress") or {}) if isinstance(m.get("from"), dict) else {})
    body = m.get("body") if isinstance(m.get("body"), dict) else {}
    content = body.get("content") if isinstance(body, dict) else ""
    received = m.get("receivedDateTime") or m.get("DateTimeReceived") or m.get("date") or ""
    return {
        "id": m.get("id") or m.get("Id") or "",
        "subject": m.get("subject") or m.get("Subject") or "",
        "from": m.get("from") or m.get("From") or {},
        "fromEmail": sender.get("address") or sender.get("Address") or "",
        "fromName": sender.get("name") or sender.get("Name") or "",
        "receivedDateTime": received,
        "date": received,
        "bodyPreview": m.get("bodyPreview") or m.get("BodyPreview") or "",
        "content": content or "",
        "body": content or "",
        "html": content or "",
    }


def _fetch_graph_messages(http: CurlSession, token: str) -> list[dict]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "Prefer": 'outlook.body-content-type="html"',
    }
    url = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
    params = {
        "$top": "20",
        "$orderby": "receivedDateTime desc",
        "$select": "id,subject,from,receivedDateTime,bodyPreview,body",
    }
    resp = http.get(url, headers=headers, params=params)
    text = resp.text or ""
    if resp.status_code != 200:
        raise OutlookClientError(f"Microsoft Graph messages HTTP {resp.status_code}: {text[:500]}")
    data = resp.json()
    rows = data.get("value") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise OutlookClientError(f"Phản hồi Microsoft Graph thiếu value: {str(data)[:300]}")
    out = [_normalize_ms_message(m) for m in rows if isinstance(m, dict)]
    for item in out:
        item["_fetch_source"] = "graph"
    return out


def _fetch_outlook_rest_messages(http: CurlSession, token: str) -> list[dict]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    url = "https://outlook.office.com/api/v2.0/me/mailfolders/inbox/messages"
    attempts = [
        {
            "$top": "20",
            "$orderby": "ReceivedDateTime desc",
            "$select": "Id,Subject,From,ReceivedDateTime,BodyPreview,Body",
        },
        {
            "$top": "20",
            "$orderby": "DateTimeReceived desc",
            "$select": "Id,Subject,From,DateTimeReceived,BodyPreview,Body",
        },
        {"$top": "20"},
    ]
    last_text = ""
    data = None
    for params in attempts:
        resp = http.get(url, headers=headers, params=params)
        text = resp.text or ""
        last_text = text[:500]
        if resp.status_code == 200:
            data = resp.json()
            break
        # 字段名不兼容时自动降级下一套参数。
        if resp.status_code == 400 and ("Could not find a property" in text or "ParseUri" in text):
            logger.debug("[Outlook] Tham số Outlook REST không tương thích, hạ cấp rồi thử lại: %s", text[:220])
            continue
        raise OutlookClientError(f"Outlook REST messages HTTP {resp.status_code}: {text[:500]}")
    if data is None:
        raise OutlookClientError(f"Outlook REST messages thất bại: {last_text}")
    rows = data.get("value") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise OutlookClientError(f"Phản hồi Outlook REST thiếu value: {str(data)[:300]}")
    out = []
    for m in rows:
        if not isinstance(m, dict):
            continue
        # Outlook REST 字段转 Graph 风格；不同版本字段大小写不同。
        from_obj = m.get("From") or m.get("from") if isinstance(m.get("From") or m.get("from"), dict) else {}
        email_addr = from_obj.get("EmailAddress") or from_obj.get("emailAddress") if isinstance(from_obj, dict) else {}
        if not isinstance(email_addr, dict):
            email_addr = {}
        body_obj = m.get("Body") or m.get("body") if isinstance(m.get("Body") or m.get("body"), dict) else {}
        received = m.get("ReceivedDateTime") or m.get("DateTimeReceived") or m.get("receivedDateTime") or ""
        out.append({
            "_fetch_source": "outlook_rest",
            "id": m.get("Id") or m.get("id") or "",
            "subject": m.get("Subject") or m.get("subject") or "",
            "from": {"emailAddress": {"address": email_addr.get("Address") or email_addr.get("address") or "", "name": email_addr.get("Name") or email_addr.get("name") or ""}},
            "fromEmail": email_addr.get("Address") or email_addr.get("address") or "",
            "fromName": email_addr.get("Name") or email_addr.get("name") or "",
            "receivedDateTime": received,
            "date": received,
            "bodyPreview": m.get("BodyPreview") or m.get("bodyPreview") or "",
            "content": body_obj.get("Content") or body_obj.get("content") or "",
            "body": body_obj.get("Content") or body_obj.get("content") or "",
            "html": body_obj.get("Content") or body_obj.get("content") or "",
        })
    logger.debug(f"[Outlook] Outlook REST trực tiếp nhận {len(out)} thư")
    return out


def _fetch_imap_direct_messages(account: OutlookAccount) -> list[dict]:
    """Đọc thư mới nhất Inbox Outlook qua IMAP XOAUTH2 cục bộ."""
    http = _ms_http()
    mail: imaplib.IMAP4_SSL | None = None
    try:
        try:
            token = _live_imap_access_token(account, http=http)
            token_source = "live_imap_new"
        except Exception as live_exc:
            logger.debug("[Outlook] Lấy token Live IMAP(New) thất bại, thử token Entra IMAP: %s", str(live_exc)[:220])
            token, _kind = _ms_access_token(account, http=http, preferred_kind="outlook")
            token_source = "entra_outlook"
        auth_string = f"user={account.email}\x01auth=Bearer {token}\x01\x01"
        mail = imaplib.IMAP4_SSL("outlook.office365.com", 993)
        mail.authenticate("XOAUTH2", lambda _challenge: auth_string.encode("utf-8"))
        status, _data = mail.select("INBOX")
        if status != "OK":
            raise OutlookClientError(f"IMAP select INBOX thất bại: {status}")

        status, msg_ids = mail.search(None, "ALL")
        if status != "OK":
            raise OutlookClientError(f"IMAP search thất bại: {status}")
        ids = msg_ids[0].split() if msg_ids and msg_ids[0] else []
        if not ids:
            logger.debug("[Outlook] Hộp thư IMAP cục bộ trống")
            return []

        out = []
        for mid in ids[-20:]:
            status, data = mail.fetch(mid, "(RFC822)")
            if status != "OK" or not data:
                continue
            try:
                raw = data[0][1]
                if not isinstance(raw, (bytes, bytearray)):
                    continue
                msg = email_lib.message_from_bytes(raw)
                item = _imap_msg_to_dict(msg)
                item["_fetch_source"] = "imap_new" if token_source == "live_imap_new" else "imap_entra_outlook"
                out.append(item)
            except Exception as exc:
                logger.debug("[Outlook] Parse thư IMAP cục bộ thất bại mid=%s: %s", mid, exc)
        if token_source == "live_imap_new":
            logger.info("[Outlook] IMAP(New) cục bộ trực tiếp nhận %s thư", len(out))
        else:
            logger.info("[Outlook] IMAP cục bộ trực tiếp nhận %s thư token_source=%s", len(out), token_source)
        return out
    except Exception as exc:
        logger.warning("[Outlook] IMAP cục bộ trực tiếp thất bại: %s: %s", type(exc).__name__, exc)
        return []
    finally:
        try:
            if mail is not None:
                mail.logout()
        except Exception:
            pass
        http.close()


def _fetch_via_graph_direct(account: OutlookAccount) -> list[dict]:
    """Đọc thư mới nhất Inbox qua Microsoft API trực tiếp; Graph không tương thích thì tự chuyển Outlook REST."""
    fatal_reason = _ms_token_fatal_reason(account)
    if fatal_reason:
        logger.debug("[Outlook] Bỏ qua Graph/REST: OAuth đã biết không dùng được: %s", fatal_reason)
        return []
    http = _ms_http()
    try:
        token, kind = _ms_access_token(account, http=http)
        if kind == "graph":
            try:
                out = _fetch_graph_messages(http, token)
                logger.debug(f"[Outlook] Microsoft Graph trực tiếp nhận {len(out)} thư")
                return out
            except Exception as exc:
                logger.warning(f"[Outlook] Đọc Microsoft Graph thất bại, thử Outlook REST: {type(exc).__name__}: {exc}")
                # 重新取 Outlook REST token。注意不能继续复用 Graph token；
                # Graph token 的 audience 是 graph.microsoft.com，拿去请求
                # outlook.office.com/api/v2.0 会返回 401。
                _MS_TOKEN_CACHE.pop(f"{account.email}|{account.client_id}|{account.refresh_token[:24]}", None)
                token, kind = _ms_access_token(account, http=http, preferred_kind="outlook")
        out = _fetch_outlook_rest_messages(http, token)
        logger.debug(f"[Outlook] Outlook REST trực tiếp nhận {len(out)} thư")
        return out
    except Exception as exc:
        logger.warning(f"[Outlook] Microsoft/Outlook trực tiếp thất bại: {type(exc).__name__}: {exc}")
        return []
    finally:
        http.close()


def _fetch_via(session: CurlSession, protocol: str, account: OutlookAccount) -> list[dict]:
    """
    Kéo hộp thư, trả danh sách emails.

    - remote: mail.chatai.codes /api/fetch-graph|imap
    - direct: Microsoft Graph trực tiếp
    - auto: remote còn dùng thì dùng remote; remote 402/DEPLOYMENT_DISABLED thì tự chuyển Graph trực tiếp
    """
    global _REMOTE_DISABLED
    mode = _outlook_fetch_mode()

    if mode in ("direct", "graph", "graph_direct", "msgraph"):
        if protocol == "graph":
            return _fetch_via_graph_direct(account)
        if protocol == "imap":
            return _fetch_imap_direct_messages(account)
        return []

    if mode == "auto" and _REMOTE_DISABLED:
        if protocol == "graph":
            return _fetch_via_graph_direct(account)
        if protocol == "imap":
            return _fetch_imap_direct_messages(account)
        return []

    url = f"{OUTLOOK_API_BASE.rstrip('/')}/api/fetch-{protocol}"
    payload = {
        "email":        account.email,
        "clientId":     account.client_id,
        "refreshToken": account.refresh_token,
        "keyword":      "",
        "limit":        10,
        "sender":       "",
    }
    try:
        data = _secure_post(session, url, payload)
    except OutlookClientError as exc:
        logger.warning(f"[Outlook] {protocol} yêu cầu thất bại: {exc}")
        if mode == "auto" and _is_remote_disabled_error(exc):
            _REMOTE_DISABLED = True
            logger.warning("[Outlook] Dịch vụ lấy thư từ xa đã bị tắt, tự chuyển sang Microsoft Graph trực tiếp")
            if protocol == "graph":
                return _fetch_via_graph_direct(account)
        return []
    except Exception as exc:
        logger.warning(f"[Outlook] {protocol} yêu cầu lỗi: {type(exc).__name__}: {exc}")
        return []

    if not data.get("success"):
        logger.debug(f"[Outlook] {protocol} success=False: {data.get('error')}")
        return []

    emails = data.get("emails") or []
    source = f"remote_{protocol}"
    for item in emails:
        if isinstance(item, dict):
            item.setdefault("_fetch_source", source)
    logger.debug(f"[Outlook] {protocol} nhận {len(emails)} thư source={source}")
    return emails


# settle 机制默认值改为从 config 读取（OTP_SETTLE_SECONDS）
# 抓到第一封 OTP 后，再多等多少秒看是否有更晚到的邮件。
# 看到更晚的就重置 settle 计时；连续无新邮件 settle 秒后才返回。


def fetch_otp_with_account(
    account: OutlookAccount,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    subject_includes: list[str] | None = None,
    subject_excludes: list[str] | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    Kéo OTP từ OutlookAccount cho sẵn (có client_id / refresh_token).
    Dùng khi account không ở DB / không trong cache bộ nhớ (ví dụ script ngoài gọi).
    """
    _CONTEXT_CACHE[_cache_key(account.email)] = account
    return fetch_latest_otp(
        account.email,
        after_ts=after_ts,
        max_wait=max_wait,
        poll_interval=poll_interval,
        subject_includes=subject_includes,
        subject_excludes=subject_excludes,
        settle_seconds=settle_seconds,
    )


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    subject_includes: list[str] | None = None,
    subject_excludes: list[str] | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    Poll OTP qua hai giao thức, quy tắc:
        - Thử Graph trước, thất bại/rỗng thì lùi IMAP
        - Gộp thư hai phía, bỏ trùng, sắp thời gian giảm dần
        - Lấy thư OpenAI **mới nhất** để rút OTP
        - **Cơ chế settle**: sau thư đầu chờ thêm settle_seconds xem có thư đến muộn hơn,
          có thì dùng bản mới nhất; hết thư mới mới trả. Tránh lấy OTP cũ bị server cập nhật giữa chừng.

    Args:
        email: email đích
        after_ts: mốc UTC. Chỉ xem thư mới hơn mốc này
        max_wait / poll_interval: mặc định lấy từ config
        subject_includes / subject_excludes: lọc subject, không bắt buộc
        settle_seconds: sau thư đầu chờ thêm bao nhiêu giây xem có bản mới hơn (mặc định 8s)
    """
    account = get_account_context(email)
    if account is None:
        raise OutlookClientError(f"Không tìm thấy {email} ngữ cảnh tài khoản, không lấy được OTP")

    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else OTP_SETTLE_SECONDS
    session = _http_session()

    logger.info(
        f"[Outlook] Bắt đầu poll {email} hộp thư (mode={_outlook_fetch_mode()}, Graph + IMAP nối thẳng local, REST dự phòng), "
        f"tối đa {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s..."
    )

    # settle 状态机
    best_otp: str | None = None       # 当前看到的最新 OTP
    best_ts: float = 0.0              # 它的邮件时间戳
    best_subject: str = ""
    best_protocol: str = ""
    best_source: str = ""
    settle_until: float | None = None # 抓到第一封后，等到这个时刻才返回
    last_diag_log = 0.0

    while time.time() < deadline:
        # 每轮都重新拉，因为可能有新邮件，也可能旧邮件因延迟才出现
        all_candidates: list[tuple[str, dict, float, str]] = []
        for protocol in ("graph", "imap"):
            emails = _fetch_via(session, protocol, account)
            for item in emails:
                ts = _parse_email_ts(item) or 0.0
                source = str(item.get("_fetch_source") or protocol) if isinstance(item, dict) else protocol
                all_candidates.append((protocol, item, ts, source))

        # 按时间降序，最新的在前
        all_candidates.sort(key=lambda x: x[2], reverse=True)

        if all_candidates and not best_otp and time.time() - last_diag_log > 12:
            diag = []
            for protocol, item, ts, source in all_candidates[:5]:
                subject = str(item.get("subject") or "")[:90]
                date = item.get("date") or item.get("receivedDateTime") or ""
                is_openai = looks_like_openai_email(item)
                after_ok = True if after_ts is None else _is_after(item, after_ts)
                otp = extract_otp(item)
                diag.append({
                    "p": source,
                    "date": date,
                    "openai": is_openai,
                    "after": after_ok,
                    "otp": bool(otp),
                    "subject": subject,
                })
            logger.info("[Outlook] Chẩn đoán thư top=%s", diag)
            last_diag_log = time.time()

        # 找出本轮"最新一封通过过滤的 OpenAI 邮件"
        for protocol, item, ts, source in all_candidates:
            if not looks_like_openai_email(item):
                continue

            subject = (item.get("subject") or "")
            subject_lower = subject.lower()
            if subject_includes and not any(s.lower() in subject_lower for s in subject_includes):
                continue
            if subject_excludes and any(s.lower() in subject_lower for s in subject_excludes):
                continue
            if after_ts is not None and not _is_after(item, after_ts):
                continue

            otp = extract_otp(item)
            if not otp:
                continue

            # 已锁定一个候选；如果新看到的更晚，则替换并重置 settle 倒计时
            if ts > best_ts:
                if best_otp:
                    logger.info(
                        f"[Outlook] Thấy OTP muộn hơn={otp} (ts={item.get('date') or item.get('receivedDateTime')}, source={source}), "
                        f"thay mã trước đó {best_otp}, đặt lại đồng hồ settle"
                    )
                else:
                    logger.info(
                        f"[Outlook] Khoá OTP lần đầu={otp}, source={source}, ts={item.get('date') or item.get('receivedDateTime')}, "
                        f"subject={subject!r}, chờ {settle}s xem có thư muộn hơn không..."
                    )
                best_otp = otp
                best_ts = ts
                best_subject = subject
                best_protocol = protocol
                best_source = source
                settle_until = time.time() + settle
            break  # 只关心本轮最新那一封

        # 判断是否可以返回
        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[Outlook] settle xong, trả OTP={best_otp}, source={best_source or best_protocol}, protocol={best_protocol}, "
                f"subject={best_subject!r}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp:
            logger.info(
                f"[Outlook] Đã khoá OTP ứng viên={best_otp}, đang chờ settle"
                f" (settle còn ~{int(settle_until - now)}s, tổng còn {remaining}s)..."
            )
        else:
            logger.info(
                f"[Outlook] Chưa nhận thư OpenAI đúng điều kiện, {interval}s nữa thử lại (còn {remaining}s)..."
            )
        time.sleep(interval)

    # 超时但已经锁定过候选（settle 没等到结束就到 deadline 了）
    if best_otp:
        logger.warning(
            f"[Outlook] Hết hạn tổng nhưng đã có ứng viên, trả OTP={best_otp}, source={best_source or best_protocol} (subject={best_subject!r})"
        )
        return best_otp

    raise OutlookClientError(
        f"Chờ {email} OTP quá hạn (>{max_wait or _email_cfg.OTP_MAX_WAIT}s）。"
        f"Có thể: refresh_token hết hạn / email bị OpenAI chặn / IP không qua kiểm soát rủi ro."
    )


# 时差容忍：只保留极小容忍。
# 重发 OTP 时上一封旧码常常只早 10~20 秒；若容忍 30 秒，会把上一轮旧码误判为新码。
_OTP_CLOCK_SKEW_TOLERANCE = 2


def _parse_email_ts(item: dict) -> float | None:
    """Parse trường thời gian thư thành timestamp UTC; không parse được thì trả None."""
    import calendar
    raw = (
        item.get("date")
        or item.get("receivedDateTime")
        or item.get("createTime")
        or item.get("receivedAt")
        or ""
    )
    if not raw:
        return None

    formats = (
        "%Y-%m-%dT%H:%M:%SZ",       # Graph: 2026-05-08T02:47:00Z
        "%Y-%m-%dT%H:%M:%S.%fZ",    # Graph 含微秒
        "%Y-%m-%d %H:%M:%S",        # IMAP / 自定义
        "%a, %d %b %Y %H:%M:%S %z", # RFC 2822 with tz
    )
    for fmt in formats:
        try:
            if fmt.endswith("%z"):
                from datetime import datetime
                return datetime.strptime(raw, fmt).timestamp()
            base_fmt = fmt[: fmt.index("%f") - 1] if "%f" in fmt else fmt
            return float(calendar.timegm(time.strptime(raw[:19] if len(raw) >= 19 else raw, base_fmt)))
        except Exception:
            continue
    return None


def _is_after(item: dict, after_ts: float) -> bool:
    """Xem thời gian thư có muộn hơn after_ts không. Chỉ dung sai 30 giây để khỏi nuốt OTP cũ."""
    ts = _parse_email_ts(item)
    if ts is None:
        # 时间字段缺失/解析不出 → 放过（不要因解析失败就丢邮件）
        return True
    return ts >= after_ts - _OTP_CLOCK_SKEW_TOLERANCE
