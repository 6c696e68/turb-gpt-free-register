# -*- coding: utf-8 -*-
"""
Module ủy quyền Codex OAuth sau khi đăng ký thành công (cải tạo 2026-06-15: session hoàn toàn mới + nhận mã SMS).

Phương án cũ "tái sử dụng session đã đăng nhập lúc đăng ký" sẽ kẹt ở /choose-an-account (React SPA không parse được
trường có thể submit). Phương án mới đổi sang dùng **session sạch hoàn toàn mới** đăng nhập từ đầu, đi theo đường chống gian lận chuẩn của OpenAI,
xác minh số điện thoại nhờ nền tảng nhận mã tự động nhận SMS; hiện qua core.sms_provider hỗ trợ GrizzlySMS và dịch vụ lấy số L cục bộ
định nghĩa trong L_API.md.

Chuỗi API đầy đủ do page/type/continue_url mà Auth trả về quyết định động:
    - Sau khi gửi email có thể vào trang mật khẩu, OTP email hoặc trang xác minh khác
    - Sau mật khẩu có thể vào MFA/TOTP, OTP email, xác minh số điện thoại hoặc ủy quyền trực tiếp
    - Sau OTP email/MFA cũng chỉ thực hiện xác minh số điện thoại khi server yêu cầu rõ ràng
    - Cuối cùng chọn workspace / theo redirect tới localhost:1455/auth/callback

Logic đổi code lấy token / lưu vào SQLite sau khi có code (exchange_codex_token /
build_codex_storage / save_codex_credential) vẫn giữ quy trình cũ.
"""
import base64
import hashlib
import json
import logging
import random
import secrets
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse, parse_qs, quote

import pyotp

# Truy cập config theo thuộc tính module, hỗ trợ WebUI hot-reload (config.reload_all()).
# Hằng số cấp giao thức (CLIENT_ID/URL/SCOPE/OUTPUT_DIRNAME) dù không đổi, vẫn đọc thống nhất từ _cfg,
# Như vậy sau reload có hiệu lực ngay, không cần tách hai bộ import.
from config import codex as _cfg
from core.session import BrowserSession
from core.humanize import delay as human_delay
from core.openai_auth import (
    _is_transient_network_error,
    _is_retryable_authorize_error,
    _reset_retryable_circuit,
    _extract_error_code,
    detect_account_unusable_response_body,
    AccountUnusableError,
    request_sentinel_token,
    build_sentinel_header,
)
from core import db
from core import sms_provider
from curl_cffi import requests as curl_requests

logger = logging.getLogger(__name__)

# Số lần nhảy tối đa khi theo chuỗi chuyển hướng, chống vòng lặp vô hạn
_MAX_REDIRECTS = 15

# Tham số retry lỗi tạm thời tầng mạng (proxy rung / TLS handshake thất bại / reset), căn chỉnh với openai_auth.follow_authorize
_NET_MAX_ATTEMPTS = 3
_NET_BACKOFF_BASE = 2.0

# Đôi khi tồn tại race condition ngắn giữa việc Auth response thiết lập cookie và workspace/select tiếp theo.
_WORKSPACE_COOKIE_WAIT_SECONDS = 4.0
_WORKSPACE_POLL_INTERVAL_SECONDS = 0.2


def _with_net_retry(label: str, fn):
    """
    Bọc thử lại cho các lỗi mạng tạm thời (TLS/proxy/timeout/reset).
    Lỗi không tạm thời (4xx nghiệp vụ v.v.) ném trực tiếp. Tối đa _NET_MAX_ATTEMPTS lần.
    """
    last_exc = None
    for attempt in range(1, _NET_MAX_ATTEMPTS + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if not _is_transient_network_error(exc):
                raise
            if attempt >= _NET_MAX_ATTEMPTS:
                break
            backoff = _NET_BACKOFF_BASE ** (attempt - 1)
            logger.warning(
                f"[Codex] {label} lỗi mạng tạm thời ({type(exc).__name__}: {str(exc)[:120]})，"
                f"{backoff:.1f}s thử lại sau (Thử {attempt}/{_NET_MAX_ATTEMPTS})..."
            )
            time.sleep(backoff)
    raise last_exc if last_exc else RuntimeError(f"[Codex] {label} thử lại hết nhưng không có bản ghi bất thường")


def _with_auth_navigation_retry(session: BrowserSession, label: str, fn):
    """Thử lại khi Auth document trả 403/429/5xx, và giữ nguyên Cookie/ngữ cảnh thiết bị hiện tại."""
    last_exc = None
    for attempt in range(1, _NET_MAX_ATTEMPTS + 1):
        try:
            resp = fn()
            status = int(getattr(resp, "status_code", 0) or 0)
            if status >= 400:
                error = RuntimeError(
                    f"{label} status={status}, body={(getattr(resp, 'text', '') or '')[:180]}"
                )
                error.response = resp
                raise error
            return resp
        except Exception as exc:
            last_exc = exc
            if not _is_retryable_authorize_error(exc) or attempt >= _NET_MAX_ATTEMPTS:
                raise
            # 403 của Cloudflare thường cập nhật __cf_bm cùng lúc. Chỉ dọn cầu chì cục bộ, tuyệt đối không
            # Tạo Session mới, nếu không Cookie vừa nhận và device/session ID thống nhất sẽ bị mất.
            _reset_retryable_circuit(session)
            backoff = _NET_BACKOFF_BASE ** (attempt - 1)
            logger.warning(
                "[Codex] %s thất bại tạm thời (%s/%s): %s: %s; "
                "giữ session/deviceId/CF Cookie hiện tại, thử lại sau %.1fs",
                label, attempt, _NET_MAX_ATTEMPTS, type(exc).__name__,
                str(exc)[:160], backoff,
            )
            time.sleep(backoff)
    raise last_exc if last_exc else RuntimeError(f"[Codex] {label} thử lại hết")


def _codex_auth_preflight(session: BrowserSession) -> None:
    """Chỉ làm nóng trước các miền Auth mà Codex thực sự phụ thuộc, không còn dùng trang chủ ChatGPT làm ngưỡng cứng."""
    headers = session.get_auth_navigate_headers(
        referer="", user_initiated=False, target_origin="https://auth.openai.com",
    )
    logger.info("[Codex][kiểm tra trước] Auth document (thống nhất session/deviceId)")
    _with_auth_navigation_retry(
        session,
        "auth document kiểm tra trước",
        lambda: session.get(
            "https://auth.openai.com/log-in",
            headers=headers,
            allow_redirects=True,
        ),
    )


def _codex_result(
    *,
    status: str,
    ok: bool = False,
    http_status: int | None = None,
    email: str | None = None,
    file_path: str | None = None,
    callback_url: str | None = None,
    message: str = "",
) -> dict:
    """Tạo kết quả có cấu trúc cùng dạng với flow_trigger._flow_result."""
    return {
        "status": status,
        "ok": ok,
        "http_status": http_status,
        "email": email,
        "file_path": file_path,
        "callback_url": callback_url,
        "message": message,
    }


def _account_registration_password(email: str) -> str:
    """Đọc mật khẩu đăng ký của tài khoản; nếu không tồn tại thì trả về chuỗi rỗng."""
    try:
        acc = db.get_account_by_email(email)
        if not acc:
            return ""
        extra_raw = acc.get("extra_json")
        extra = {}
        if isinstance(extra_raw, str) and extra_raw.strip():
            try:
                extra = json.loads(extra_raw)
            except Exception:
                extra = {}
        elif isinstance(extra_raw, dict):
            extra = extra_raw
        return str(extra.get("registration_password") or acc.get("registration_password") or "").strip()
    except Exception:
        return ""


def _account_totp_secret(email: str) -> str:
    """Đọc khóa 2FA đã bật của tài khoản; nếu không tồn tại thì trả về chuỗi rỗng."""
    try:
        acc = db.get_account_by_email(email)
        if not acc:
            return ""
        return str(acc.get("totp_secret") or "").strip()
    except Exception:
        return ""


def _account_totp_code(email: str) -> str:
    secret = _account_totp_secret(email)
    return pyotp.TOTP(secret).now() if secret else ""


# ============================================================
# PKCE / state (đối chiếu CLIProxyAPI pkce.go)
# ============================================================

def _generate_pkce() -> tuple[str, str]:
    """Sinh cặp mã PKCE: verifier=base64url(96 byte), challenge=base64url(sha256(verifier))."""
    verifier_bytes = secrets.token_bytes(96)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _generate_state() -> str:
    """Tạo chuỗi ngẫu nhiên OAuth state, chống CSRF."""
    return secrets.token_urlsafe(32)


def _build_authorize_url(state: str, code_challenge: str, prompt: str = "login") -> str:
    """Ghép URL ủy quyền Codex theo bộ tham số của CLIProxyAPI openai_auth.go."""
    params = {
        "client_id": _cfg.CODEX_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": _cfg.CODEX_REDIRECT_URI,
        "scope": _cfg.CODEX_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": prompt,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    return f"{_cfg.CODEX_AUTH_URL}?{urlencode(params)}"


def _ensure_oai_context_url(auth_url: str, session: BrowserSession) -> str:
    """Bổ sung tham số ngữ cảnh cùng nguồn phía frontend trên URL ủy quyền OAuth Codex, giữ oai-did liên tục."""
    try:
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        changed = False
        additions = {
            "ext-oai-did": session.device_id,
            "auth_session_logging_id": session.auth_session_logging_id,
            "screen_hint": "login_or_signup",
        }
        for key, value in additions.items():
            if not params.get(key):
                params[key] = [value]
                changed = True
        if not changed:
            return auth_url
        query = urlencode(params, doseq=True)
        return parsed._replace(query=query).geturl()
    except Exception:
        return auth_url


# ============================================================
# Giao diện quản lý CPA: địa chỉ ủy quyền do CPA tạo, callback thành công gửi cho CPA
# ============================================================

def _codex_auth_url_source() -> str:
    return str(getattr(_cfg, "CODEX_AUTH_URL_SOURCE", "cpa") or "cpa").strip().lower()


def _cpa_management_origin() -> str:
    raw = str(getattr(_cfg, "CPA_MANAGEMENT_URL", "") or "").strip()
    if not raw:
        raise RuntimeError("[Codex][CPA] chưa cấu hình CPA_MANAGEMENT_URL")
    try:
        parsed = urlparse(raw)
    except Exception as exc:
        raise RuntimeError(f"[Codex][CPA] CPA_MANAGEMENT_URL Định dạng không hợp lệ: {raw}") from exc
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(f"[Codex][CPA] CPA_MANAGEMENT_URL Định dạng không hợp lệ: {raw}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _cpa_management_key() -> str:
    key = str(getattr(_cfg, "CPA_MANAGEMENT_KEY", "") or "").strip()
    if not key:
        raise RuntimeError("[Codex][CPA] chưa cấu hình CPA_MANAGEMENT_KEY")
    return key


def _cpa_request_json(method: str, path: str, body: dict | None = None) -> dict:
    """Gọi API quản lý CPA, tương thích giao thức /v0/management/* của FlowPilot."""
    origin = _cpa_management_origin()
    key = _cpa_management_key()
    timeout = int(getattr(_cfg, "CPA_REQUEST_TIMEOUT", 30) or 30)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
        "X-Management-Key": key,
    }
    url = f"{origin}{path}"
    session = curl_requests.Session()
    try:
        resp = session.request(
            method.upper(),
            url,
            headers=headers,
            data=None if body is None else json.dumps(body),
            timeout=timeout,
        )
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = ""
            if isinstance(payload, dict):
                msg = payload.get("error") or payload.get("message") or payload.get("detail") or payload.get("reason") or ""
            raise RuntimeError(
                f"[Codex][CPA] API quản trị thất bại {method.upper()} {path} status={resp.status_code}: "
                f"{msg or (resp.text or '')[:300]}"
            )
        return payload if isinstance(payload, dict) else {}
    finally:
        try:
            session.close()
        except Exception:
            pass


def _sub2_codex_base() -> str:
    from config import sub2api as _sub2_cfg
    raw = str(
        getattr(_sub2_cfg, "SUB2API_API_BASE", "")
        or getattr(_sub2_cfg, "SUB2_CODEX_API_BASE", "")
        or ""
    ).strip().rstrip("/")
    if not raw:
        raise RuntimeError("[Codex][sub2] chưa cấu hình SUB2API_API_BASE")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(f"[Codex][sub2] SUB2API_API_BASE Định dạng không hợp lệ: {raw}")
    return raw


def _sub2_codex_headers() -> dict:
    from config import sub2api as _sub2_cfg
    token = str(getattr(_sub2_cfg, "SUB2_CODEX_API_TOKEN", "") or getattr(_sub2_cfg, "SUB2API_API_KEY", "") or getattr(_sub2_cfg, "SUB2API_API_TOKEN", "") or "").strip()
    auth_header = str(getattr(_sub2_cfg, "SUB2_CODEX_AUTH_HEADER", "") or getattr(_sub2_cfg, "SUB2API_API_AUTH_HEADER", "x-api-key") or "x-api-key").strip()
    auth_prefix = str(getattr(_sub2_cfg, "SUB2_CODEX_AUTH_PREFIX", "") or getattr(_sub2_cfg, "SUB2API_API_AUTH_PREFIX", "") or "").strip()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "turb-gpt-free-register/codex-sub2",
    }
    if token:
        headers[auth_header] = f"{auth_prefix} {token}".strip() if auth_prefix else token
    return headers


def _sub2_codex_request_json(method: str, path: str, body: dict | None = None) -> dict:
    from config import sub2api as _sub2_cfg
    base = _sub2_codex_base()
    timeout = int(getattr(_sub2_cfg, "SUB2API_API_TIMEOUT", 20) or 20)
    normalized_path = "/" + str(path or "").lstrip("/")
    url = f"{base}{normalized_path}"
    session = curl_requests.Session()
    try:
        resp = session.request(
            method.upper(),
            url,
            headers=_sub2_codex_headers(),
            data=None if body is None else json.dumps(body),
            timeout=timeout,
        )
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = ""
            if isinstance(payload, dict):
                msg = payload.get("error") or payload.get("message") or payload.get("detail") or payload.get("reason") or ""
            raise RuntimeError(
                f"[Codex][sub2] API thất bại {method.upper()} {normalized_path} status={resp.status_code}: "
                f"{msg or (resp.text or '')[:300]}"
            )
        return payload if isinstance(payload, dict) else {}
    finally:
        try:
            session.close()
        except Exception:
            pass


def _request_sub2_authorize_url() -> dict:
    """Tạo địa chỉ ủy quyền OAuth Codex từ sub2; không tạo PKCE ở local."""
    from config import sub2api as _sub2_cfg
    path = str(getattr(_sub2_cfg, "SUB2_CODEX_AUTH_URL_PATH", "/api/v1/admin/openai/generate-auth-url") or "/api/v1/admin/openai/generate-auth-url")
    logger.info("[Codex][sub2] đang thông qua sub2 API tạo địa chỉ uỷ quyền...")
    payload = _sub2_codex_request_json("POST", path, {})
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    auth_url = _first_non_empty(
        payload.get("url"), payload.get("auth_url"), payload.get("authUrl"),
        data.get("url"), data.get("auth_url"), data.get("authUrl"),
    )
    session_id = _first_non_empty(
        payload.get("session_id"), payload.get("sessionId"),
        data.get("session_id"), data.get("sessionId"),
    )
    state = _first_non_empty(
        payload.get("state"), payload.get("auth_state"), payload.get("authState"),
        data.get("state"), data.get("auth_state"), data.get("authState"),
        _extract_state_from_auth_url(auth_url),
    )
    if not auth_url.startswith("http"):
        raise RuntimeError(f"[Codex][sub2] sub2 không trả về hợp lệ auth_url: {payload}")
    if not state:
        raise RuntimeError("[Codex][sub2] địa chỉ uỷ quyền thiếu state")
    logger.info("[Codex][sub2] đã lấy địa chỉ uỷ quyền, state=%s...", state[:12])
    logger.info("[Codex][sub2] URL uỷ quyền đầy đủ: %s", auth_url)
    if not session_id:
        logger.warning("[Codex][sub2] Thiếu phản hồi địa chỉ uỷ quyền session_id, Tiếp theo exchange-code Có thể thất bại")
    return {"auth_url": auth_url, "state": state, "session_id": session_id, "origin": _sub2_codex_base(), "raw": payload}


def _summarize_sub2_response(payload: dict) -> str:
    """Nén nhật ký phản hồi sub2api, tránh in tràn toàn bộ gói, đồng thời giữ thông tin quan trọng về tạo tài khoản."""
    try:
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        parts = []
        if isinstance(data, dict):
            for key in ("id", "account_id", "name", "email", "platform", "type"):
                val = data.get(key)
                if val not in (None, ""):
                    parts.append(f"{key}={val}")
        if parts:
            return " ".join(parts)
        if isinstance(payload, dict):
            compact = {k: payload.get(k) for k in ("code", "message", "success") if k in payload}
            return str(compact or payload)[:300]
    except Exception:
        pass
    return str(payload)[:300]


def _submit_sub2_callback(callback_url: str, *, session_id: str = "", redirect_uri: str = "") -> dict:
    """Gửi OAuth callback tới sub2."""
    from config import sub2api as _sub2_cfg
    path = str(getattr(_sub2_cfg, "SUB2_CODEX_CALLBACK_PATH", "/api/v1/admin/openai/create-from-oauth") or "/api/v1/admin/openai/create-from-oauth")
    mode = str(getattr(_sub2_cfg, "SUB2_CODEX_CALLBACK_PAYLOAD_MODE", "create_from_oauth") or "create_from_oauth").strip().lower()
    if mode == "callback_url":
        body = {"callback_url": str(callback_url or "").strip()}
    elif mode == "redirect_url":
        body = {"redirect_url": str(callback_url or "").strip()}
    else:
        parsed = urlparse(str(callback_url or ""))
        qs = parse_qs(parsed.query)
        code = (qs.get("code") or [""])[0]
        state = (qs.get("state") or [""])[0]
        if not session_id:
            raise RuntimeError("[Codex][sub2] exchange-code thiếu session_id")
        if not code:
            raise RuntimeError(f"[Codex][sub2] callback_url thiếu code: {callback_url}")
        if not state:
            raise RuntimeError(f"[Codex][sub2] callback_url thiếu state: {callback_url}")
        body = {"session_id": session_id, "code": code, "state": state}
        if redirect_uri:
            body["redirect_uri"] = redirect_uri
        if mode in {"create_from_oauth", "create-from-oauth", "create_oauth_account"}:
            body.setdefault("concurrency", 3)
            body.setdefault("priority", 50)

    max_attempts = max(1, int(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRIES", 5) or 5))
    base_delay = max(1.0, float(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRY_DELAY", 6) or 6))
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info("[Codex][sub2] Đang tải lên OAuth callback (thứ %s/%s lần)... callback=%s", attempt, max_attempts, callback_url)
            payload = _sub2_codex_request_json("POST", path, body)
            logger.info("[Codex][sub2] callback Đã tải lên và xử lý xong (thứ %s Lần thành công)Phản hồi=%s", attempt, _summarize_sub2_response(payload))
            return payload
        except Exception as exc:
            last_exc = exc
            retryable = _is_cpa_callback_retryable(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning("[Codex][sub2] callback tải lên thất bại và không thử lại nữa: attempt=%s/%s retryable=%s error=%s", attempt, max_attempts, retryable, exc)
                raise
            delay = base_delay * attempt
            logger.warning("[Codex][sub2] callback tải lên thất bại, Sẽ trong %.1fs thử lại sau: attempt=%s/%s error=%s", delay, attempt, max_attempts, exc)
            time.sleep(delay)
    raise RuntimeError(f"[Codex][sub2] callback tải lên thất bại: {last_exc}")



def _cpa_request_raw(method: str, path: str, body: dict | None = None, *, response_type: str = "text"):
    """Gọi API quản lý CPA và trả về phản hồi gốc; dùng để tải các phản hồi không phải JSON như auth-files."""
    origin = _cpa_management_origin()
    key = _cpa_management_key()
    timeout = int(getattr(_cfg, "CPA_REQUEST_TIMEOUT", 30) or 30)
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
        "X-Management-Key": key,
    }
    url = f"{origin}{path}"
    session = curl_requests.Session()
    try:
        resp = session.request(
            method.upper(),
            url,
            headers=headers,
            data=None if body is None else json.dumps(body),
            timeout=timeout,
        )
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = ""
            try:
                payload = resp.json()
                if isinstance(payload, dict):
                    msg = payload.get("error") or payload.get("message") or payload.get("detail") or payload.get("reason") or ""
            except Exception:
                pass
            raise RuntimeError(
                f"[Codex][CPA] API quản trị thất bại {method.upper()} {path} status={resp.status_code}: "
                f"{msg or (resp.text or '')[:300]}"
            )
        if response_type == "bytes":
            return resp.content
        return resp.text
    finally:
        try:
            session.close()
        except Exception:
            pass


def list_cpa_codex_auth_files() -> list[dict]:
    """Đọc danh sách CPA auth-files, chỉ trả về các chứng chỉ type/name/email nhận diện được là codex."""
    payload = _cpa_request_json("GET", "/v0/management/auth-files")
    files = payload.get("files") if isinstance(payload.get("files"), list) else []
    out = []
    for item in files:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        ftype = str(item.get("type") or "").strip().lower()
        email = str(item.get("email") or "").strip().lower()
        if ftype == "codex" or name.lower().startswith("codex-") or "codex" in name.lower():
            copied = dict(item)
            copied["name"] = name
            copied["email"] = email or str(item.get("email") or "")
            out.append(copied)
    return out


def find_cpa_codex_auth_file(*, email: str = "", local_filename: str = "") -> dict | None:
    """Khớp tệp auth codex phía CPA theo tên tệp biên nhận/chứng thực cục bộ hoặc email."""
    email_l = str(email or "").strip().lower()
    local_name_l = str(local_filename or "").strip().lower()
    local_stem_l = local_name_l[:-5] if local_name_l.endswith(".json") else local_name_l
    files = list_cpa_codex_auth_files()
    if not files:
        return None

    def score(item: dict) -> int:
        name_l = str(item.get("name") or "").lower()
        item_email_l = str(item.get("email") or "").lower()
        s = 0
        if local_name_l and name_l == local_name_l:
            s = max(s, 100)
        if local_stem_l and name_l.startswith(local_stem_l):
            s = max(s, 80)
        if email_l and item_email_l == email_l:
            s = max(s, 70)
        if email_l and email_l in name_l:
            s = max(s, 60)
        # Tên biên nhận CPA local thường là codex-email-cpa-callback.json, file thực tế của CPA là codex-email-free.json.
        if local_stem_l.endswith("-cpa-callback"):
            base = local_stem_l[:-len("-cpa-callback")]
            if base and name_l.startswith(base + "-"):
                s = max(s, 75)
        return s

    ranked = sorted(((score(item), item) for item in files), key=lambda x: x[0], reverse=True)
    return ranked[0][1] if ranked and ranked[0][0] > 0 else None


def download_cpa_codex_auth_text(*, cpa_name: str | None = None, email: str = "", local_filename: str = "") -> tuple[str, str, dict]:
    """
    Tải một văn bản JSON Codex từ CPA auth-files.
    Returns: (content_text, download_filename, matched_file_meta)
    """
    meta = None
    name = str(cpa_name or "").strip()
    if name:
        # Khi đã có tên file CPA thì tải trực tiếp, không kéo thêm danh sách auth-files một lần nữa.
        # Danh sách tài khoản tải hàng loạt sẽ liệt kê thống nhất một lần trước; liệt kê lại ở đây sẽ khiến trình duyệt chờ xác nhận tải xuống lâu khi chọn nhiều tài khoản.
        meta = {"name": name}
    else:
        meta = find_cpa_codex_auth_file(email=email, local_filename=local_filename)
        name = str((meta or {}).get("name") or "").strip()
    if not name:
        target = email or local_filename or cpa_name or "Không rõ"
        raise RuntimeError(f"[Codex][CPA] Không trong CPA auth-files Tìm thấy khớp trong Codex Thông tin xác thực: {target}")
    text = _cpa_request_raw("GET", f"/v0/management/auth-files/download?name={quote(name, safe='')}", response_type="text")
    # API tải xuống bình thường phải trả về văn bản JSON; ở đây kiểm tra nhẹ một lần, tránh xuất HTML/văn bản lỗi như chứng chỉ.
    try:
        parsed = json.loads(text)
    except Exception as exc:
        raise RuntimeError(f"[Codex][CPA] CPA Nội dung tải xuống không hợp lệ JSON: {name}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"[Codex][CPA] CPA Nội dung tải xuống không phải JSON Đối tượng: {name}")
    return json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", name, (meta or {"name": name})

def _first_non_empty(*values) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _extract_state_from_auth_url(auth_url: str) -> str:
    try:
        return parse_qs(urlparse(auth_url).query).get("state", [""])[0]
    except Exception:
        return ""


def _request_cpa_authorize_url() -> dict:
    """Tạo địa chỉ ủy quyền OAuth Codex từ CPA; phía cục bộ không tạo PKCE."""
    logger.info("[Codex][CPA] đang thông qua CPA API quản lý tạo địa chỉ uỷ quyền...")
    payload = _cpa_request_json("GET", "/v0/management/codex-auth-url")
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    auth_url = _first_non_empty(
        payload.get("url"),
        payload.get("auth_url"),
        payload.get("authUrl"),
        data.get("url"),
        data.get("auth_url"),
        data.get("authUrl"),
    )
    state = _first_non_empty(
        payload.get("state"),
        payload.get("auth_state"),
        payload.get("authState"),
        data.get("state"),
        data.get("auth_state"),
        data.get("authState"),
        _extract_state_from_auth_url(auth_url),
    )
    if not auth_url.startswith("http"):
        raise RuntimeError(f"[Codex][CPA] CPA không trả về hợp lệ auth_url: {payload}")
    if not state:
        raise RuntimeError("[Codex][CPA] CPA địa chỉ uỷ quyền thiếu state")
    logger.info(f"[Codex][CPA] đã lấy địa chỉ uỷ quyền, state={state[:12]}...")
    logger.info(f"[Codex][CPA] URL uỷ quyền đầy đủ: {auth_url}")
    return {
        "auth_url": auth_url,
        "state": state,
        "origin": _cpa_management_origin(),
        "raw": payload,
    }


def _is_cpa_callback_retryable(exc: Exception) -> bool:
    text = str(exc or "").lower()
    return (
        "status=409" in text
        or "timeout waiting for oauth callback" in text
        or "timeout" in text
        or "timed out" in text
        or "connection" in text
        or "status=429" in text
        or "status=500" in text
        or "status=502" in text
        or "status=503" in text
        or "status=504" in text
    )


def _is_cpa_callback_reauth_error(exc_or_text) -> bool:
    """CPA nhận callback rồi vẫn 409 timeout, thường cần tạo lại địa chỉ ủy quyền và chạy lại một vòng OAuth."""
    text = str(exc_or_text or "").lower()
    return (
        "oauth-callback" in text
        and "status=409" in text
        and "timeout waiting for oauth callback" in text
    ) or (
        "timeout waiting for oauth callback" in text
    )


def _submit_cpa_callback(callback_url: str) -> dict:
    """Gửi OAuth callback cho CPA.

    CPA đôi khi vẫn trả
    “409 Timeout waiting for OAuth callback” dù trình duyệt đã nhận localhost callback, thường do race chờ/ghi DB phía quản trị;
    ở đây thử lại nhiều lần với cùng callback URL, không tạo lại địa chỉ ủy quyền.
    """
    body = {
        "provider": "codex",
        "redirect_url": str(callback_url or "").strip(),
    }
    max_attempts = max(1, int(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRIES", 5) or 5))
    base_delay = max(1.0, float(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRY_DELAY", 6) or 6))
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(
                "[Codex][CPA] Đang gửi OAuth callback Cho CPA (thứ %s/%s lần)... callback=%s",
                attempt, max_attempts, str(callback_url or "")
            )
            payload = _cpa_request_json("POST", "/v0/management/oauth-callback", body)
            logger.info("[Codex][CPA] callback Đã gửi (thứ %s Lần thành công)", attempt)
            return payload
        except Exception as exc:
            last_exc = exc
            retryable = _is_cpa_callback_retryable(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning(
                    "[Codex][CPA] callback gửi thất bại và không thử lại nữa: attempt=%s/%s retryable=%s error=%s",
                    attempt, max_attempts, retryable, exc
                )
                raise
            delay = base_delay * attempt
            logger.warning(
                "[Codex][CPA] callback gửi thất bại, Sẽ trong %.1fs thử lại sau: attempt=%s/%s error=%s",
                delay, attempt, max_attempts, exc
            )
            time.sleep(delay)
    raise RuntimeError(f"[Codex][CPA] callback gửi thất bại: {last_exc}")


# ============================================================
# Công cụ nhỏ: phán đoán/phân tích
# ============================================================

def _is_redirect_uri(location: str) -> bool:
    """Xác định liệu Location có trỏ tới redirect_uri đã đăng ký (localhost:1455/auth/callback) hay không."""
    try:
        parsed = urlparse(location)
    except Exception:
        return False
    return parsed.scheme in ("http", "https") and \
        parsed.hostname in ("localhost", "127.0.0.1") and \
        parsed.port == 1455 and \
        parsed.path == "/auth/callback"


def _extract_code(location: str, state: str) -> str:
    """Trích xuất và kiểm tra code từ Location của redirect_uri."""
    parsed = urlparse(location)
    qs = parse_qs(parsed.query)
    err = (qs.get("error") or [""])[0]
    if err:
        err_desc = (qs.get("error_description") or [""])[0]
        raise RuntimeError(f"[Codex] Máy chủ uỷ quyền trả về lỗi: error={err}, desc={err_desc}")
    code = (qs.get("code") or [""])[0]
    if not code:
        raise RuntimeError(f"[Codex] redirect_uri thiếu code tham số: {location}")
    returned_state = (qs.get("state") or [""])[0]
    if returned_state and returned_state != state:
        raise RuntimeError(
            f"[Codex] state Không khớp (Nghi ngờ CSRF): expected={state[:8]}..., got={returned_state[:8]}..."
        )
    return code


def _decode_jwt_segment(seg: str) -> dict:
    """Giải mã base64url một đoạn JWT/cookie thành JSON dict (thất bại trả về {})."""
    try:
        padding = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + padding))
    except Exception:
        return {}


def _post_json(session: BrowserSession, url: str, payload: dict, referer: str,
               sentinel_header: str | None = None, so_header: str | None = None):
    """Gửi thống nhất JSON POST tới /api/accounts/*."""
    headers = session.get_auth_headers(referer=referer)
    if sentinel_header:
        headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    resp = session.post(url, headers=headers, data=json.dumps(payload), allow_redirects=False)
    _cache_auth_session_metadata(session, resp)
    return resp


def _resp_json(resp) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}


def _response_text(resp) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict):
            parts = []
            def walk(x):
                if isinstance(x, dict):
                    for v in x.values(): walk(v)
                elif isinstance(x, list):
                    for v in x: walk(v)
                elif x is not None:
                    parts.append(str(x))
            walk(data)
            return " ".join(parts)
    except Exception:
        pass
    return str(getattr(resp, 'text', '') or '')


def _decode_auth_session_metadata(value) -> dict:
    """Chuyển oai-client-auth-session trong phản hồi thành workspace payload."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    return _decode_jwt_segment(value.split(".", 1)[0])


def _cache_auth_session_metadata(session: BrowserSession, resp) -> None:
    """Cache metadata session mang theo trong phản hồi Auth, để khôi phục workspace khi thiếu cookie."""
    try:
        payload = _resp_json(resp)
        if not isinstance(payload, dict):
            return
        value = payload.get("oai-client-auth-session")
        if value is None:
            value = payload.get("auth_session") or payload.get("authSession")
        cached = _decode_auth_session_metadata(value)
        if cached:
            session._codex_auth_session_payload = cached
    except Exception:
        logger.debug("[Codex] Cache Auth session Metadata thất bại", exc_info=True)


def _phone_failure_reason(text: str, status_code: int | None = None) -> str:
    low = str(text or '').lower()
    if 'whatsapp' in low or 'whats app' in low:
        return 'whatsapp_channel'
    if any(k in low for k in (
        'phone number is not valid', 'invalid phone number', 'invalid phone', 'not a valid phone',
        '号码无效', '手机号无效', '电话号码无效', 'invalid_number', 'invalid_phone',
    )):
        return 'invalid_phone'
    if any(k in low for k in (
        'cannot send', "can't send", 'could not send', "couldn't send", 'unable to send',
        'cannot deliver', 'unable to deliver', 'failed to send', 'send failed',
        '无法发送', '不能发送', '无法向', '发送验证码', '发送短信',
    )):
        return 'delivery_refused'
    if any(k in low for k in ('too many', 'rate limit', 'throttle', 'limited', '频繁', '限流')):
        return 'send_limited'
    if any(k in low for k in ('already used', 'used too many', 'maximum', '上限', '已被使用')):
        return 'phone_used_or_max'
    if status_code and status_code >= 500:
        return 'server_error'
    if status_code and status_code >= 400:
        return 'send_rejected'
    return ''


# ============================================================
# Bước 0: dùng session hoàn toàn mới theo Codex authorize URL, thiết lập phiên auth.openai.com
# ============================================================

def _bootstrap_authorize(
    session: BrowserSession,
    state: str,
    code_challenge: str | None = None,
    auth_url: str | None = None,
) -> None:
    """
    GET Codex authorize URL và theo các chuyển hướng, đến trang đăng nhập, thiết lập cookies auth.openai.com
    (bao gồm oai-client-auth-session: chứa mục tiêu Codex + danh sách workspace sẽ dùng sau).
    """
    # Mặc định dùng địa chỉ ủy quyền CPA do bên gọi truyền vào; chỉ khi chưa truyền mới chạy logic sinh PKCE cục bộ đã giữ lại.
    if not auth_url:
        if not code_challenge:
            raise RuntimeError("[Codex] Tạo địa chỉ uỷ quyền cục bộ cần code_challenge")
        auth_url = _build_authorize_url(state, code_challenge, prompt="login")
    auth_url = _ensure_oai_context_url(auth_url, session)
    # Địa chỉ ủy quyền Codex CLI/CPA là điều hướng cấp cao do người dùng mở trực tiếp từ client bên ngoài, không phải từ
    # Đến từ click trên trang chatgpt.com. Dùng sec-fetch-site:none và không giả mạo Referer.
    headers = session.get_auth_navigate_headers(referer="", user_initiated=True)
    logger.info("[Codex] theo Codex authorize URL thiết lập session...")
    logger.info(f"[Codex] URL uỷ quyền đầy đủ: {auth_url}")
    resp = _with_auth_navigation_retry(
        session,
        "bootstrap authorize",
        lambda: session.get(auth_url, headers=headers, allow_redirects=True),
    )
    logger.debug(f"[Codex] authorize điểm đến: {getattr(resp, 'url', '')}, status={getattr(resp, 'status_code', '')}")


# ============================================================
# Bước 1: Gửi email (kích hoạt gửi OTP email)
# ============================================================

def _submit_email(session: BrowserSession, email: str) -> dict:
    """POST authorize/continue gửi email, để dịch vụ Auth trả về bước tiếp theo (trang mật khẩu/trang OTP v.v.). Có sentinel."""
    sentinel_resp = request_sentinel_token(session, "authorize_continue")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "authorize_continue")
    payload = {"username": {"kind": "email", "value": email}}
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/authorize/continue",
        payload,
        referer="https://auth.openai.com/log-in",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code not in (200, 204):
        raise RuntimeError(
            f"[Codex] Gửi email thất bại status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    result = _resp_json(resp)
    logger.info(
        "[Codex] Đã gửi email %s, Auth bước tiếp theo: page=%s continue=%s",
        email,
        _page_type(result) or "-",
        _extract_continue_url(result) or "-",
    )
    return result


def _extract_continue_url(result: dict | None) -> str:
    """Trích xuất URL continue/redirect từ phản hồi Auth JSON."""
    if not isinstance(result, dict):
        return ""
    page = result.get("page") or {}
    page = page if isinstance(page, dict) else {}
    return str(
        result.get("continue_url")
        or result.get("external_url")
        or result.get("redirect_url")
        or result.get("url")
        or page.get("continue_url")
        or page.get("external_url")
        or page.get("redirect_url")
        or page.get("url")
        or ""
    ).strip()


def _extract_factor_id(result: dict | None, continue_url: str = "") -> str:
    """Trích xuất factor_id từ phản hồi MFA hoặc URL /mfa-challenge/<factor_id>."""
    if isinstance(result, dict):
        factor_id = str(result.get("factor_id") or result.get("id") or "").strip()
        if factor_id:
            return factor_id
        page = result.get("page") or {}
        page = page if isinstance(page, dict) else {}
        payload = page.get("payload") or {}
        if isinstance(payload, dict):
            factor_id = str(payload.get("factor_id") or payload.get("id") or "").strip()
            if factor_id:
                return factor_id
    if "/mfa-challenge/" in continue_url:
        return continue_url.rstrip("/").rsplit("/", 1)[-1]
    return ""


def _page_type(result: dict | None) -> str:
    if not isinstance(result, dict):
        return ""
    page = result.get("page") or {}
    return str((page if isinstance(page, dict) else {}).get("type") or "").strip()


def _result_text(result: dict | None) -> str:
    """Làm phẳng kết quả lồng nhau do Auth trả về thành văn bản có thể khớp, không phụ thuộc tên trường đơn lẻ."""
    try:
        return json.dumps(result or {}, ensure_ascii=False, separators=(",", ":")).lower()
    except Exception:
        return str(result or "").lower()


def _result_has_any(result: dict | None, *terms: str) -> bool:
    text = _result_text(result)
    return any(str(term).lower() in text for term in terms)


def _is_password_step(result: dict | None) -> bool:
    return _result_has_any(
        result,
        "log-in/password",
        "login/password",
        "password_verify",
        '"page":"password"',
        '"type":"password"',
        '"type":"login_password"',
    )


def _is_email_otp_step(result: dict | None) -> bool:
    return _result_has_any(
        result,
        "email-verification",
        "email_otp",
        "email-otp",
        "email_otp_send",
    )


def _is_mfa_step(result: dict | None, continue_url: str = "") -> bool:
    return "/mfa-challenge/" in str(continue_url or "").lower() or _result_has_any(
        result,
        "mfa-challenge",
        "mfa_challenge",
        "totp",
        '"type":"mfa"',
    )


def _is_phone_step(result: dict | None) -> bool:
    return _result_has_any(
        result,
        "add-phone",
        "add_phone",
        "phone-verification",
        "phone_verification",
        "phone_otp",
    )


def _password_verify(session: BrowserSession, password: str) -> dict:
    """提交登录密码。"""
    sentinel_resp = request_sentinel_token(session, "password_verify")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "password_verify")
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/password/verify",
        {"password": password},
        referer="https://auth.openai.com/log-in/password",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"[Codex] Xác minh mật khẩu thất bại status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    logger.info("[Codex] xác minh mật khẩu thành công")
    return _resp_json(resp)


def _mfa_issue_challenge(session: BrowserSession, factor_id: str) -> dict:
    """Khởi tạo challenge TOTP MFA."""
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/mfa/issue_challenge",
        {"id": factor_id, "type": "totp", "force_fresh_challenge": False},
        referer="https://auth.openai.com/mfa-challenge",
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"[Codex] MFA challenge Khởi tạo thất bại status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    return _resp_json(resp)


def _mfa_verify(session: BrowserSession, factor_id: str, code: str) -> dict:
    """提交 TOTP MFA 验证码。"""
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/mfa/verify",
        {"id": factor_id, "type": "totp", "code": code},
        referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"[Codex] MFA Xác minh thất bại status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    logger.info("[Codex] MFA/TOTP xác minh thành công")
    return _resp_json(resp)


def _complete_mfa_if_required(session: BrowserSession, email: str, result: dict | None) -> dict:
    """Chỉ khi kết quả Auth hiện tại yêu cầu rõ MFA, mới gửi TOTP tài khoản và trả về trạng thái tiếp theo."""
    continue_url = _extract_continue_url(result)
    if not _is_mfa_step(result, continue_url):
        return result or {}

    factor_id = _extract_factor_id(result, continue_url)
    if not factor_id:
        raise RuntimeError(f"[Codex] Auth yêu cầu MFA, Nhưng chưa lấy được factor_id: {result}")
    code = _account_totp_code(email)
    if not code:
        raise RuntimeError(f"[Codex] Auth yêu cầu MFA, Nhưng tài khoản không có sẵn totp_secret: {email}")

    logger.info("[Codex] Auth yêu cầu MFA, bắt đầu gửi tài khoản TOTP: %s factor_id=%s", email, factor_id)
    _mfa_issue_challenge(session, factor_id)
    return _mfa_verify(session, factor_id, code)


def _follow_login_continue(session: BrowserSession, continue_url: str, state: str) -> str | None:
    """
    URL continue sau mật khẩu/MFA thành công có thể nhảy thẳng callback, hoặc chỉ đưa phiên tới
    trang Codex consent/workspace. Ở đây chỉ theo redirect và giữ Cookie:
      - Trúng localhost callback: trả về callback URL
      - Dừng ở 200 HTML/không Location: trả về None, sau đó tiếp tục workspace/select
    """
    if not continue_url:
        return None
    url = continue_url if continue_url.startswith("http") else ("https://auth.openai.com" + continue_url)
    for hop in range(_MAX_REDIRECTS):
        if _is_redirect_uri(url):
            return url
        headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/", user_initiated=True)
        resp = session.get(url, headers=headers, allow_redirects=False)
        loc = resp.headers.get("location") or resp.headers.get("Location")
        logger.debug(
            "[Codex] đăng nhập continue theo hop %s: status=%s, location=%s",
            hop, getattr(resp, "status_code", ""), loc,
        )
        if not loc:
            return None
        url = loc if loc.startswith("http") else ("https://auth.openai.com" + loc)
    raise RuntimeError(f"[Codex] đăng nhập continue theo vượt quá {_MAX_REDIRECTS} nhảy")


def _try_password_mfa_login(
    session: BrowserSession,
    email: str,
    state: str,
    initial_result: dict | None,
) -> tuple[str, str | None, dict]:
    """
    Khi có mật khẩu đăng ký thì ưu tiên đăng nhập bằng mật khẩu; nếu vào MFA challenge thì dùng totp_secret của tài khoản để tạo TOTP.

    Trả về:
      ("logged_in", callback_url_or_None, result)  đã hoàn tất đăng nhập mật khẩu/MFA
      ("email_otp", None, result)                  server yêu cầu OTP email
      ("not_applicable", None, result)            trang hiện tại thực tế không phải trang mật khẩu
    """
    password = _account_registration_password(email)
    if not password or not _is_password_step(initial_result):
        logger.info(
            "[Codex] Hiện tại Auth Không yêu cầu mật khẩu, Tiếp tục theo phản hồi máy chủ: email=%s page=%s continue=%s",
            email,
            _page_type(initial_result) or "-",
            _extract_continue_url(initial_result) or "-",
        )
        return "not_applicable", None, initial_result or {}

    logger.info("[Codex] tài khoản đã có mật khẩu đăng ký, ưu tiên đăng nhập bằng mật khẩu: %s", email)
    result = _password_verify(session, password)
    continue_url = _extract_continue_url(result)
    page_type = _page_type(result)

    if _is_mfa_step(result, continue_url) or page_type == "mfa_challenge":
        result = _complete_mfa_if_required(session, email, result)
        continue_url = _extract_continue_url(result) or continue_url
        page_type = _page_type(result)

    if _is_email_otp_step(result) or page_type in {"email_verification", "email_otp_send"}:
        logger.info("[Codex] Sau đăng nhập mật khẩu, máy chủ vẫn yêu cầu email OTP, Chuyển sang email OTP: %s", email)
        return "email_otp", None, result

    callback_url = _follow_login_continue(session, continue_url, state) if continue_url else None
    logger.info("[Codex] mật khẩu/MFA chuỗi đăng nhập đã hoàn tất, Tiếp tục Codex workspace/callback: %s", email)
    return "logged_in", callback_url, result


# ============================================================
# Bước 2: Gửi OTP email
# ============================================================

def _submit_email_otp(session: BrowserSession, code: str) -> dict:
    """POST email-otp/validate 提交邮箱验证码。带 sentinel(authorize_continue)。"""
    sentinel_resp = request_sentinel_token(session, "authorize_continue")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "authorize_continue")
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/email-otp/validate",
        {"code": code},
        referer="https://auth.openai.com/email-verification",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code != 200:
        error_code = _extract_error_code(resp)
        if error_code in ("account_deactivated", "account_deleted", "account_banned"):
            raise AccountUnusableError(
                f"[Codex] Tài khoản đã chết ({error_code}）status={resp.status_code}: {(resp.text or '')[:200]}",
                error_code=error_code,
            )
        body_error_code = detect_account_unusable_response_body(resp.text or "")
        if body_error_code:
            raise AccountUnusableError(
                f"[Codex] Tài khoản đã chết ({body_error_code}）status={resp.status_code}: {(resp.text or '')[:200]}",
                error_code=body_error_code,
            )
        raise RuntimeError(
            f"[Codex] email OTP Xác minh thất bại status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    logger.info("[Codex] email OTP xác minh thành công")
    result = _resp_json(resp)
    logger.info(
        "[Codex] email OTP sau Auth bước tiếp theo: page=%s continue=%s phone=%s mfa=%s",
        _page_type(result) or "-",
        _extract_continue_url(result) or "-",
        _is_phone_step(result),
        _is_mfa_step(result, _extract_continue_url(result)),
    )
    return result


# ============================================================
# Bước 3-4: Xác minh số điện thoại (nhận mã, thất bại thì đổi số thử lại)
# ============================================================

def _sms_provider_name() -> str:
    """Tên kênh nhận mã hiện tại, chỉ dùng cho nhật ký quy trình Codex."""
    return str(getattr(_cfg, "SMS_PROVIDER", "grizzly") or "grizzly").strip().lower()


def _sleep_before_phone_retry(attempt: int, max_retries: int, *, prefix: str = "[Codex]") -> None:
    """Chờ ngẫu nhiên trước khi đổi số, ít nhất 3 giây, tránh gửi số liên tục quá nhanh."""
    if attempt >= max_retries:
        return
    seconds = random.uniform(3.0, 8.0)
    logger.info(f"{prefix} chờ ngẫu nhiên trước khi đổi số {seconds:.1f} giây")
    time.sleep(seconds)


def _do_phone_verification(session: BrowserSession) -> dict:
    """
    Dùng nền tảng nhận mã lấy số → add-phone/send gửi SMS → nhận mã → phone-otp/validate.
    Một số không nhận được mã hoặc bị OpenAI từ chối thì hủy đổi số, tối đa SMS_MAX_RETRIES lần (hot-reload).

    Adapter nền tảng thực tế nằm ở core.sms_provider:
        - SMS_PROVIDER="grizzly": GrizzlySMS handler_api.php
        - SMS_PROVIDER="l": giao diện JSON /take-phone và /fetch-code theo L_API.md
    """
    http = sms_provider._http()
    max_retries = _cfg.SMS_MAX_RETRIES
    provider = _sms_provider_name()
    try:
        last_err = None
        for attempt in range(1, max_retries + 1):
            activation_id = None
            try:
                activation_id, phone = sms_provider.acquire_number(http)
                logger.info(
                    f"[Codex] lần thử xác minh điện thoại {attempt}/{max_retries}，"
                    f"provider={provider}, activation_id={activation_id}, số=+{phone}"
                )

                # Gửi SMS
                send_resp = _post_json(
                    session,
                    "https://auth.openai.com/api/accounts/add-phone/send",
                    {"phone_number": f"+{phone}", "channel": "sms"},
                    referer="https://auth.openai.com/add-phone",
                )
                send_text = _response_text(send_resp)
                send_reason = _phone_failure_reason(send_text, send_resp.status_code)
                if send_resp.status_code not in (200, 204) or send_reason:
                    # Số không hợp lệ / không gửi được / kênh WhatsApp / rate limit v.v. → giải phóng số hiện tại và đổi số.
                    logger.warning(
                        f"[Codex] add-phone/send chưa thành công reason={send_reason or 'unknown'}, "
                        f"status={send_resp.status_code}: {send_text[:240]}, đổi số thử lại"
                    )
                    sms_provider.cancel(activation_id, http)
                    _sleep_before_phone_retry(attempt, max_retries)
                    continue

                # Thông báo nền tảng SMS đã gửi (status=1)
                sms_provider.set_status(activation_id, 1, http=http)

                # Định kỳ poll nền tảng nhận mã để lấy SMS. wait_for_sms_code bên trong poll theo SMS_POLL_INTERVAL,
                # Chờ tối đa SMS_CODE_WAIT; hết thời gian thì hủy ngay số hiện tại và đổi số.
                try:
                    logger.info(
                        f"[Codex] đã gửi SMS, bắt đầu polling mã OTP activation_id={activation_id}, "
                        f"wait={_cfg.SMS_CODE_WAIT}s, interval={_cfg.SMS_POLL_INTERVAL}s"
                    )
                    sms_code = sms_provider.wait_for_sms_code(activation_id, http)
                except sms_provider.SmsCodeTimeout:
                    logger.warning(f"[Codex] số +{phone} tại {_cfg.SMS_CODE_WAIT}s chưa nhận SMS trong hạn, huỷ đổi số")
                    sms_provider.cancel(activation_id, http)
                    _sleep_before_phone_retry(attempt, max_retries)
                    continue

                # Xác minh mã điện thoại
                val_resp = _post_json(
                    session,
                    "https://auth.openai.com/api/accounts/phone-otp/validate",
                    {"code": sms_code},
                    referer="https://auth.openai.com/phone-verification",
                )
                if val_resp.status_code != 200:
                    val_text = _response_text(val_resp)
                    val_reason = _phone_failure_reason(val_text, val_resp.status_code) or 'code_rejected'
                    logger.warning(
                        f"[Codex] phone-otp/validate Thất bại reason={val_reason}, status={val_resp.status_code}: "
                        f"{val_text[:240]}, đổi số thử lại"
                    )
                    sms_provider.cancel(activation_id, http)
                    _sleep_before_phone_retry(attempt, max_retries)
                    continue

                # Thành công
                sms_provider.complete(activation_id, http)
                logger.info("[Codex] qua xác minh số điện thoại")
                return _resp_json(val_resp)

            except sms_provider.SmsNoBalanceError:
                # Số dư không đủ, thử lại vô nghĩa, ném trực tiếp
                raise
            except sms_provider.SmsProviderError as exc:
                last_err = exc
                logger.warning(f"[Codex] thử nhận mã {attempt} Thất bại: {exc}")
                if activation_id:
                    sms_provider.cancel(activation_id, http)
                _sleep_before_phone_retry(attempt, max_retries)
                continue

        raise RuntimeError(
            f"[Codex] Thử lại xác minh số điện thoại {max_retries} lần vẫn thất bại (provider={provider}）"
            + (f", Lỗi cuối: {last_err}" if last_err else "")
        )
    finally:
        http.close()


# ============================================================
# Bước 5: chọn workspace → lấy callback code
# ============================================================

def _get_workspace_id(session: BrowserSession) -> str:
    """
    Ưu tiên giải workspace từ cookie oai-client-auth-session; khi cookie chưa ghi xuống,
    lùi về metadata phản hồi Auth, và trong thời gian có giới hạn chờ cookie/trạng thái phản hồi hoàn tất.
    """
    def find_workspace_id(payload: dict) -> str:
        for workspace in payload.get("workspaces") or []:
            if isinstance(workspace, dict) and workspace.get("id"):
                return str(workspace["id"])
        return ""

    deadline = time.monotonic() + max(0.0, float(_WORKSPACE_COOKIE_WAIT_SECONDS))
    while True:
        raw = None
        try:
            for c in session.session.cookies.jar:
                if c.name == "oai-client-auth-session":
                    raw = c.value
                    break
        except Exception:
            pass
        if not raw:
            try:
                raw = session.session.cookies.get("oai-client-auth-session")
            except Exception:
                raw = None

        if raw:
            wid = find_workspace_id(_decode_auth_session_metadata(raw))
            if wid:
                logger.info(f"[Codex] workspace_id={wid}")
                return wid

        wid = find_workspace_id(getattr(session, "_codex_auth_session_payload", {}) or {})
        if wid:
            logger.info(f"[Codex] workspace_id={wid} (Từ Auth siêu dữ liệu phản hồi)")
            return wid

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if not raw:
                raise RuntimeError("[Codex] không tìm thấy oai-client-auth-session cookie, không lấy được workspace_id")
            raise RuntimeError("[Codex] oai-client-auth-session không có sẵn workspace_id")
        time.sleep(min(_WORKSPACE_POLL_INTERVAL_SECONDS, remaining))


def _select_workspace_and_get_callback(session: BrowserSession, state: str) -> str:
    """
    POST workspace/select, sau đó theo dõi URL trong các lần chuyển hướng/phản hồi tiếp theo cho đến khi gặp callback localhost:1455.
    Trả về URL callback đầy đủ (bao gồm code).
    """
    wid = _get_workspace_id(session)
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/workspace/select",
        {"workspace_id": wid},
        referer="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
    )

    # 1) Trực tiếp mang header Location trúng callback
    loc = resp.headers.get("location") or resp.headers.get("Location")
    if loc and _is_redirect_uri(loc):
        return loc

    # 2) Trong JSON phản hồi có URL bước tiếp theo (continue_url / redirect_url / url / next)
    data = _resp_json(resp)
    next_url = None
    for key in ("redirect_url", "continue_url", "url", "next", "location"):
        v = data.get(key)
        if isinstance(v, str) and v:
            next_url = v
            break

    # 3) Không có URL nhưng có Location (không phải callback) → theo dõi từ Location
    if not next_url and loc:
        next_url = loc

    if not next_url:
        raise RuntimeError(
            f"[Codex] workspace/select Sau đó không tìm thấy bước tiếp theo URL: status={resp.status_code}, "
            f"body={(resp.text or '')[:300]}"
        )

    # Theo chuỗi chuyển hướng đến khi gặp callback
    return _follow_until_callback(session, next_url, state)


def _follow_until_callback(session: BrowserSession, url: str, state: str) -> str:
    """Bắt đầu từ URL cho trước, theo dõi từng bước nhảy; khi trúng callback localhost:1455 thì trả về Location của nó."""
    if url.startswith("/"):
        url = "https://auth.openai.com" + url
    for hop in range(_MAX_REDIRECTS):
        if _is_redirect_uri(url):
            return url
        headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/")
        resp = session.get(url, headers=headers, allow_redirects=False)
        loc = resp.headers.get("location") or resp.headers.get("Location")
        logger.debug(f"[Codex] callback theo hop {hop}: status={getattr(resp,'status_code','')}, location={loc}")
        if loc is None:
            raise RuntimeError(
                f"[Codex] theo dõi bị ngắt, không trúng callback: url={url}, "
                f"status={getattr(resp,'status_code','')}, body={(resp.text or '')[:200]}"
            )
        if _is_redirect_uri(loc):
            return loc
        url = loc if loc.startswith("http") else ("https://auth.openai.com" + loc)
    raise RuntimeError(f"[Codex] theo callback vượt quá {_MAX_REDIRECTS} nhảy")


# ============================================================
# Đổi token (đối chiếu CLIProxyAPI ExchangeCodeForTokensWithRedirect) —— chưa chỉnh sửa
# ============================================================

def exchange_codex_token(session: BrowserSession, code: str, code_verifier: str) -> dict:
    """Đổi authorization code lấy token."""
    data = {
        "grant_type": "authorization_code",
        "client_id": _cfg.CODEX_CLIENT_ID,
        "code": code,
        "redirect_uri": _cfg.CODEX_REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    base = session._get_common_headers()
    base.update(headers)
    headers = base

    logger.info("[Codex] dùng authorization code đổi token...")
    resp = session.post(_cfg.CODEX_TOKEN_URL, headers=headers, data=urlencode(data))
    http_status = resp.status_code
    if http_status != 200:
        raise RuntimeError(
            f"[Codex] đổi token Thất bại status={http_status}: {(resp.text or '')[:300]}"
        )
    token_resp = resp.json()
    if not token_resp.get("access_token"):
        raise RuntimeError(f"[Codex] token Thiếu phản hồi access_token: {token_resp}")
    logger.info(
        f"[Codex] đổi token thành công, expires_in={token_resp.get('expires_in')}, "
        f"access_token={token_resp['access_token'][:16]}..."
    )
    return token_resp


# ============================================================
# Phân tích id_token / ghi đĩa —— chưa chỉnh sửa
# ============================================================

def _parse_id_token(id_token: str) -> dict:
    """Giải mã base64 JWT payload (không xác minh chữ ký), trích email / account_id / plan_type."""
    if not id_token:
        return {}
    try:
        parts = id_token.split(".")
        if len(parts) < 2:
            return {}
        claims = _decode_jwt_segment(parts[1])
    except Exception as exc:
        logger.warning(f"[Codex] id_token phân tích thất bại: {exc}")
        return {}

    auth_claim = claims.get("https://api.openai.com/auth", {}) or {}
    profile_claim = claims.get("https://api.openai.com/profile", {}) or {}
    # email của id_token OpenAI bản mới nằm ở claim cấp cao nhất; bản cũ/CLIProxyAPI nằm trong profile_claim.
    # Ưu tiên tầng trên, không thì fallback profile_claim, tránh trường email trong file codex-email.json ghi đĩa bị trống.
    email_value = claims.get("email") or profile_claim.get("email", "")
    return {
        "email": email_value,
        "account_id": auth_claim.get("chatgpt_account_id", ""),
        "plan_type": auth_claim.get("chatgpt_plan_type", ""),
    }


def build_codex_storage(token_resp: dict, id_claims: dict) -> dict:
    """Lắp ráp cấu trúc JSON CLIProxyAPI CodexTokenStorage."""
    expires_in = token_resp.get("expires_in", 0) or 0
    expired_dt = datetime.now(timezone.utc) + _timedelta_seconds(expires_in)
    last_refresh_dt = datetime.now(timezone.utc)
    return {
        "id_token": token_resp.get("id_token", ""),
        "access_token": token_resp.get("access_token", ""),
        "refresh_token": token_resp.get("refresh_token", ""),
        "account_id": id_claims.get("account_id", ""),
        "last_refresh": last_refresh_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "email": id_claims.get("email", ""),
        "type": "codex",
        "expired": expired_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _timedelta_seconds(seconds: int):
    from datetime import timedelta
    return timedelta(seconds=int(seconds))


def _credential_file_name(email: str, plan_type: str) -> str:
    """Đối chiếu CLIProxyAPI filename.go: không có plan→codex-{email}.json, ngược lại có hậu tố plan."""
    email = (email or "").strip()
    plan = (plan_type or "").strip().lower()
    if plan == "":
        return f"codex-{email}.json"
    return f"codex-{email}-{plan}.json"


def save_codex_credential(storage: dict, email: str, plan_type: str) -> str:
    """Lưu thông tin xác thực Codex vào SQLite, không tạo tệp cục bộ."""
    fname = _credential_file_name(email, plan_type)
    db.upsert_codex_credential(storage, fname)
    return f"sqlite://codex_accounts/{fname}"


def _save_codex_credential(email: str, storage: dict) -> str:
    """Điểm vào tương thích BrowserUse: cũng chỉ lưu vào SQLite."""
    plan = ""
    if isinstance(storage, dict):
        plan = storage.get("plan_type") or storage.get("chatgpt_plan_type") or ""
    return save_codex_credential(storage, email, plan)


def _extract_cpa_auth_json(payload: dict) -> dict | None:
    """
    Thử trích xuất tệp ủy quyền đầy đủ từ phản hồi CPA oauth-callback.
    Tên trường có thể khác giữa các phiên bản CPA; chỉ cần trông giống codex auth json thì lưu local.
    """
    if not isinstance(payload, dict):
        return None
    candidates = [
        payload.get("auth_json"),
        payload.get("authJson"),
        payload.get("auth"),
        payload.get("auth_file"),
        payload.get("authFile"),
        payload.get("file"),
        payload.get("data"),
    ]
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    candidates.extend([
        data.get("auth_json"),
        data.get("authJson"),
        data.get("auth"),
        data.get("auth_file"),
        data.get("authFile"),
        data.get("file"),
    ])
    for item in candidates:
        if isinstance(item, dict) and (
            item.get("type") == "codex"
            or item.get("access_token")
            or item.get("refresh_token")
            or item.get("id_token")
        ):
            return item
    return None


def _save_cpa_local_record(
    *,
    email: str,
    callback_url: str,
    auth_url: str,
    state: str,
    submit_payload: dict,
) -> str | None:
    """
    Ghi kết quả ủy quyền CPA vào SQLite:
      1) Nếu CPA trả về auth json đầy đủ, lưu thành codex-email[-plan].json khả dụng;
      2) Nếu không, theo cấu hình lưu biên nhận gửi callback, để theo dõi kết quả ủy quyền phía CPA.
    """
    auth_json = _extract_cpa_auth_json(submit_payload)
    if auth_json:
        effective_email = auth_json.get("email") or email
        plan = auth_json.get("plan_type") or auth_json.get("chatgpt_plan_type") or ""
        return save_codex_credential(auth_json, effective_email, plan)

    if not bool(getattr(_cfg, "CPA_SAVE_CALLBACK_RECEIPT", True)):
        return None

    safe_email = (email or "unknown").strip().replace("/", "_").replace("\\", "_")
    fname = f"codex-{safe_email}-cpa-callback.json"
    record = {
        "type": "codex_cpa_callback",
        "email": email,
        "state": state,
        "auth_url": auth_url,
        "callback_url": callback_url,
        "cpa_management_origin": _cpa_management_origin(),
        "cpa_submit_response": submit_payload,
        "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "địa chỉ uỷ quyền do CPA tạo; callback đã gửi cho CPA. nếu CPA phản hồi không chứa token, tệp này là bản ghi biên nhận cục bộ. ",
    }
    db.upsert_codex_credential(record, fname)
    return f"sqlite://codex_accounts/{fname}"


def _save_sub2_local_record(
    *,
    email: str,
    callback_url: str,
    auth_url: str,
    state: str,
    submit_payload: dict,
) -> str | None:
    """Ghi kết quả ủy quyền sub2 vào SQLite; nếu trả về auth json đầy đủ thì lưu làm thông tin xác thực Codex."""
    auth_json = _extract_cpa_auth_json(submit_payload)
    if auth_json:
        effective_email = auth_json.get("email") or email
        plan = auth_json.get("plan_type") or auth_json.get("chatgpt_plan_type") or ""
        return save_codex_credential(auth_json, effective_email, plan)

    if not bool(getattr(_cfg, "CPA_SAVE_CALLBACK_RECEIPT", True)):
        return None

    safe_email = (email or "unknown").strip().replace("/", "_").replace("\\", "_")
    fname = f"codex-{safe_email}-sub2-callback.json"
    try:
        sub2_origin = _sub2_codex_base()
    except Exception:
        sub2_origin = ""
    record = {
        "type": "codex_sub2_callback",
        "email": email,
        "state": state,
        "auth_url": auth_url,
        "callback_url": callback_url,
        "sub2_origin": sub2_origin,
        "sub2_submit_response": submit_payload,
        "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "địa chỉ uỷ quyền do sub2 tạo; callback đã tải lên cho sub2. nếu sub2 phản hồi không chứa token, tệp này là bản ghi biên nhận cục bộ. ",
    }
    db.upsert_codex_credential(record, fname)
    return f"sqlite://codex_accounts/{fname}"


# ============================================================
# Lối vào
# ============================================================

def run_codex_oauth(
    email: str,
    otp_provider=None,
    proxy: str | None = None,
    force: bool = False,
    _cpa_reauth_round: int = 1,
) -> dict:
    """
    注册成功后的 Codex OAuth 授权入口（全新 session + 接码方案）。

    不复用注册的 session：内部新建干净 BrowserSession，从头登录该邮箱，
    走 邮箱 OTP → 手机短信验证 → 选 workspace → 拿 code → 换 token → 落盘。

    Args:
        email: 已注册成功的账号邮箱
        otp_provider: 邮箱 OTP 获取回调 fn(email, after_ts)->code，默认用 wait_for_otp
        proxy: 代理（不传从 PROXY_POOL 抽）
        force: True 时跳过 ENABLE_CODEX_AUTO 开关限制，供手动补跑使用

    Returns:
        结构化结果 dict。任何异常都被吞掉转 status=failed，不向上抛，不影响注册主流程。
    """
    if not force and not _cfg.ENABLE_CODEX_AUTO:
        return _codex_result(status="skipped", message="ENABLE_CODEX_AUTO=False")
    if not email:
        return _codex_result(status="skipped", message="email trống")

    # Codex OAuth hỗ trợ nhiều driver:
    # protocol: giao thức thuần gốc; roxy/cloak/browser_use: dùng trình duyệt thật chạy trang và bắt localhost callback.
    try:
        from config import codex as _codex_cfg
        from config import roxybrowser as _roxy_cfg
        oauth_driver = str(getattr(_codex_cfg, "CODEX_OAUTH_DRIVER", "protocol") or "protocol").strip().lower()
        if oauth_driver == "same_as_registration":
            oauth_driver = str(getattr(_roxy_cfg, "REGISTRATION_DRIVER", "protocol") or "protocol").strip().lower()
        if oauth_driver in ("roxy", "roxybrowser", "fingerprint", "browser"):
            from core.roxy_codex_oauth import run_roxy_codex_oauth
            return run_roxy_codex_oauth(email, otp_provider=otp_provider, proxy=proxy, force=True)
        if oauth_driver in ("browser_use", "browseruse", "browser-use", "bu"):
            from core.browser_use_codex_oauth import run_browser_use_codex_oauth
            return run_browser_use_codex_oauth(email, otp_provider=otp_provider, proxy=proxy, force=True)
        if oauth_driver in ("skyvern", "sv"):
            from core.skyvern_codex_oauth import run_skyvern_codex_oauth
            return run_skyvern_codex_oauth(email, otp_provider=otp_provider, proxy=proxy, force=True)
        if oauth_driver in ("cloak", "cloakbrowser"):
            from config import cloakbrowser as _cloak_cfg
            from core.cloakbrowser_driver import build_cloak_driver
            from core.roxy_codex_oauth import run_roxy_codex_oauth
            driver, opened = build_cloak_driver(proxy=proxy)
            try:
                return run_roxy_codex_oauth(
                    email,
                    otp_provider=otp_provider,
                    proxy=proxy,
                    force=True,
                    existing_driver=driver,
                    existing_opened=opened,
                    reuse_existing_profile=True,
                    clear_existing_state=True,
                )
            finally:
                if not bool(getattr(_cloak_cfg, "CLOAK_KEEP_BROWSER_OPEN", False)):
                    try:
                        driver.quit()
                    except Exception:
                        pass
        if oauth_driver not in ("protocol", "api", "http"):
            raise RuntimeError(f"[Codex] Không hỗ trợ CODEX_OAUTH_DRIVER={oauth_driver!r}, tuỳ chọn protocol / roxy / cloak / browser_use / skyvern")
    except ImportError:
        # Khi chưa cài selenium / chưa cung cấp cấu hình roxy thì tiếp tục dùng chế độ protocol, giữ hành vi cũ.
        pass

    if otp_provider is None:
        from core.email_provider import wait_for_otp as otp_provider

    # Toàn bộ một lần ủy quyền Codex dùng thống nhất một danh tính; tác vụ tiếp theo dù cùng tài khoản cũng tạo danh tính cô lập hoàn toàn mới.
    task_seed = f"codex-oauth:{email.lower()}:{uuid.uuid4()}"
    session = BrowserSession(proxy=proxy, fingerprint_seed=task_seed)
    try:
        logger.info(f"[Codex] Bắt đầu uỷ quyền (Mới hoàn toàn session): {email}")
        logger.info(
            "[Codex] Thống nhất ngữ cảnh fingerprint: device_id=%s oai_session_id=%s auth_session_logging_id=%s %s",
            session.device_id,
            session.oai_session_id,
            session.auth_session_logging_id,
            session.fingerprint_summary_text(),
        )

        # 1. Địa chỉ ủy quyền
        #    Mặc định do CPA tạo (local không tạo PKCE/state); chế độ local giữ code cũ để tương thích.
        auth_source = _codex_auth_url_source()
        cpa_auth = None
        code_verifier = None
        code_challenge = None
        auth_url = None
        if auth_source == "cpa":
            cpa_auth = _request_cpa_authorize_url()
            state = cpa_auth["state"]
            auth_url = cpa_auth["auth_url"]
            logger.info(f"[Codex] Đang dùng CPA Địa chỉ uỷ quyền: {auth_url}")
        elif auth_source == "sub2":
            sub2_auth = _request_sub2_authorize_url()
            state = sub2_auth["state"]
            auth_url = sub2_auth["auth_url"]
            logger.info(f"[Codex] Đang dùng sub2 Địa chỉ uỷ quyền: {auth_url}")
        elif auth_source == "local":
            code_verifier, code_challenge = _generate_pkce()
            state = _generate_state()
            logger.info("[Codex] Hiện đang dùng local PKCE tạo địa chỉ uỷ quyền, đầy đủ URL Sẽ trong bootstrap đầu ra giai đoạn")
        else:
            raise RuntimeError(f"[Codex] Không hỗ trợ CODEX_AUTH_URL_SOURCE={auth_source!r}")

        # 2. Kiểm tra trước mạng + thiết lập phiên. Kiểm tra trước không mang email, không kích hoạt OTP;
        #    Việc authorize/continue thực sự đốt email chỉ chạy sau khi precheck thành công.
        _codex_auth_preflight(session)
        human_delay("navigate")

        _bootstrap_authorize(session, state, code_challenge, auth_url=auth_url)
        human_delay("navigate")

        # 3. Gửi email. Tiếp theo không đoán luồng theo “tài khoản có mật khẩu hay không”, mà dựa vào những gì Auth thực sự trả về
        #    lấy page/type/continue_url làm chuẩn; tài khoản mật khẩu chỉ là thông tin xác thực khả dụng khi trang mật khẩu xuất hiện.
        otp_after_ts = time.time()
        auth_result = _submit_email(session, email)
        human_delay("form")
        login_status, early_callback_url, auth_result = _try_password_mfa_login(
            session, email, state, auth_result
        )
        password_login_done = login_status == "logged_in"

        # 4. Chỉ khi Auth rõ ràng đưa quy trình đến trang xác minh email thì mới poll OTP email.
        if not password_login_done and (
            login_status == "email_otp" or _is_email_otp_step(auth_result)
        ):
            email_otp = None
            max_email_otp_attempts = 3
            for email_otp_attempt in range(1, max_email_otp_attempts + 1):
                logger.info(f"[Codex] chờ email OTP: {email} (thứ {email_otp_attempt}/{max_email_otp_attempts} lần)")
                try:
                    email_otp = otp_provider(email, after_ts=otp_after_ts)
                    break
                except Exception as exc:
                    if email_otp_attempt >= max_email_otp_attempts:
                        raise
                    logger.warning(
                        "[Codex] mãi chưa nhận được email OTP, gửi lại email để kích hoạt gửi lại rồi tiếp tục chờ (vòng tiếp theo %s/%s): %s: %s",
                        email_otp_attempt + 1,
                        max_email_otp_attempts,
                        type(exc).__name__,
                        str(exc)[:180],
                    )
                    otp_after_ts = time.time()
                    auth_result = _submit_email(session, email)
                    human_delay("api")
                    retry_status, retry_callback_url, retry_result = _try_password_mfa_login(
                        session, email, state, auth_result
                    )
                    if retry_status == "logged_in":
                        password_login_done = True
                        early_callback_url = retry_callback_url
                        auth_result = retry_result
                        break
            if not password_login_done:
                logger.info(f"[Codex] email OTP đã nhận: {email_otp}")
                human_delay("otp_input")
                auth_result = _submit_email_otp(session, email_otp)
                human_delay("api")

        # Sau xác minh email vẫn có thể bị Auth yêu cầu MFA; chỉ submit TOTP khi trả về trạng thái MFA.
        if not password_login_done and _is_mfa_step(
            auth_result, _extract_continue_url(auth_result)
        ):
            auth_result = _complete_mfa_if_required(session, email, auth_result)
            continue_url = _extract_continue_url(auth_result)
            early_callback_url = _follow_login_continue(
                session, continue_url, state
            ) if continue_url else early_callback_url

        # 5. Việc có cần số điện thoại cũng hoàn toàn do Auth trả về quyết định, không còn thực thi cố định vì đã qua OTP/mật khẩu.
        if _is_phone_step(auth_result):
            logger.info("[Codex] Auth yêu cầu rõ xác minh số điện thoại, bắt đầu nhận mã: %s", email)
            phone_result = _do_phone_verification(session)
            phone_continue = _extract_continue_url(phone_result)
            if phone_continue:
                early_callback_url = _follow_login_continue(
                    session, phone_continue, state
                ) or early_callback_url
                auth_result = phone_result
            human_delay("post_auth")
        else:
            logger.info(
                "[Codex] Auth không yêu cầu xác minh số điện thoại, Bỏ qua: email=%s page=%s continue=%s",
                email,
                _page_type(auth_result) or "-",
                _extract_continue_url(auth_result) or "-",
            )

        # 6. Chọn workspace → lấy callback code; nếu login continue đã trúng callback trực tiếp thì tái sử dụng.
        callback_url = early_callback_url or _select_workspace_and_get_callback(session, state)
        code = _extract_code(callback_url, state)
        logger.info(f"[Codex] Đã lấy được authorization code: {code[:24]}...")

        # 7A. Chế độ CPA: giao callback URL cho CPA, CPA giữ verifier và hoàn tất đổi token / ghi auth.
        #     Cục bộ không còn dùng code đổi token; chỉ lưu tệp ủy quyền hoặc biên nhận callback mà CPA trả về.
        if auth_source == "cpa":
            submit_payload = _submit_cpa_callback(callback_url)
            path = _save_cpa_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url or "",
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "CPA callback submitted"
            logger.info(f"[Codex][CPA] thành công: {email}，{msg}, bản ghi cục bộ={path or 'disabled'}")
            return _codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=str(msg),
            )

        # 7A-sub2. Chế độ sub2: tải URL callback lên sub2.
        if auth_source == "sub2":
            submit_payload = _submit_sub2_callback(
                callback_url,
                session_id=(sub2_auth or {}).get("session_id", ""),
                redirect_uri=(parse_qs(urlparse(auth_url or "").query).get("redirect_uri") or [""])[0],
            )
            path = _save_sub2_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url or "",
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "sub2 callback uploaded"
            logger.info(f"[Codex][sub2] thành công: {email}，{msg}, bản ghi cục bộ={path or 'disabled'}")
            return _codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=str(msg),
            )

        # 7B. chế độ local: giữ triển khai cũ, dùng verifier cục bộ đổi token và lưu file ủy quyền tương thích CPA.
        if not code_verifier:
            raise RuntimeError("[Codex] local Thiếu chế độ code_verifier")
        token_resp = exchange_codex_token(session, code, code_verifier)

        # 8. Phân tích id_token + ghi đĩa
        id_claims = _parse_id_token(token_resp.get("id_token", ""))
        effective_email = id_claims.get("email") or email
        storage = build_codex_storage(token_resp, id_claims)
        path = save_codex_credential(storage, effective_email, id_claims.get("plan_type", ""))

        logger.info(
            f"[Codex] thành công: {effective_email}，plan={id_claims.get('plan_type') or 'unknown'}, "
            f"account_id={id_claims.get('account_id') or 'unknown'}, Đã lưu vào {path}"
        )
        return _codex_result(
            status="success",
            ok=True,
            email=effective_email,
            file_path=str(path),
            callback_url=callback_url,
            message=f"plan={id_claims.get('plan_type') or 'unknown'}",
        )
    except AccountUnusableError as exc:
        logger.warning(f"[Codex] Tài khoản đã chết ({exc.error_code}）：{email}")
        return _codex_result(
            status="deactivated",
            email=email,
            message=f"Tài khoản đã chết ({exc.error_code}）",
        )
    except Exception as exc:
        if _is_cpa_callback_reauth_error(exc) and _cpa_reauth_round < 2:
            logger.warning(
                "[Codex][CPA] callback trả về Timeout waiting for OAuth callback, bắt đầu lại lần thứ %s/2 vòng Codex uỷ quyền: %s",
                _cpa_reauth_round + 1, email,
            )
            return run_codex_oauth(
                email,
                otp_provider=otp_provider,
                proxy=proxy,
                force=force,
                _cpa_reauth_round=_cpa_reauth_round + 1,
            )
        logger.warning(f"[Codex] Thất bại: {email}，{type(exc).__name__}: {str(exc)[:200]}")
        logger.debug("[Codex] Chi tiết thất bại:", exc_info=True)
        return _codex_result(
            status="failed",
            email=email,
            message=f"{type(exc).__name__}: {str(exc)[:200]}",
        )
