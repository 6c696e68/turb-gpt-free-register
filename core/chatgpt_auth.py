# -*- coding: utf-8 -*-
"""
Mô-đun ChatGPT Auth
Xử lý các yêu cầu xác thực trên tên miền chatgpt.com (bước 1-3)
"""
import json
import logging
from urllib.parse import urlencode, urlparse, parse_qs

from core.session import BrowserSession
from config import (
    OPENAI_CLIENT_ID, OPENAI_SCOPE, OPENAI_AUDIENCE, OPENAI_REDIRECT_URI
)

logger = logging.getLogger(__name__)

# 2026-09-14 mẫu thành công Roxy: signin không còn chủ động mang passkey capabilities;
# authorize dùng hai ccaps, và trả rõ về trang chủ ChatGPT.
_CC_CAPS = "login_methods chatgpt_login_finalizer_v1"


def _ensure_authorize_context(authorize_url: str, session: BrowserSession, email: str) -> str:
    """
    Xử lý dự phòng cuối cho authorize URL do NextAuth trả về: đảm bảo các tham số ngữ cảnh
    của luồng login_or_signup mặc định phía frontend không bị mất ở giai đoạn tạo chuyển hướng.
    """
    try:
        parsed = urlparse(authorize_url)
        if not parsed.netloc.endswith("auth.openai.com"):
            return authorize_url
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Bản cũ chủ động inject trường này; authorize trình duyệt thành công hiện tại đã không mang theo.
        changed = bool(params.pop("ext-passkey-client-capabilities", None))
        ui_locale = session.navigator_language()
        required = {
            "ext-oai-did": session.device_id,
            "auth_session_logging_id": session.auth_session_logging_id,
            "screen_hint": "login_or_signup",
            "login_hint": email,
            "ui_locales": ui_locale,
            "ccaps": _CC_CAPS,
            "auth_return_target_category": "chatgpt_home",
        }
        for key, value in required.items():
            if key in {"ccaps", "auth_return_target_category", "ui_locales"}:
                if params.get(key) != [value]:
                    params[key] = [value]
                    changed = True
            elif not params.get(key):
                params[key] = [value]
                changed = True
        if not changed:
            return authorize_url
        logger.info(
            "[Bước3] đã căn chỉnh ngữ cảnh authorize：ui_locales=%s oai-did=%s",
            ui_locale,
            str(session.device_id)[:12] + "...",
        )
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()
    except Exception:
        return authorize_url


def get_providers(session: BrowserSession) -> dict:
    """
    Bước 1: Lấy danh sách OAuth Providers.
    GET https://chatgpt.com/api/auth/providers

    Kiểm tra kết nối với chatgpt.com có bình thường không, và lấy các nhà cung cấp OAuth khả dụng.

    Returns:
        dict providers, ví dụ:
        {
            "openai": {
                "id": "openai",
                "name": "openai",
                "type": "oauth",
                "signinUrl": "https://chatgpt.com/api/auth/signin/openai",
                "callbackUrl": "https://chatgpt.com/api/auth/callback/openai"
            },
            ...
        }
    """
    url = "https://chatgpt.com/api/auth/providers"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")

    logger.info("[Bước1] lấy OAuth Providers...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    logger.info(f"[Bước1] lấy thành công {len(data)} providers: {list(data.keys())}")
    return data


def get_csrf_token(session: BrowserSession) -> str:
    """
    Bước 2: Lấy CSRF Token.
    GET https://chatgpt.com/api/auth/csrf

    CSRF token sẽ được dùng trong các request signin tiếp theo.

    Returns:
        chuỗi csrfToken
    """
    url = "https://chatgpt.com/api/auth/csrf"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")

    logger.info("[Bước2] lấy CSRF Token...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()

    data = resp.json()
    csrf_token = data.get("csrfToken", "")
    logger.info(f"[Bước2] lấy CSRF Token thành công: {csrf_token[:20]}...")
    return csrf_token


def probe_auth_session(session: BrowserSession) -> dict:
    """Đọc một lần session NextAuth ẩn danh theo thứ tự trang đăng nhập Web sau providers."""
    url = "https://chatgpt.com/api/auth/session"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")
    logger.info("[Bước1.5] đọc Auth Session ẩn danh...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()
    try:
        data = resp.json()
    except Exception:
        data = {}
    return data if isinstance(data, dict) else {}


def signin_openai(session: BrowserSession, csrf_token: str, email: str) -> str:
    """
    Bước 3: Gửi request OAuth Signin.
    POST https://chatgpt.com/api/auth/signin/openai

    Xây tham số ủy quyền OAuth, lấy authorize URL.

    Args:
        session: phiên trình duyệt
        csrf_token: CSRF token lấy từ bước 2
        email: email đăng ký

    Returns:
        authorize_url: URL ủy quyền của auth.openai.com
    """
    # Xây dựng tham số truy vấn URL
    query_params = {
        "prompt": "login",
        "ext-oai-did": session.device_id,
        "auth_session_logging_id": session.auth_session_logging_id,
        "screen_hint": "login_or_signup",
        "login_hint": email,
    }
    url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query_params)

    # Tạo header yêu cầu
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    # Tạo body yêu cầu
    body = urlencode({
        "callbackUrl": "/",
        "csrfToken": csrf_token,
        "json": "true",
    })

    logger.info(f"[Bước3] gửi request OAuth Signin, email: {email}")
    resp = session.post(url, headers=headers, data=body)
    resp.raise_for_status()

    data = resp.json()
    authorize_url = data.get("url", "")

    if not authorize_url:
        raise ValueError(f"[Bước3] không lấy được authorize URL, phản hồi: {data}")

    authorize_url = _ensure_authorize_context(authorize_url, session, email)
    logger.info("[Bước3] lấy authorize URL thành công, đã xác nhận ngữ cảnh login_or_signup/oai-did")
    logger.debug(f"[Bước3] URL: {authorize_url[:160]}...")
    return authorize_url
