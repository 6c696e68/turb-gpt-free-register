# -*- coding: utf-8 -*-
"""
ChatGPT Auth mô-đun khối
chỗ lý chatgpt.com miền tên dưới xác thựcrequest（bước1-3）
"""
import json
import logging
from urllib.parse import urlencode, urlparse, parse_qs

from core.session import BrowserSession
from config import (
    OPENAI_CLIENT_ID, OPENAI_SCOPE, OPENAI_AUDIENCE, OPENAI_REDIRECT_URI
)

logger = logging.getLogger(__name__)

# 2026-09-14 Roxy 成功样本：signin 不再主动携带 passkey capabilities；
# authorize 使用两个 ccaps，并明确返回 ChatGPT 首页。
_CC_CAPS = "login_methods chatgpt_login_finalizer_v1"


def _ensure_authorize_context(authorize_url: str, session: BrowserSession, email: str) -> str:
    """
với NextAuth trả về authorize URL làm cuốifallback：xác nhận giữ hiện tạifrontendmặc định
login_or_signup chuỗi ngữ cảnhtham sốkhông cótại lại định tới tạogiai đoạnmất mất 。
"""
    try:
        parsed = urlparse(authorize_url)
        if not parsed.netloc.endswith("auth.openai.com"):
            return authorize_url
        params = parse_qs(parsed.query, keep_blank_values=True)
        # 旧实现主动注入该字段；当前成功浏览器 authorize 已不携带。
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
bước1: lấy OAuth Providers list。
GET https://chatgpt.com/api/auth/providers

xác thực và chatgpt.com kết nốilà không bình thường， và lấycó thể dùng OAuth nêu chonhà cung cấp 。

Returns:
providers ký tự điển ，ví dụ nếu :
{
\"openai\": {
\"id\": \"openai\",
\"name\": \"openai\",
\"type\": \"oauth\",
\"signinUrl\": \"https://chatgpt.com/api/auth/signin/openai\",
\"callbackUrl\": \"https://chatgpt.com/api/auth/callback/openai\"
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
bước2: lấy CSRF Token。
GET https://chatgpt.com/api/auth/csrf

CSRF token tại sau đó signin request dùng。

Returns:
csrfToken ký tự ký hiệu chuỗi
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
    """theo Web trang đăng nhậpthuận thứ tự tại providers sau đóđọcmột ẩn tên NextAuth session。"""
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
bước3: gửi OAuth Signin request。
POST https://chatgpt.com/api/auth/signin/openai

cấu trúc tạo OAuth uỷ quyềntham số，lấy authorize URL。

Args:
session: trình duyệtphiên
csrf_token: từbước2lấy CSRF token
email: đăng kýemail

Returns:
authorize_url: auth.openai.com uỷ quyền URL
"""
    # 构造 URL 查询参数
    query_params = {
        "prompt": "login",
        "ext-oai-did": session.device_id,
        "auth_session_logging_id": session.auth_session_logging_id,
        "screen_hint": "login_or_signup",
        "login_hint": email,
    }
    url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query_params)

    # 构造请求头
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/auth/login")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    # 构造请求体
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
