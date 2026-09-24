# -*- coding: utf-8 -*-
"\nsau đăng ký xử lý module: \n  1. kéo /api/auth/session, từ trong trích accessToken / user thông tin\n  2. thiết lập 2FA(TOTP), trả về secret\n  3.  tài khoản thông tin(email + accessToken + TOTP secret)lưu đến SQLite\n\ntổng thể tái dùng đăng ký giai đoạn  BrowserSession(cùng một cookie jar / cùng một IP / cùng một UA), \ntránh lại bắt đầu mới phiên bị kiểm soát rủi ro liên quan hoặc thiếu đăng nhập trạng thái. \n"
import json
import logging
import random
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

import pyotp

from core.session import BrowserSession
from core.humanize import delay as human_delay

logger = logging.getLogger(__name__)


def _clear_twofa_session_circuit(
    session: BrowserSession, *, source: str = "làm nóng tuỳ chọn"
) -> None:
    "dọn 2FA có thể khôi phục bước bước trạng thái ngắt mạch do. \n\n  đăng nhập trạng thái bootstrap sẽ truy cập một số không then chốt trước đầu API; trong đó bất kỳ một API  403 đều sẽ\n  kích hoạt BrowserSession  thông dùng ngắt mạch bộ. làm nóng này thân cho phép thất bại, do đó không thể để này ngắt mạch tiếp tục\n  chặn sau mặt đang kiểu request xác thực lại(đặc biệt đó là ``/api/auth/csrf``). \n  "
    blocked_reason = str(getattr(session, "blocked_reason", "") or "")
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
    elif getattr(session, "blocked_until", 0.0):
        # 兼容测试桩或旧版 BrowserSession。
        session.blocked_until = 0.0
        session.blocked_reason = ""
    if blocked_reason:
        logger.info("[2FA] đã dọn%s trạng thái ngắt mạch do: %s", source, blocked_reason)


_RETRYABLE_REAUTH_HINTS = (
    "403", "408", "425", "429", "500", "502", "503", "504",
    "proxy", "socks", "timeout", "timed out", "connection", "closed",
    "reset", "temporarily unavailable", "熔断冷却",
)


def _is_retryable_reauth_error(exc: BaseException) -> bool:
    "chỉ thử lại giới hạn tốc độ, máy chủ lỗi và lỗi truyền, không thử lại nghiệp vụ thường 4xx. "
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    if status:
        return status in (403, 408, 425, 429) or status >= 500
    text = str(exc or "").lower()
    return any(hint in text for hint in _RETRYABLE_REAUTH_HINTS)


def _trigger_reauth_with_retry(session: BrowserSession, email: str) -> str:
    "với CSRF + signin giai đoạn tạm sự cố thực thi có số mũ giới hạn số lùi thử lại. "
    from config import twofa as _twofa_cfg

    max_attempts = max(1, min(8, int(
        getattr(_twofa_cfg, "TWOFA_REAUTH_MAX_ATTEMPTS", 3) or 3
    )))
    base_delay = max(0.0, min(60.0, float(
        getattr(_twofa_cfg, "TWOFA_REAUTH_RETRY_DELAY", 3.0) or 0.0
    )))
    last_exc: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            auth_url = _trigger_reauth(session, email)
            if attempt > 1:
                logger.info("[2FA] thử lại khởi tạo xác thực lại thành công: attempt=%s/%s", attempt, max_attempts)
            return auth_url
        except Exception as exc:
            last_exc = exc
            retryable = _is_retryable_reauth_error(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning(
                    "[2FA] khởi tạo xác thực lại thất bại và không thử lại: attempt=%s/%s retryable=%s error=%s: %s",
                    attempt, max_attempts, retryable, type(exc).__name__, str(exc)[:200],
                )
                raise

            # 403/429 已开启 BrowserSession 熔断；不清理会导致下一轮在本地直接失败。
            _clear_twofa_session_circuit(session, source="request xác thực lại")
            delay = min(120.0, base_delay * (2 ** (attempt - 1)))
            logger.warning(
                "[2FA] khởi tạo xác thực lại thất bại tạm: attempt=%s/%s error=%s: %s; %.1fs rồi thử lại",
                attempt, max_attempts, type(exc).__name__, str(exc)[:200], delay,
            )
            if delay > 0:
                time.sleep(delay)

    assert last_exc is not None
    raise last_exc


def _follow_reauth_with_retry(session: BrowserSession, auth_url: str) -> str:
    "thử lại liên site authorize điều hướng; đầu  403 dưới gửi  CF Cookie có thể cung cấp dưới một vòng tái dùng. "
    from config import twofa as _twofa_cfg

    max_attempts = max(1, min(8, int(
        getattr(_twofa_cfg, "TWOFA_REAUTH_MAX_ATTEMPTS", 3) or 3
    )))
    base_delay = max(0.0, min(60.0, float(
        getattr(_twofa_cfg, "TWOFA_REAUTH_RETRY_DELAY", 3.0) or 0.0
    )))

    # 新建协议会话此前会从 ChatGPT 直接命中复杂 authorize URL，auth 域没有
    # document/locale/CF Cookie 上下文。先用简单页面做 best-effort 预热；预热
    # 和正式 authorize 仍严格复用同一个 BrowserSession/deviceId/Cookie Jar。
    _warm_auth_document_for_reauth(session)

    for attempt in range(1, max_attempts + 1):
        try:
            result = _follow_reauth(session, auth_url)
            if attempt > 1:
                logger.info("[2FA] authorize thử lại điều hướng thành công: attempt=%s/%s", attempt, max_attempts)
            return result
        except Exception as exc:
            retryable = _is_retryable_reauth_error(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning(
                    "[2FA] authorize điều hướng thất bại và không thử lại: attempt=%s/%s retryable=%s error=%s: %s",
                    attempt, max_attempts, retryable, type(exc).__name__, str(exc)[:200],
                )
                raise

            # 403 响应通常会刷新 __cf_bm。清理本地熔断但保留 Cookie Jar，
            # 下一轮继续使用同一 OAuth state 和新 Cookie 导航。
            _clear_twofa_session_circuit(session, source="authorize điều hướng")
            delay = min(120.0, base_delay * (2 ** (attempt - 1)))
            logger.warning(
                "[2FA] authorize điều hướng thất bại tạm: attempt=%s/%s error=%s: %s; "
                "%.1fs rồi tái dùng CF Cookie thử lại",
                attempt, max_attempts, type(exc).__name__, str(exc)[:200], delay,
            )
            if delay > 0:
                time.sleep(delay)

    raise RuntimeError("authorize hết lượt thử điều hướng")


def _warm_auth_document_for_reauth(session: BrowserSession) -> None:
    "làm nóng auth.openai.com tầng trên tài liệu; 403 khi giữ mới Cookie sau có giới hạn thử lại. "
    get_headers = getattr(session, "get_auth_navigate_headers", None)
    request_get = getattr(session, "get", None)
    if not callable(get_headers) or not callable(request_get):
        return
    headers = get_headers(referer="", user_initiated=False)
    for attempt in range(1, 3):
        try:
            resp = request_get(
                "https://auth.openai.com/log-in",
                headers=headers,
                allow_redirects=True,
            )
            status = int(getattr(resp, "status_code", 0) or 0)
            if status < 400:
                logger.info("[2FA] Auth document làm nóng xong")
                return
            logger.info("[2FA] Auth document làm nóng trả về HTTP %s, giữ phản hồi Cookie", status)
        except Exception as exc:
            logger.debug("[2FA] Auth document làm nóng ngoại lệ: %s: %s", type(exc).__name__, str(exc)[:160])
        _clear_twofa_session_circuit(session, source="Auth document làm nóng")
        if attempt < 2:
            time.sleep(float(attempt))
    logger.info("[2FA] Auth document làm nóng chưa đạt, tiếp tục đang kiểu authorize chuỗi thử lại")


def _post_register_dwell_seconds(seconds_range: str | None = None) -> float:
    if seconds_range is None:
        try:
            from config import register as _register_cfg

            raw = str(getattr(_register_cfg, "POST_REGISTER_DWELL_SECONDS_RANGE", "5,15") or "0,0").strip()
        except Exception:
            raw = "0,0"
    else:
        raw = str(seconds_range or "0,0").strip()
    try:
        parts = [float(x.strip()) for x in raw.replace(";", ",").replace("|", ",").split(",") if x.strip()]
        if not parts:
            lo = hi = 0.0
        elif len(parts) == 1:
            lo = hi = parts[0]
        else:
            lo, hi = parts[0], parts[1]
    except Exception:
        lo = hi = 0.0
    lo, hi = max(0.0, lo), max(0.0, hi)
    if hi < lo:
        lo, hi = hi, lo
    seconds = random.uniform(lo, hi) if hi > lo else lo
    return max(0.0, min(300.0, seconds))


def post_register_dwell(
    email: str,
    *,
    label: str = "sau đăng ký",
    seconds_range: str | None = None,
) -> None:
    "dừng ngẫu nhiên sau khi đăng ký thành công một đoạn khi khoảng; cung cấp khác driver trình duyệt tái dùng. "
    seconds = _post_register_dwell_seconds(seconds_range)
    if seconds <= 0:
        return
    logger.info("[%s] dừng ngẫu nhiên sau khi đăng ký thành công %.1fs: %s", label, seconds, email)
    time.sleep(seconds)


def _account_material_line(email: str, row: dict | None = None) -> str:
    "ưu tiên xuất Outlook gốc nguyên liệu; không có nguyên liệu khi lùi về email địa chỉ. "
    if row:
        base = row.get("original_email_line") or row.get("email") or email
        password = ""
        if isinstance(row.get("extra_json"), str) and row.get("extra_json"):
            try:
                extra = json.loads(str(row.get("extra_json") or ""))
                password = str(extra.get("registration_password") or "").strip()
            except Exception:
                password = ""
        if not password:
            password = str(row.get("password") or "").strip()
        parts = [p for p in str(base or "").split("----") if p != ""]
        if password:
            if not parts:
                base = password
            elif len(parts) == 1:
                if parts[0] != password:
                    parts.insert(1, password)
                base = "----".join(parts)
            elif parts[1] != password:
                looks_like_material = (
                    parts[1].startswith("M.")
                    or parts[1].startswith("m.")
                    or (len(parts[1]) >= 32 and parts[1].count("-") >= 4)
                    or any(ch in parts[1] for ch in ("@", ":", "/", "\\"))
                )
                if looks_like_material:
                    parts.insert(1, password)
                    base = "----".join(parts)
        return base
    return email


def _account_copy_line(
    material_line: str,
    access_token: str,
    gpt_password: str | None = None,
    totp_secret: str | None = None,
) -> str:
    "tạo chứa token  cả dòng lưu trữ, bên thì từ lô lần tổng hợp file sao chép trong. "
    parts = [material_line, access_token]
    if gpt_password or totp_secret:
        parts.append(str(gpt_password or ""))
    if totp_secret:
        parts.append(totp_secret)
    return "----".join(parts)


def create_batch_archive_dir(count: int, workers: int = 1) -> None:
    "tương thích cũ gọi bên; lô lần số dữ liệu hiện ở trực tiếp lưu đến SQLite, không tạo lưu trữ thư mục. "
    return None


def _append_batch_archive(
    *,
    row_id: int,
    email: str,
    access_token: str,
    totp_secret: str | None,
    email_source: str | None,
    proxy_used: str | None,
    extra: dict,
    batch_dir: Path | None,
) -> None:
    "tương thích cũ gọi bên; đăng ký tài khoản đã qua bởi db.insert_account lưu đến SQLite. "
    from core import db
    # 参数保留是为了兼容注册驱动；不再读取 batch_dir 或写入任何归档文件。
    _ = (db, row_id, email, access_token, totp_secret, email_source, proxy_used, extra, batch_dir)
    return None


def follow_oauth_callback(session: BrowserSession, continue_url: str, referer: str = "https://auth.openai.com/about-you") -> str:
    "\n  bước bước 12.5: theo create_account trả về  continue_url, hoàn tất OAuth callback. \n\n  create_account thành công sau trả về  continue_url thường chỉ tới\n  https://auth.openai.com/authorize/continue?...\n  nó sẽ lại 302 đến\n  https://chatgpt.com/api/auth/callback/openai?code=...&state=...\n  callback request sẽ để chatgpt.com thiết lập `__Secure-next-auth.session-token` cookie, \n  của sau /api/auth/session mới có thể trả về accessToken. \n\n  Returns:\n  chuyển hướng tới chuỗi cuối cùng điểm đến URL(thường là chatgpt.com site trong địa chỉ)\n  "
    if not continue_url:
        raise ValueError("continue_url trống, không cách hoàn tất OAuth callback")

    # continue_url 通常是 auth.openai.com/authorize/continue；
    # OTP 后 external_url 分支也可能直接给 chatgpt.com 回调地址。
    # 按目标域名选择导航头，避免 auth step 正确但请求头语义不一致。
    if str(continue_url).startswith("https://chatgpt.com"):
        headers = session.get_chatgpt_navigate_headers(referer=referer)
    else:
        headers = session.get_auth_navigate_headers(referer=referer)

    logger.info(f"[OAuth callback] theo continue_url hoàn tất OAuth callback...")
    resp = session.get(continue_url, headers=headers, allow_redirects=True)
    # 必须在本阶段暴露 callback 的 403/429；否则 BrowserSession 虽已熔断，
    # 错误却会延迟到 fetch_session，查活无法针对 callback 原请求重试。
    resp.raise_for_status()
    observe = getattr(session, "observe_chatgpt_document", None)
    if callable(observe):
        observe(resp)
    log_cookies = getattr(session, "log_cookie_names", None)
    if callable(log_cookies):
        log_cookies("oauth_callback_complete")
    logger.info(f"[OAuth callback] hoàn tất, cuối cùng điểm đến: {resp.url}")
    return resp.url


def fetch_session(session: BrowserSession) -> dict:
    "\n  GET https://chatgpt.com/api/auth/session\n  đăng ký thành công sau ngay gọi, lấy được accessToken / user / account / expires. \n\n  Returns:\n  đầy đủ session JSON, chứa trường:\n  - accessToken: str (Bearer token, dùng để backend-api gọi)\n  - user: {id, name, email, idp, iat, mfa}\n  - account: {id, planType, structure, ...}\n  - expires: ISO khi khoảng chuỗi\n  "
    url = "https://chatgpt.com/api/auth/session"
    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")

    logger.info("[Session] kéo ChatGPT session thông tin...")
    resp = session.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()

    if not data.get("accessToken"):
        logger.error(f"[Session] trong phản hồi không có accessToken: {data}")
        raise RuntimeError("chưa lấy được accessToken, trạng thái đăng nhập có thể chưa được thiết lập")

    user = data.get("user") or {}
    account = data.get("account") or {}
    logger.info(
        f"[Session] thành công, user_id={user.get('id')}, email={user.get('email')}, "
        f"plan={account.get('planType')}, mfa={user.get('mfa')}"
    )
    return data


def _trigger_reauth(session: BrowserSession, email: str) -> str:
    "\n  bước bước 2-3: khởi tạo mật khẩu xác thực lại, trả về OpenAI authorize URL. \n  chuyển hướng tới chuỗi sẽ tự động kích hoạt email gửi một bản mới  OTP(dùng để 2FA xác thực lại). \n  "
    # 重新拿一次 csrf（旧的可能已过期）
    csrf_url = "https://chatgpt.com/api/auth/csrf"
    csrf_resp = session.get(csrf_url, headers=session.get_nextauth_headers(referer="https://chatgpt.com/"))
    csrf_resp.raise_for_status()
    csrf_token = csrf_resp.json()["csrfToken"]
    logger.info(f"[2FA] xác thực lại CSRF: {csrf_token[:20]}...")

    # POST /api/auth/signin/openai 带 reauth 参数
    query = {
        "connection": "password",
        "login_hint": email,
        "reauth": "password",
        "max_age": "0",
        "ext-oai-did": session.device_id,
    }
    signin_url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query)

    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    body = urlencode({
        "callbackUrl": "https://chatgpt.com/?action=enable&factor=totp",
        "csrfToken": csrf_token,
        "json": "true",
    })

    logger.info("[2FA] khởi tạo xác thực lại signin/openai...")
    resp = session.post(signin_url, headers=headers, data=body)
    resp.raise_for_status()
    auth_url = resp.json().get("url")
    if not auth_url:
        raise RuntimeError(f"chưa lấy được reauth authorize URL: {resp.text}")
    return auth_url


def _follow_reauth(session: BrowserSession, auth_url: str) -> str:
    "\n  bước bước 3: theo authorize URL kích hoạt email OTP gửi. \n  auth.openai.com sẽ chuyển hướng tới đến /email-verification trang, kỳ khoảng gửi OTP thư. \n  "
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")
    logger.info("[2FA] theo authorize URL, kích hoạt OTP gửi...")
    resp = session.get(auth_url, headers=headers, allow_redirects=True)
    resp.raise_for_status()
    logger.info(f"[2FA] điểm đến URL: {resp.url}")
    return str(getattr(resp, "url", "") or "")


def _validate_reauth_otp(session: BrowserSession, code: str) -> str:
    "\n  bước bước 4: gửi email OTP xác minh. \n  trả về continue_url(mang code tham số số  callback URL, dùng để nhảy về chatgpt.com). \n  "
    url = "https://auth.openai.com/api/accounts/email-otp/validate"
    headers = session.get_auth_headers(referer="https://auth.openai.com/email-verification")
    body = json.dumps({"code": code})

    logger.info(f"[2FA] gửi xác thực lại OTP: {code}")
    resp = session.post(url, headers=headers, data=body)
    resp.raise_for_status()
    data = resp.json()
    continue_url = data.get("continue_url")
    if not continue_url:
        raise RuntimeError(f"OTP phản hồi xác minh thiếu continue_url: {data}")
    return continue_url


def _exchange_new_token(session: BrowserSession, continue_url: str) -> str:
    "\n  bước bước 5: theo continue_url hoàn tất callback, lần nữa kéo /api/auth/session lấy được mới accessToken\n  (này khi token trong nhúng  pwd_auth_time là mới , 2FA enroll mới sẽ chấp nhận). \n  "
    headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
    logger.info("[2FA] theo continue_url, làm mới session-token cookie...")
    session.get(continue_url, headers=headers, allow_redirects=True)

    # 拿新的 accessToken
    new_session = fetch_session(session)
    new_token = new_session["accessToken"]
    logger.info(f"[2FA] mới accessToken(có mới pwd_auth_time): {new_token[:40]}...")
    return new_token


def _enroll_totp(session: BrowserSession, access_token: str) -> tuple[str, str]:
    "\n  bước bước 6: đăng ký TOTP, trả về (secret, session_id)\n  "
    url = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["authorization"] = f"Bearer {access_token}"
    headers["oai-device-id"] = session.device_id
    headers["oai-language"] = session.navigator_language()

    body = json.dumps({"factor_type": "totp"})

    logger.info("[2FA] đăng ký TOTP...")
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error(f"[2FA] enroll thất bại {resp.status_code}: {resp.text}")
        resp.raise_for_status()
    data = resp.json()
    secret = data.get("secret")
    session_id = data.get("session_id")
    if not secret or not session_id:
        raise RuntimeError(f"enroll thiếu trường phản hồi: {data}")
    logger.info(f"[2FA] TOTP secret đã lấy: {secret[:4]}...{secret[-4:]}")
    return secret, session_id


def _activate_totp(
    session: BrowserSession,
    access_token: str,
    secret: str,
    session_id: str,
) -> bool:
    "\n  bước bước 7: dùng secret tạo 6 chữ số TOTP mã, kích hoạt 2FA. \n  "
    url = "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["authorization"] = f"Bearer {access_token}"
    headers["oai-device-id"] = session.device_id
    headers["oai-language"] = session.navigator_language()

    totp_code = pyotp.TOTP(secret).now()
    body = json.dumps({
        "code": totp_code,
        "factor_type": "totp",
        "session_id": session_id,
    })

    logger.info(f"[2FA] kích hoạt enrollment, code={totp_code}")
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error(f"[2FA] activate thất bại {resp.status_code}: {resp.text}")
        resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"kích hoạt trả về success=false: {data}")
    return True


def setup_2fa(
    session: BrowserSession,
    email: str,
    otp_code: str | None = None,
    access_token: str | None = None,
) -> str:
    "\n  đầy đủ  2FA thiết lập quy trình. \n  sẽ kích hoạt lại gửi một bản email mã OTP: \n  - USE_EMAIL_SERVICE=True khi tự động từ Outlook tài khoản kho kéo\n  - nếu không cần người dùng thủ công nhập\n\n  Args:\n  session: đã hoàn tất đăng ký phiên\n  email: tài khoản email(dùng làm login_hint)\n  otp_code: email mã OTP(None thì theo trên chiến lược đã nêu lấy)\n\n  Returns:\n  TOTP secret(Base32 chuỗi), có thể trực tiếp dùng để pyotp.TOTP() tạo 6 chữ số động mã\n  "
    # 用模块属性读，支持 WebUI 热加载
    from config import email as _email_cfg
    from core.chatgpt_bootstrap import authenticated_bootstrap

    logger.info("=" * 60)
    logger.info("bắt đầu thiết lập 2FA")
    logger.info("=" * 60)

    if access_token:
        try:
            logger.info("[2FA] dùng hiện có accessToken làm nóng trạng thái đăng nhập...")
            authenticated_bootstrap(session, access_token, strict=False)
            human_delay("navigate")
            logger.info("[2FA] accessToken làm nóng xong")
        except Exception as exc:
            logger.warning("[2FA] accessToken làm nóng thất bại, tiếp tục theo quy trình xác thực lại: %s: %s", type(exc).__name__, str(exc)[:180])
        finally:
            # authenticated_bootstrap(strict=False) 是可选预热。其非关键接口返回
            # 403 时会开启会话级熔断，若不清理，下一步 CSRF 请求甚至不会发出。
            _clear_twofa_session_circuit(session, source="làm nóng tuỳ chọn")

    # 阶段一：重认证
    logger.info("[2FA] giai đoạn 1: khởi tạo xác thực lại")
    reauth_otp_after_ts = time.time()
    auth_url = _trigger_reauth_with_retry(session, email)
    logger.info("[2FA] xác thực lại authorize URL đã lấy")
    human_delay("api")
    _follow_reauth_with_retry(session, auth_url)
    logger.info("[2FA] đã theo xác thực lại authorize URL")
    # 浏览器登录页在落到 email-verification 后还会显式 GET
    # /api/accounts/email-otp/send；仅跟随 authorize URL 有时只打开页面而不真正
    # 投递邮件，尤其是复用 accessToken 的 reauth 场景。与查活/网页登录保持一致，
    # 显式触发一次发送。
    from core.openai_auth import send_email_otp
    send_email_otp(session)
    logger.info("[2FA] đã kích hoạt xác thực lại email một cách tường minh OTP gửi")
    human_delay("navigate")

    if otp_code is None:
        if _email_cfg.USE_EMAIL_SERVICE:
            from core.email_provider import wait_for_otp
            logger.info("[2FA] tự chờ xác thực lại email OTP...")
            try:
                otp_code = wait_for_otp(email, after_ts=reauth_otp_after_ts)
            except Exception as first_wait_exc:
                # 重认证页本身没有可靠的 resend API；重新发起一次 authorize
                # 流程会让 auth.openai.com 再发送一封新的 OTP。只自动重发一次，
                # 避免邮箱服务异常时无限重复触发验证码。
                logger.warning(
                    "[2FA] lần chờ xác thực lại đầu tiên OTP timeout, thử gửi lại mã OTP: %s: %s",
                    type(first_wait_exc).__name__, str(first_wait_exc)[:180],
                )
                reauth_otp_after_ts = time.time()
                resend_auth_url = _trigger_reauth_with_retry(session, email)
                human_delay("api")
                _follow_reauth_with_retry(session, resend_auth_url)
                send_email_otp(session)
                logger.info("[2FA] đã kích hoạt lại xác thực lại OTP, bắt đầu vòng chờ thứ hai")
                # Remail 的 receivedAt 可能比本地发送时间早几十秒（网关缓存/时钟
                # 偏差），重发后的第二轮放宽时间下界，避免已到邮箱却被 after_ts
                # 过滤掉；若拿到旧码，后面的 401 重试逻辑仍会校验。
                broad_after_ts = max(0.0, reauth_otp_after_ts - 120.0)
                logger.info("[2FA] vòng lấy mã thứ hai bật dung sai lệch thời gian: after_ts=%.0f", broad_after_ts)
                otp_code = wait_for_otp(email, after_ts=broad_after_ts)
            logger.info("[2FA] đã nhận xác thực lại email OTP")
        else:
            logger.info("")
            logger.info("[2FA] hãy kiểm tra email, nhập mã mới nhận 6 chữ số mã OTP")
            otp_code = input(">>> 2FA mã OTP: ").strip()
            logger.info("[2FA] đã nhập thủ công xác thực lại email OTP")

    human_delay("otp_input")
    logger.info("[2FA] đang gửi xác thực lại email OTP...")
    try:
        continue_url = _validate_reauth_otp(session, otp_code)
    except Exception as first_exc:
        # 部分取码接口会短暂返回缓存中的上一封邮件。若服务端拒绝验证码，
        # 重新轮询一次并提交最新候选，避免第一次旧码直接终止整个 2FA 流程。
        status_code = getattr(getattr(first_exc, "response", None), "status_code", None)
        if status_code != 401 or not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
            raise
        logger.warning("[2FA] lần đầu OTP bị từ chối, lấy lại mã OTP mới nhất rồi thử một lần nữa")
        from core.email_provider import wait_for_otp
        retry_settle = max(8, int(getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5) or 5))
        fresh_otp = wait_for_otp(
            email,
            after_ts=reauth_otp_after_ts,
            settle_seconds=retry_settle,
        )
        if fresh_otp == otp_code:
            logger.warning("[2FA] thử lại vẫn lấy được cùng OTP=%s, tiếp tục gửi để giữ thông báo lỗi gốc", fresh_otp)
        else:
            logger.info("[2FA] đã lấy mới OTP=%s, thay ứng viên lần đầu", fresh_otp)
        otp_code = fresh_otp
        continue_url = _validate_reauth_otp(session, otp_code)
    logger.info("[2FA] xác thực lại email OTP xác minh đạt, continue_url=%s", continue_url)
    human_delay("api")
    logger.info("[2FA] đang đổi mới token...")
    new_token = _exchange_new_token(session, continue_url)
    logger.info("[2FA] đã lấy được mới token")
    human_delay("api")

    # 阶段二：enroll + activate
    logger.info("[2FA] giai đoạn 2: bắt đầu enroll TOTP")
    secret, session_id = _enroll_totp(session, new_token)
    logger.info("[2FA] enroll thành công, session_id=%s", session_id)
    human_delay("form")
    logger.info("[2FA] đang kích hoạt TOTP enrollment")
    _activate_totp(session, new_token, secret, session_id)
    logger.info("[2FA] TOTP kích hoạt hoàn tất")

    logger.info("=" * 60)
    logger.info(f"✅ 2FA thiết lập xong! Secret: {secret[:4]}...{secret[-4:]}")
    logger.info("=" * 60)
    return secret


def save_account_data(
    email: str,
    access_token: str,
    totp_secret: str | None = None,
    extra: dict | None = None,
    output_path: Path | None = None,  # 兼容老接口，已废弃
    email_source: str | None = None,
    proxy_used: str | None = None,
    batch_dir: Path | None = None,
    auto_plan_check: bool | None = None,
) -> int:
    "\n  sẽ tài khoản thông tin lưu đến SQLite; output_path chỉ là tương thích cũ gọi bên giữ. \n  trả về mới chèn/cập nhật  row id. \n  "
    from core.db import insert_account
    extra = dict(extra or {})
    # Remail 的 service token 只存在进程内上下文中。注册成功后把订单上下文
    # 一并保存到账号 extra_json，服务重启时查活即可恢复，不再依赖“同一进程
    # 中先领取邮箱”。普通账号列表不会返回 extra_json。
    if str(email_source or "").strip().lower() == "remail":
        try:
            from core.remail_client import get_account_context_metadata

            remail_metadata = get_account_context_metadata(email)
            if remail_metadata:
                existing_service = extra.get("email_service")
                merged_service = dict(existing_service) if isinstance(existing_service, dict) else {}
                merged_service.update(remail_metadata)
                extra["email_service"] = merged_service
        except Exception as exc:
            # 订单上下文保存失败不应让已经完成的注册失败；后续查活仍会
            # 尝试用 API Key 按邮箱搜索 Remail 订单恢复凭证。
            logger.warning(
                "[Save] lưu Remail ngữ cảnh đơn hàng thất bại, sau đó sẽ thử khôi phục theo email: %s: %s",
                type(exc).__name__,
                str(exc)[:180],
            )
    user = extra.get("user") or {}
    account = extra.get("account") or {}
    # 从 extra.codex 抽出顶层 codex 状态/错误，方便 WebUI 直接读账号字段
    codex = extra.get("codex") or {}
    codex_status = codex.get("status")  # success / failed / skipped
    codex_error = None
    if codex_status == "failed":
        codex_error = codex.get("message")

    row_id = insert_account(
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        user_id=user.get("id"),
        user_name=user.get("name"),
        plan_type=account.get("planType"),
        expires_at=extra.get("expires"),
        proxy_used=proxy_used,
        email_source=email_source,
        extra=extra,
        codex_status=codex_status,
        codex_error=codex_error,
    )
    batch_folder = _append_batch_archive(
        row_id=row_id,
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        email_source=email_source,
        proxy_used=proxy_used,
        extra=extra,
        batch_dir=batch_dir,
    )
    logger.info("[Save] đã lưu tài khoản và credential vào SQLite, id=%s, email=%s", row_id, email)

    auto_twofa = False
    try:
        from config import twofa as _twofa_cfg

        auto_twofa = bool(getattr(_twofa_cfg, "ENABLE_2FA", False))
    except Exception:
        auto_twofa = False
    if auto_twofa and not str(totp_secret or "").strip():
        try:
            from core.twofa_service import enqueue_account_totp_setup

            queued = enqueue_account_totp_setup(
                account_id=row_id,
                email=email,
                access_token=access_token,
                trigger="registration_auto",
                proxy=proxy_used,
            )
            if queued.get("accepted"):
                logger.info(f"[2FA] tự bật sau đăng ký 2FA đã xếp hàng: id={row_id}, email={email}")
            elif queued.get("busy"):
                logger.info(f"[2FA] tài khoản đã có 2FA tác vụ, quy trình đăng ký không xếp hàng trùng: id={row_id}, email={email}")
            else:
                logger.warning(f"[2FA] tự bật sau đăng ký 2FA xếp hàng thất bại(không ảnh hưởng kết quả đăng ký): {email}, {queued.get('error')}")
        except Exception as exc:
            logger.warning(
                f"[2FA] tự bật sau đăng ký 2FA xếp hàng ngoại lệ(không ảnh hưởng kết quả đăng ký): "
                f"{email}, {type(exc).__name__}: {str(exc)[:180]}"
            )

    if auto_plan_check is None:
        try:
            from config import register as _register_cfg

            auto_plan_check = bool(getattr(_register_cfg, "AUTO_PLAN_CHECK_AFTER_REGISTER", False))
        except Exception:
            auto_plan_check = False
    if not auto_plan_check:
        logger.info(f"[Plan] đã bỏ qua tự tra gói sau đăng ký: id={row_id}, email={email}")
        return row_id
    # session 中的 account.planType 不能说明 Plus 试用资格。账号落库后只负责
    # 入队，由专用线程池异步查询并回写，避免占用注册工作线程。
    try:
        from core.plan_check_service import enqueue_account_plan_check

        queued = enqueue_account_plan_check(
            account_id=row_id,
            email=email,
            access_token=access_token,
            trigger="registration_auto",
        )
        if queued.get("accepted"):
            logger.info(f"[Plan] đã xếp hàng tự tra cứu sau đăng ký: id={row_id}, email={email}")
        elif queued.get("busy"):
            logger.info(f"[Plan] tài khoản đã có tra cứu gói, quy trình đăng ký không xếp hàng trùng: id={row_id}, email={email}")
        else:
            logger.warning(f"[Plan] xếp hàng tự tra cứu sau đăng ký thất bại(không ảnh hưởng kết quả đăng ký): {email}, {queued.get('error')}")
    except Exception as exc:
        logger.warning(
            f"[Plan] xếp hàng tự tra cứu sau đăng ký gặp ngoại lệ(không ảnh hưởng kết quả đăng ký): "
            f"{email}, {type(exc).__name__}: {str(exc)[:180]}"
        )
    return row_id
