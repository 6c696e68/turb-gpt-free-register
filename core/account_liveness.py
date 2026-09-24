# -*- coding: utf-8 -*-
"""đã đăng kýtài khoảnkiểm tra sống：ưu trước tái sử dụngđã có AT khởi động trước sauđi reauth OTP，thành cônglàm mới mới AT tức coi là bình thường。"""
import logging
import json
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from core import db
from core.session import BrowserSession, close_browser_session
from core.codex_oauth import _account_registration_password, _account_totp_secret, _account_totp_code
from core.humanize import delay as human_delay
from core.chatgpt_auth import get_csrf_token, get_providers, probe_auth_session, signin_openai
from core.openai_auth import (
    follow_authorize,
    send_email_otp,
    validate_email_otp,
    EmailOtpInvalidError,
    AccountUnusableError,
    detect_account_unusable_text,
)
from core.account_export import (
    _follow_reauth_with_retry,
    _trigger_reauth_with_retry,
    _validate_reauth_otp,
    fetch_session,
    follow_oauth_callback,
)
from core.email_provider import wait_for_otp

logger = logging.getLogger(__name__)
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"
_RUNNING: set[str] = set()
_RUNNING_LOCK = threading.Lock()

# 查活网络预检失败（403/429/代理/超时等）多为出口 IP 被 CF 标记或代理池抖动，
# 视为可换新 IP 重试；账号本身问题（废号/邮箱错误等）不重试。
_RETRYABLE_NETWORK_HINTS = (
    "403", "429", "502", "503", "504",
    "proxy", "socks", "timeout", "timed out",
    "connection", "closed", "reset",
)

_SESSION_FINGERPRINT_KEYS = {
    "device_id",
    "sentinel_sid",
    "oai_session_id",
    "auth_session_logging_id",
    "datadog_trace_id",
    "datadog_parent_id",
    "react_listening_key",
    "react_container_key",
    "react_resources_key",
}


def _is_retryable_network_error(exc: BaseException) -> bool:
    if isinstance(exc, AccountUnusableError):
        return False
    text = str(exc or "").lower()
    return any(h in text for h in _RETRYABLE_NETWORK_HINTS)


def _new_fingerprint_pinned_session(
    email: str,
    proxy: str | None,
    fingerprint_state: dict | None = None,
) -> BrowserSession:
    """tạotác vụđộc chiếm tài khoảnphiên；cùngđường do thử thử trong cố định định đầy đủthân phần và trình duyệtprofile。"""
    state = fingerprint_state if fingerprint_state is not None else {}
    saved_profile = state.get("browser_profile")
    identity = str(email).strip().lower()
    # 每个查活任务生成一次独立 seed；同一任务内所有阶段/重试复用，下一任务及
    # 其他账号均不会继承该组 device/session/sentinel 标识。
    fingerprint_seed = str(state.get("fingerprint_seed") or "").strip()
    if not fingerprint_seed:
        fingerprint_seed = f"live-check:{identity}:{uuid.uuid4()}"
        state["fingerprint_seed"] = fingerprint_seed
    session = BrowserSession(
        proxy=proxy,
        # 首次按当前出口生成地区画像；同一路由内部如需重建则原样复用。
        detect_exit_geo=not bool(saved_profile),
        browser_profile=dict(saved_profile) if isinstance(saved_profile, dict) else None,
        fingerprint_seed=fingerprint_seed,
        device_id=state.get("device_id"),
        auth_session_logging_id=state.get("auth_session_logging_id"),
        oai_session_id=state.get("oai_session_id"),
        sentinel_sid=state.get("sentinel_sid"),
    )
    for key in (
        "device_id", "auth_session_logging_id", "oai_session_id", "sentinel_sid",
    ):
        state.setdefault(key, str(getattr(session, key, "") or ""))
    if not saved_profile:
        generated_profile = getattr(session, "browser_profile", None)
        if isinstance(generated_profile, dict):
            state["browser_profile"] = dict(generated_profile)
    return session


def _warm_login_fingerprint_context(session: BrowserSession) -> None:
    """lặp hiện plus thuần giao thứcđăng kýthành côngmẫu này trang đăng nhậpKhởi tạothuận thứ tự 。"""
    from core.chatgpt_bootstrap import anonymous_bootstrap

    logger.info(
        "[Kiểm tra sống] khởi động trước chuỗi đăng nhập：/auth/login điều hướng top-level → anonymous bootstrap → "
        "providers → session → CSRF → session"
    )
    nav = session.get(
        "https://chatgpt.com/auth/login",
        headers=session.get_chatgpt_navigate_headers(
            # 地址栏级顶层导航：无 Referer，Sec-Fetch-Site=none。
            referer="", user_initiated=True,
        ),
        allow_redirects=True,
        # 代理端口可连接不代表其上游 TLS 可用，避免坏节点长期占住 worker。
        timeout=12,
    )
    nav.raise_for_status()
    observe = getattr(session, "observe_chatgpt_document", None)
    if callable(observe):
        observe(nav)
    anonymous_bootstrap(session, strict=False)
    # best-effort bootstrap 的非关键接口不能阻断正式认证链。
    _clear_optional_bootstrap_circuit(session)
    get_providers(session)
    probe_auth_session(session)


def _network_preflight_with_retry(
    email: str,
    proxy: str | None,
    max_attempts: int = 4,
    fingerprint_state: dict | None = None,
) -> tuple[BrowserSession, str]:
    """CSRF → Signin dự phòngpreflight；thất bại khigiữ giữ cùngphiênthử lại。

`/api/auth/providers` chỉ là NextAuth gửi hiện nhận cổng ，signin đầu điểm và không phụ thuộcnó trả về
trong dung 。thực tếchạy dòng này nhận cổng rất dung dễ trước bị Cloudflare chặn， nếu kết quả nó làmcứng cửa ngưỡng ，sau đó
này đến có thể dùng CSRF/uỷ quyềnchuỗi mãi xa không sẽ thực thi。vì này kiểm tra sốngdự phòngchuỗi không lại providers khi làm
bắt buộc qua bước。

này trong bắt buộc phải gốc mẫu truyền chuyển ``proxy``：``None`` bảng hiện theo cấu hìnhchọn proxy，trống ký tự ký hiệu chuỗi bảng hiện rõ xác nhận
kết nối trực tiếp。của trướcdùng ``proxy if proxy else None`` Fallback kết nối trực tiếpnhầm đổi thành lần nữarút lấy proxy。
"""
    session: BrowserSession | None = None
    last_exc: BaseException | None = None
    state = fingerprint_state if fingerprint_state is not None else {}
    # 一次网络预检只创建一个 BrowserSession。403 响应下发的新 __cf_bm、
    # OAuth/设备上下文都保留在同一 Cookie Jar 中供下一轮使用。
    session = _new_fingerprint_pinned_session(email, proxy, state)
    for attempt in range(1, max_attempts + 1):
        logger.info(
            "[Kiểm tra sống] tái sử dụng phiên thống nhất：proxy=%s device_id=%s oai_session_id=%s（preflight mạng lần %s/%s ）",
            session.proxy or "Ngẫu nhiên theo cấu hình / kết nối trực tiếp", session.device_id,
            str(getattr(session, "oai_session_id", "") or "")[:12] + "...",
            attempt, max_attempts,
        )
        logger.info("[Kiểm tra sống] Tóm tắt vân tay: %s", session.fingerprint_summary_text())
        try:
            _warm_login_fingerprint_context(session)
            csrf = get_csrf_token(session)
            # 成功 Web 样本在 signin 前会再次确认匿名 NextAuth session。
            probe_auth_session(session)
            authorize_url = signin_openai(session, csrf, email)
            return session, authorize_url
        except Exception as exc:
            last_exc = exc
            if attempt >= max_attempts or not _is_retryable_network_error(exc):
                try:
                    close_browser_session(session)
                except Exception:
                    pass
                raise
            _clear_optional_bootstrap_circuit(session)
            logger.warning(
                "[Kiểm tra sống] preflight mạng thất bại（%s/%s），giữ session/deviceId/CF Cookie hiện tại rồi thử lại：%s",
                attempt, max_attempts, str(exc)[:200],
            )
            time.sleep(2)
    raise RuntimeError(f"Preflight mạng thất bại nhiều lần: {last_exc}")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_fingerprint_for_account(session: BrowserSession) -> dict:
    """tài khoảntrong chỉ bản ghichạy dòng vòng môi trường profile，không lưuphiên/đặt dự nhãn biết 。"""
    fp = session.fingerprint_summary()
    return {k: v for k, v in fp.items() if k not in _SESSION_FINGERPRINT_KEYS}


def _safe_fingerprint_text_for_account(session: BrowserSession) -> str:
    fp = _safe_fingerprint_for_account(session)
    parts = [
        f"proxy={BrowserSession._short_value(fp.get('proxy') or 'direct', 36)}",
        f"ua={BrowserSession._short_value(fp.get('user_agent'), 72)}",
        f"lang={fp.get('accept_language')}",
        f"tz={fp.get('timezone_iana')}({fp.get('timezone_offset_minutes')})",
        f"screen={fp.get('screen_width')}x{fp.get('screen_height')}@{fp.get('device_pixel_ratio')}",
        f"cpu={fp.get('hardware_concurrency')}",
        f"mem={fp.get('device_memory')}",
        f"geo={fp.get('geo_country') or '?'}:{fp.get('geo_city') or '?'}",
    ]
    return " ".join(parts)


def _extract_continue_url(result: dict | None) -> str:
    if not isinstance(result, dict):
        return ""
    page = result.get("page") or {}
    page = page if isinstance(page, dict) else {}
    return str(
        result.get("continue_url")
        or result.get("external_url")
        or result.get("url")
        or page.get("continue_url")
        or page.get("external_url")
        or page.get("url")
        or ""
    ).strip()


def _extract_factor_id(result: dict | None, continue_url: str) -> str:
    if isinstance(result, dict):
        page = result.get("page") or {}
        page = page if isinstance(page, dict) else {}
        payload = page.get("payload") or {}
        if isinstance(payload, dict):
            factor_id = str(payload.get("factor_id") or "").strip()
            if factor_id:
                return factor_id
        if isinstance(page.get("payload"), dict):
            factor_id = str(page["payload"].get("factor_id") or "").strip()
            if factor_id:
                return factor_id
    if "/mfa-challenge/" in continue_url:
        return continue_url.rstrip("/").rsplit("/", 1)[-1]
    return ""


def _password_verify(session: BrowserSession, password: str) -> dict:
    from core.openai_auth import build_sentinel_header, request_sentinel_token

    sentinel_resp = request_sentinel_token(session, "password_verify")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "password_verify")
    headers = session.get_auth_headers(referer="https://auth.openai.com/log-in/password")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    resp = session.post(
        "https://auth.openai.com/api/accounts/password/verify",
        headers=headers,
        data=json.dumps({"password": password}),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _mfa_issue_challenge(session: BrowserSession, factor_id: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/issue_challenge",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "force_fresh_challenge": False}),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _mfa_verify(session: BrowserSession, factor_id: str, code: str) -> dict:
    headers = session.get_auth_headers(referer="https://auth.openai.com/mfa-challenge")
    headers.pop("openai-sentinel-token", None)
    headers.pop("openai-sentinel-so-token", None)
    resp = session.post(
        "https://auth.openai.com/api/accounts/mfa/verify",
        headers=headers,
        data=json.dumps({"id": factor_id, "type": "totp", "code": code}),
        allow_redirects=False,
    )
    resp.raise_for_status()
    return resp.json()


def _follow_continue_and_fetch(session: BrowserSession, continue_url: str, *, referer: str) -> dict:
    """xong callback/session， và với 403 giữ giữ cùng phiên Cookie làm giai đoạntrong thử lại。

callback và session phần mở thử lại：callback một sáng thành côngkhông lại lặp xoá phí OAuth code；
chỉ có callback này thân thất bại khi mới lại đặt continue_url。thử lạihao hết sauném chotrên lớp ，do
live_check_service theo đã có sách lược đổi thành độc lậpkết nối trực tiếpphiênđầy đủfallback。
"""
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            follow_oauth_callback(session, continue_url, referer=referer)
            break
        except Exception as exc:
            if attempt >= max_attempts or not _is_retryable_network_error(exc):
                raise
            _clear_optional_bootstrap_circuit(session)
            delay = float(2 ** (attempt - 1))
            logger.warning(
                "[Kiểm tra sống] callback OAuth tạm thất bại（%s/%s），giữ giữ hiện tại "
                "session/deviceId/CF Cookie，%.1fs sauthử lại：%s",
                attempt, max_attempts, delay, str(exc)[:200],
            )
            time.sleep(delay)

    for attempt in range(1, max_attempts + 1):
        try:
            return fetch_session(session)
        except Exception as exc:
            if attempt >= max_attempts or not _is_retryable_network_error(exc):
                raise
            _clear_optional_bootstrap_circuit(session)
            delay = float(2 ** (attempt - 1))
            logger.warning(
                "[Kiểm tra sống] kéo Session/AT tạm thất bại（%s/%s），giữ giữ hiện tại "
                "session/deviceId/CF Cookie，%.1fs sauthử lại：%s",
                attempt, max_attempts, delay, str(exc)[:200],
            )
            time.sleep(delay)
    raise RuntimeError("Hết lần thử lại kéo Session/AT khi kiểm tra sống")


def _stored_access_token(email: str) -> str:
    """đọclocaltài khoảnđã có AT，dùng chotrước khởi động trướcphiên đăng nhậplại đi ổn định reauth chuỗi 。"""
    try:
        account = db.get_account_by_email(email)
        return str((account or {}).get("access_token") or "").strip()
    except Exception as exc:
        logger.debug("[Kiểm tra sống] đọc accessToken sẵn có thất bại, chuyển chuỗi đăng nhập dự phòng：%s: %s", type(exc).__name__, exc)
        return ""


def _clear_optional_bootstrap_circuit(session: BrowserSession) -> None:
    """dọntuỳ chọnphiên đăng nhậpkhởi động trướctạo thành localngắt mạch，không ảnh hưởng sau đóchínhxác thựcrequest。

authenticated_bootstrap là best-effort khởi động trước，nó khác cũnhận cổng trả về 403 không v.v.tại
reauth chuỗi không có thể dùng ；BrowserSession thông dùng ngắt mạchbộ nếu giữ giữ này trạng thái，sẽ trực tiếpchặnsau đó
`/api/auth/csrf`，dẫn khiến ổn định 2FA chuỗi cũng không thểbắt đầu。
"""
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
        return
    if getattr(session, "blocked_until", 0.0):
        session.blocked_until = 0.0
        session.blocked_reason = ""


def _warm_authenticated_session(session: BrowserSession, access_token: str) -> None:
    """tái sử dụng 2FA đã xác thực phiên đăng nhậpkhởi động trướcluồng。khởi động trướcthất bạikhông trực tiếpphán định tài khoảnchết mất 。"""
    if not access_token:
        return
    from core.chatgpt_bootstrap import authenticated_bootstrap

    try:
        logger.info("[Kiểm tra sống] dùng accessToken sẵn có để khởi động trước phiên đăng nhập...")
        authenticated_bootstrap(session, access_token, strict=False)
        logger.info("[Kiểm tra sống] khởi động trước accessToken xong, tiếp tục reauth OTP")
    except Exception as exc:
        # strict=False 已经会吞掉大部分单接口错误；这里仅兜住初始化异常。
        logger.warning("[Kiểm tra sống] khởi động trước accessToken thất bại, tiếp tục reauth OTP：%s: %s", type(exc).__name__, str(exc)[:180])
    finally:
        _clear_optional_bootstrap_circuit(session)


def _exception_response_text(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    return str(getattr(response, "text", "") or "")


def _exception_status_code(exc: BaseException) -> int | None:
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return None
    return status or None


def _validate_reauth_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 3,
    email_source: str | None = None,
) -> str:
    """gửi reauth OTP；mã OTPlỗi khigửi lại và lại mới lấy mã。"""
    current_otp: str | None = None
    last_exc: Exception | None = None
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[Kiểm tra sống] chờ OTP reauth：%s（lần %s/%s ）", email, attempt, max_otp_attempts)
                current_otp = wait_for_otp(
                    email,
                    after_ts=otp_after_ts,
                    email_source=email_source,
                )
            human_delay("otp_input")
            continue_url = _validate_reauth_otp(session, current_otp)
            if not continue_url:
                raise RuntimeError("reauth Phản hồi xác thực OTP thiếu continue_url")
            return str(continue_url)
        except AccountUnusableError:
            raise
        except Exception as exc:
            last_exc = exc
            body = _exception_response_text(exc)
            dead_code = detect_account_unusable_text(body) or detect_account_unusable_text(str(exc))
            if dead_code:
                raise AccountUnusableError(
                    f"Tài khoản đã bị huỷ ({dead_code}), email không dùng lại được",
                    error_code=dead_code,
                ) from exc

            status = _exception_status_code(exc)
            # reauth validate 的 403 可能是 Cloudflare/出口拦截；不要在同一已熔断
            # 会话上反复发送 OTP，交给上层的直连兜底处理。
            retryable_otp = status in (400, 401, 422)
            if attempt >= max_otp_attempts or not retryable_otp:
                raise
            logger.warning(
                "[Kiểm tra sống] OTP reauth không hợp lệ/hết hạn, gửi lại rồi lấy（%s/%s）：%s",
                attempt,
                max_otp_attempts,
                str(exc)[:180],
            )
            send_email_otp(session)
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("Xác thực OTP reauth thất bại")


def _login_via_reauth(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """theo 2FA đã xác thựcchuỗilại mới xác thực và làm mới mới ChatGPT session。"""
    auth_url = _trigger_reauth_with_retry(session, email)
    logger.info("[Kiểm tra sống] đã lấy reauth authorize URL")
    human_delay("api")
    final_url = _follow_reauth_with_retry(session, auth_url)
    dead_code = detect_account_unusable_text(final_url)
    if dead_code:
        raise AccountUnusableError(f"Tài khoản đã bị huỷ ({dead_code}）", error_code=dead_code)
    human_delay("navigate")
    logger.info("[Kiểm tra sống] đã follow reauth authorize URL, bắt đầu chờ OTP email")
    continue_url = _validate_reauth_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    logger.info("[Kiểm tra sống] xác thực reauth OTP thành công, bắt đầu đổi token mới")
    human_delay("api")
    return _follow_continue_and_fetch(
        session,
        continue_url,
        referer="https://auth.openai.com/email-verification",
    )


def _login_via_email_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """xongemail OTP đăng nhập， và follow OAuth callback saukéo ChatGPT session。"""
    validate_result = _validate_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    page = validate_result.get("page") if isinstance(validate_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")
    continue_url = _extract_continue_url(validate_result)
    if not continue_url:
        raise RuntimeError(f"Đăng nhập OTP thành công nhưng không có OAuth continue_url: {validate_result}")
    if "about-you" in str(continue_url) or page_type in {"about_you", "about-you"}:
        raise RuntimeError(f"Email này sau đăng nhập vào trang hồ sơ, có vẻ chưa phải tài khoản đăng ký đầy đủ: page_type={page_type}, continue_url={continue_url}")
    logger.info("[Kiểm tra sống] xác thực OTP email xong, bắt đầu follow callback OAuth")
    return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/email-verification")


def _login_via_password_or_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """ưu trước mật khẩuđăng nhập； nếu vào vào MFA challenge thì tự độngdùng TOTP xong。"""
    password = _account_registration_password(email)
    if not password:
        logger.info("[Kiểm tra sống] không thấy mật khẩu đăng ký, tiếp tục dùng OTP email：%s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    logger.info("[Kiểm tra sống] tài khoản có mật khẩu, ưu tiên đăng nhập mật khẩu：%s", email)
    password_result = _password_verify(session, password)
    continue_url = _extract_continue_url(password_result)
    page = password_result.get("page") if isinstance(password_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")

    if "/mfa-challenge/" in continue_url or page_type == "mfa_challenge":
        factor_id = _extract_factor_id(password_result, continue_url)
        secret = _account_totp_secret(email)
        if not factor_id:
            raise RuntimeError(f"Đăng nhập mật khẩu vào MFA nhưng chưa lấy factor_id: {password_result}")
        if not secret:
            raise RuntimeError(f"Đăng nhập mật khẩu vào MFA nhưng tài khoản không có totp_secret: {email}")
        logger.info("[Kiểm tra sống] đã vào MFA challenge, bắt đầu gửi TOTP：%s factor_id=%s", email, factor_id)
        _mfa_issue_challenge(session, factor_id)
        code = _account_totp_code(email)
        if not code:
            raise RuntimeError(f"Không tạo được mã OTP TOTP: {email}")
        mfa_result = _mfa_verify(session, factor_id, code)
        mfa_continue_url = _extract_continue_url(mfa_result) or continue_url
        if not mfa_continue_url:
            raise RuntimeError(f"Xác thực MFA thành công nhưng không có continue_url: {mfa_result}")
        return _follow_continue_and_fetch(
            session,
            mfa_continue_url,
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        )

    if "email-verification" in continue_url or page_type in {"email_verification", "email_otp_send"}:
        logger.info("[Kiểm tra sống] sau đăng nhập mật khẩu vẫn vào OTP email, tiếp tục xác thực email：%s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    if continue_url:
        logger.info("[Kiểm tra sống] đăng nhập mật khẩu trả luôn URL callback, tiếp tục hoàn thành callback：%s", email)
        return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/log-in/password")

    raise RuntimeError(f"Đăng nhập mật khẩu thành công nhưng không có continue_url dùng được: {password_result}")


def _login_via_full_web_flow(
    email: str,
    proxy: str | None,
    *,
    email_source: str | None,
    fingerprint_state: dict,
) -> tuple[BrowserSession, dict]:
    """theo plus thuần giao thứcđăng ký Web đăng nhậpthứ tự cột dựng đứng một phần toàn mới phiên đăng nhập。"""
    session, authorize_url = _network_preflight_with_retry(
        email,
        proxy,
        fingerprint_state=fingerprint_state,
    )
    otp_after_ts = time.time()
    final_url = follow_authorize(session, authorize_url)
    dead_code = detect_account_unusable_text(final_url)
    if dead_code:
        raise AccountUnusableError(
            f"Tài khoản đã bị huỷ ({dead_code}）",
            error_code=dead_code,
        )
    session_info = _login_via_password_or_otp(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    return session, session_info


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"live-check-{safe}.log"


def is_checking(email: str) -> bool:
    key = str(email or "").strip().lower()
    with _RUNNING_LOCK:
        return key in _RUNNING


def _validate_with_retry(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    max_otp_attempts: int = 3,
    email_source: str | None = None,
) -> dict:
    current_otp = None
    last_exc: Exception | None = None
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[Kiểm tra sống] chờ OTP đăng nhập：%s（lần %s/%s ）", email, attempt, max_otp_attempts)
                current_otp = wait_for_otp(
                    email,
                    after_ts=otp_after_ts,
                    email_source=email_source,
                )
            result = validate_email_otp(session, current_otp, sentinel_header=None, so_header=None)
            return result
        except EmailOtpInvalidError as exc:
            last_exc = exc
            if attempt >= max_otp_attempts:
                break
            logger.warning("[Kiểm tra sống] OTP không hợp lệ/hết hạn, gửi lại rồi lấy：%s", str(exc)[:180])
            send_email_otp(session)
            # 以“重新发送请求完成后”为新基准，避免刚刚失败的上一封旧码再次被 after 容忍窗口命中。
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
        except Exception as exc:
            # 提交 OTP 后的网络抖动（连接断开/超时/代理波动）：同一会话重发验证码再验证一次。
            if attempt >= max_otp_attempts or not _is_retryable_network_error(exc):
                raise
            last_exc = exc
            logger.warning("[Kiểm tra sống] xác thực OTP rung mạng, gửi lại rồi lấy（%s/%s）：%s", attempt, max_otp_attempts, str(exc)[:180])
            try:
                send_email_otp(session)
            except Exception:
                raise
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("Xác thực OTP thất bại")


def check_account_liveness(
    email: str,
    proxy: str | None = None,
    *,
    clear_log: bool = True,
    email_source: str | None = None,
    fingerprint_state: dict | None = None,
) -> dict:
    """
lại mới đăng nhậptài khoản và làm mới mới mới nhất accessToken。

trả về：
{
ok: bool,
status: live/deactivated/failed,
access_token: str?,
session: dict?,
checked_at: ISO,
error: str?
}
"""
    email = str(email or "").strip()
    if not email:
        raise ValueError("email không được trống")

    checked_at = _now()
    key = email.lower()
    path = log_path(email)
    path.parent.mkdir(parents=True, exist_ok=True)
    if clear_log:
        path.write_text("", encoding="utf-8")

    fh: logging.FileHandler | None = None
    session: BrowserSession | None = None
    task_fingerprint_state = fingerprint_state if fingerprint_state is not None else {}
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    with _RUNNING_LOCK:
        _RUNNING.add(key)
    try:
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)

        logger.info("[Kiểm tra sống] file nhật ký：%s", path)
        logger.info("[Kiểm tra sống] bắt đầu đăng nhập lại：%s", email)
        existing_access_token = _stored_access_token(email)
        has_totp = bool(_account_totp_secret(email))
        if existing_access_token and not has_totp:
            # 2FA 设置流程已经验证：先用已有 AT 预热 ChatGPT 登录态，再走
            # reauth → 邮箱 OTP → callback。该链路不依赖容易被 CF 拦截的
            # /api/auth/providers。已开启 TOTP 的账号保留密码 → MFA 路径，
            # 避免把 MFA challenge 误当成邮箱 OTP 页面。
            logger.info("[Kiểm tra sống] luồng：phiên đăng nhậpkhởi động trước → CSRF → Reauth Signin → Authorize → email OTP → OAuth callback → Session/AT")
            session = _new_fingerprint_pinned_session(email, proxy, task_fingerprint_state)
            logger.info(
                "[Kiểm tra sống] tạo phiên xong：proxy=%s device_id=%s（tái sử dụng chuỗi 2FA ổn định）",
                session.proxy or "Kết nối trực tiếp / ngẫu nhiên theo cấu hình",
                session.device_id,
            )
            logger.info("[Kiểm tra sống] Tóm tắt vân tay: %s", session.fingerprint_summary_text())
            _warm_authenticated_session(session, existing_access_token)
            human_delay("navigate")
            try:
                session_info = _login_via_reauth(
                    session,
                    email,
                    time.time(),
                    email_source=email_source,
                )
            except Exception as reauth_exc:
                if not _is_retryable_network_error(reauth_exc):
                    raise
                # reauth/callback 的同会话阶段重试已经耗尽。继续复用熔断的
                # Cookie Jar 没有意义；参考 plus 纯协议注册，建立干净会话并按
                # /auth/login → providers/session/csrf/session → signin 完整重登。
                failed_proxy = session.proxy if proxy is None else proxy
                logger.warning(
                    "[Kiểm tra sống] chuỗi AT reauth tạm thất bại, chuyển phiên sạch chạy đăng nhập đầy đủ thuần protocol：%s",
                    str(reauth_exc)[:240],
                )
                try:
                    close_browser_session(session)
                except Exception:
                    pass
                session, session_info = _login_via_full_web_flow(
                    email,
                    failed_proxy,
                    email_source=email_source,
                    fingerprint_state=task_fingerprint_state,
                )
        else:
            # 兼容没有本地 AT 或已开启 TOTP 的记录，按 plus 成功注册样本复现
            # 登录页 document 与完整 NextAuth 调用顺序。
            logger.info(
                "[Kiểm tra sống] luồng：trang đăng nhập → Providers/Session/CSRF/Session → Signin → "
                "Authorize → mật khẩu/email OTP → MFA( nếu có ) → OAuth callback → Session/AT"
            )
            session, session_info = _login_via_full_web_flow(
                email,
                proxy,
                email_source=email_source,
                fingerprint_state=task_fingerprint_state,
            )
        access_token = str(session_info.get("accessToken") or "")
        if not access_token:
            raise RuntimeError("Đăng nhập lại xong vẫn chưa lấy được accessToken")

        user = session_info.get("user") or {}
        account = session_info.get("account") or {}
        logger.info("[Kiểm tra sống] bình thường：%s user_id=%s plan=%s", email, user.get("id"), account.get("planType"))
        fp = _safe_fingerprint_for_account(session)
        return {
            "ok": True,
            "status": "live",
            "checked_at": checked_at,
            "access_token": access_token,
            "session": session_info,
            "proxy_used": session.proxy or None,
            "fingerprint": fp,
            "fingerprint_text": _safe_fingerprint_text_for_account(session),
        }
    except AccountUnusableError as exc:
        code = getattr(exc, "error_code", "") or detect_account_unusable_text(str(exc)) or "account_deactivated"
        logger.warning("[Kiểm tra sống] đã tài khoản hỏng：%s %s", email, code)
        return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
    except Exception as exc:
        code = detect_account_unusable_text(_exception_response_text(exc)) or detect_account_unusable_text(str(exc))
        if code:
            logger.warning("[Kiểm tra sống] đã tài khoản hỏng：%s %s", email, code)
            return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
        logger.warning("[Kiểm tra sống] thất bại：%s %s: %s", email, type(exc).__name__, str(exc)[:260])
        return {"ok": False, "status": "failed", "checked_at": checked_at, "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
    finally:
        try:
            logger.info("[Kiểm tra sống] kết thúc：%s", email)
            if session is not None:
                try:
                    close_browser_session(session)
                except Exception:
                    pass
            if fh is not None:
                root_logger.removeHandler(fh)
                fh.close()
        finally:
            with _RUNNING_LOCK:
                _RUNNING.discard(key)
