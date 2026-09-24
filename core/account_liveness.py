# -*- coding: utf-8 -*-
"đã đăng ký tài khoản kiểm tra sống: ưu tiên tái dùng đã có AT làm nóng sau đi reauth OTP, thành công làm mới AT tức xem là bình thường. "
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

# Kiểm tra sống precheck mạng thất bại (403/429/proxy/timeout v.v.) phần lớn do IP đầu ra bị CF đánh dấu hoặc pool proxy dao động,
# Coi là có thể đổi IP mới thử lại; vấn đề bản thân tài khoản (số hỏng/email sai v.v.) không thử lại.
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
    "tạo tác vụ độc quyền tài khoản phiên; cùng một tuyến thử trong cố định đầy đủ thân bản và trình duyệt hồ sơ. "
    state = fingerprint_state if fingerprint_state is not None else {}
    saved_profile = state.get("browser_profile")
    identity = str(email).strip().lower()
    # Mỗi task check-live tạo một seed độc lập một lần; mọi stage/retry trong cùng task tái dùng, task sau và
    # Các tài khoản khác đều không kế thừa định danh device/session/sentinel của nhóm đó.
    fingerprint_seed = str(state.get("fingerprint_seed") or "").strip()
    if not fingerprint_seed:
        fingerprint_seed = f"live-check:{identity}:{uuid.uuid4()}"
        state["fingerprint_seed"] = fingerprint_seed
    session = BrowserSession(
        proxy=proxy,
        # Lần đầu tạo hồ sơ khu vực theo lối ra hiện tại; trong cùng route nếu cần tạo lại thì tái sử dụng nguyên trạng.
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
    "tái hiện plus giao thức thuần đăng ký thành công kiểu này trang đăng nhập khởi tạo thứ tự. "
    from core.chatgpt_bootstrap import anonymous_bootstrap

    logger.info(
        "[kiểm tra sống] làm nóng chuỗi đăng nhập: /auth/login tầng trên điều hướng → anonymous bootstrap → "
        "providers → session → CSRF → session"
    )
    nav = session.get(
        "https://chatgpt.com/auth/login",
        headers=session.get_chatgpt_navigate_headers(
            # Điều hướng cấp thanh địa chỉ top-level: không Referer, Sec-Fetch-Site=none.
            referer="", user_initiated=True,
        ),
        allow_redirects=True,
        # Proxy port connect được không nghĩa TLS upstream khả dụng; tránh node hỏng chiếm worker lâu.
        timeout=12,
    )
    nav.raise_for_status()
    observe = getattr(session, "observe_chatgpt_document", None)
    if callable(observe):
        observe(nav)
    anonymous_bootstrap(session, strict=False)
    # API non-critical của best-effort bootstrap không được chặn chuỗi auth chính thức.
    _clear_optional_bootstrap_circuit(session)
    get_providers(session)
    probe_auth_session(session)


def _network_preflight_with_retry(
    email: str,
    proxy: str | None,
    max_attempts: int = 4,
    fingerprint_state: dict | None = None,
) -> tuple[BrowserSession, str]:
    "CSRF → Signin dự phòng tiền kiểm; thất bại khi giữ cùng một phiên thử lại. \n\n  `/api/auth/providers` chỉ là NextAuth  phát hiện API, signin đầu điểm và không phụ thuộc nó trả về \n  trong dung. thực tế chạy trong này API rất dễ bị trước bị Cloudflare chặn, nếu nó làm là ngưỡng cứng, sau tiếp\n  này đến có thể dùng  CSRF/uỷ quyền chuỗi mãi sẽ không thực thi. do đó kiểm tra sống dự phòng chuỗi không lại  providers khi làm\n  phải qua bước bước. \n\n  này trong phải gốc truyền nguyên ``proxy``: ``None`` bảng hiện theo cấu hình chọn proxy, trống chuỗi bảng thể hiện rõ\n  kết nối trực tiếp. của trước dùng ``proxy if proxy else None``  kết nối trực tiếp dự phòng vô tình thành lần nữa trích proxy. \n  "
    session: BrowserSession | None = None
    last_exc: BaseException | None = None
    state = fingerprint_state if fingerprint_state is not None else {}
    # Một lần precheck mạng chỉ tạo một BrowserSession. __cf_bm mới do phản hồi 403 phát xuống,
    # Ngữ cảnh OAuth/thiết bị đều giữ trong cùng Cookie Jar để dùng vòng sau.
    session = _new_fingerprint_pinned_session(email, proxy, state)
    for attempt in range(1, max_attempts + 1):
        logger.info(
            "[kiểm tra sống] tái dùng phiên thống nhất: proxy=%s device_id=%s oai_session_id=%s(tiền kiểm mạng lần %s/%s lần)",
            session.proxy or "cấu hình ngẫu nhiên/kết nối trực tiếp", session.device_id,
            str(getattr(session, "oai_session_id", "") or "")[:12] + "...",
            attempt, max_attempts,
        )
        logger.info("[kiểm tra sống] tóm tắt fingerprint: %s", session.fingerprint_summary_text())
        try:
            _warm_login_fingerprint_context(session)
            csrf = get_csrf_token(session)
            # Mẫu Web thành công sẽ xác nhận lại phiên NextAuth ẩn danh trước signin.
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
                "[kiểm tra sống] tiền kiểm mạng thất bại(%s/%s), giữ hiện tại session/deviceId/CF Cookie thử lại: %s",
                attempt, max_attempts, str(exc)[:200],
            )
            time.sleep(2)
    raise RuntimeError(f"tiền kiểm mạng thất bại nhiều lần: {last_exc}")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_fingerprint_for_account(session: BrowserSession) -> dict:
    "tài khoản trong chỉ bản ghi chạy môi trường hồ sơ, không lưu phiên/định danh thiết bị. "
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
    "hoàn tất callback/session, và với 403 giữ cùng phiên Cookie làm giai đoạn trong thử lại. \n\n  callback và session phút mở thử lại: callback một khi thành công thì không tiêu thụ trùng OAuth code; \n  chỉ có callback này thân thất bại khi mới phát lại continue_url. thử lại cạn sau ném cho trên lớp, bởi\n  live_check_service theo đã có đổi chiến lược thành độc lập kết nối trực tiếp phiên đầy đủ dự phòng. \n  "
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
                "[kiểm tra sống] OAuth callback tạm thất bại(%s/%s), giữ hiện tại "
                "session/deviceId/CF Cookie, %.1fs rồi thử lại: %s",
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
                "[kiểm tra sống] Session/AT kéo tạm thất bại(%s/%s), giữ hiện tại "
                "session/deviceId/CF Cookie, %.1fs rồi thử lại: %s",
                attempt, max_attempts, delay, str(exc)[:200],
            )
            time.sleep(delay)
    raise RuntimeError("kiểm tra sống Session/AT hết lượt thử kéo")


def _stored_access_token(email: str) -> str:
    "đọc cục bộ tài khoản đã có AT, dùng để trước làm nóng trạng thái đăng nhập lại đi chuỗi ổn định  reauth chuỗi. "
    try:
        account = db.get_account_by_email(email)
        return str((account or {}).get("access_token") or "").strip()
    except Exception as exc:
        logger.debug("[kiểm tra sống] đọc đã có accessToken thất bại, chuyển sang chuỗi đăng nhập dự phòng: %s: %s", type(exc).__name__, exc)
        return ""


def _clear_optional_bootstrap_circuit(session: BrowserSession) -> None:
    "dọn tuỳ chọn làm nóng trạng thái đăng nhập gây ra cục bộ ngắt mạch, không ảnh hưởng sau tiếp đang kiểu xác thực request. \n\n  authenticated_bootstrap là best-effort làm nóng, trong đó khác cũ API trả về 403 không v.v.tại\n  reauth chuỗi không thể dùng; BrowserSession  thông dùng ngắt mạch bộ nếu giữ này trạng thái, sẽ trực tiếp chặn sau tiếp\n  `/api/auth/csrf`, làm cho ổn định  2FA chuỗi cũng không cách bắt đầu. \n  "
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
        return
    if getattr(session, "blocked_until", 0.0):
        session.blocked_until = 0.0
        session.blocked_reason = ""


def _warm_authenticated_session(session: BrowserSession, access_token: str) -> None:
    "tái dùng 2FA đã xác minh làm nóng trạng thái đăng nhập quy trình. làm nóng thất bại không trực tiếp xác định tài khoản chết. "
    if not access_token:
        return
    from core.chatgpt_bootstrap import authenticated_bootstrap

    try:
        logger.info("[kiểm tra sống] dùng đã có accessToken làm nóng trạng thái đăng nhập...")
        authenticated_bootstrap(session, access_token, strict=False)
        logger.info("[kiểm tra sống] accessToken làm nóng xong, tiếp tục đi reauth OTP")
    except Exception as exc:
        # strict=False đã nuốt hầu hết lỗi từng API; đây chỉ bắt exception khởi tạo.
        logger.warning("[kiểm tra sống] accessToken làm nóng thất bại, tiếp tục đi reauth OTP: %s: %s", type(exc).__name__, str(exc)[:180])
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
    "gửi reauth OTP; mã OTP lỗi khi lại gửi và lại lấy mã. "
    current_otp: str | None = None
    last_exc: Exception | None = None
    for attempt in range(1, max_otp_attempts + 1):
        try:
            if current_otp is None:
                logger.info("[kiểm tra sống] chờ xác thực lại OTP: %s(lần %s/%s lần)", email, attempt, max_otp_attempts)
                current_otp = wait_for_otp(
                    email,
                    after_ts=otp_after_ts,
                    email_source=email_source,
                )
            human_delay("otp_input")
            continue_url = _validate_reauth_otp(session, current_otp)
            if not continue_url:
                raise RuntimeError("xác thực lại OTP phản hồi xác minh thiếu continue_url")
            return str(continue_url)
        except AccountUnusableError:
            raise
        except Exception as exc:
            last_exc = exc
            body = _exception_response_text(exc)
            dead_code = detect_account_unusable_text(body) or detect_account_unusable_text(str(exc))
            if dead_code:
                raise AccountUnusableError(
                    f"tài khoản đã hỏng({dead_code}), email không dùng lại được",
                    error_code=dead_code,
                ) from exc

            status = _exception_status_code(exc)
            # 403 của reauth validate có thể là Cloudflare/chặn egress; đừng trên cùng phiên đã circuit break
            # Gửi OTP lặp lại trên phiên, giao cho lớp trên xử lý dự phòng kết nối trực tiếp.
            retryable_otp = status in (400, 401, 422)
            if attempt >= max_otp_attempts or not retryable_otp:
                raise
            logger.warning(
                "[kiểm tra sống] xác thực lại OTP không hợp lệ/hết hạn, gửi lại rồi lấy tiếp(%s/%s): %s",
                attempt,
                max_otp_attempts,
                str(exc)[:180],
            )
            send_email_otp(session)
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("xác thực lại OTP xác minh thất bại")


def _login_via_reauth(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    "theo 2FA đã xác minh chuỗi lại xác thực và làm mới ChatGPT session. "
    auth_url = _trigger_reauth_with_retry(session, email)
    logger.info("[kiểm tra sống] reauth authorize URL đã lấy")
    human_delay("api")
    final_url = _follow_reauth_with_retry(session, auth_url)
    dead_code = detect_account_unusable_text(final_url)
    if dead_code:
        raise AccountUnusableError(f"tài khoản đã hỏng({dead_code}）", error_code=dead_code)
    human_delay("navigate")
    logger.info("[kiểm tra sống] đã theo reauth authorize URL, bắt đầu chờ email OTP")
    continue_url = _validate_reauth_with_retry(
        session,
        email,
        otp_after_ts,
        email_source=email_source,
    )
    logger.info("[kiểm tra sống] reauth OTP xác minh đạt, bắt đầu đổi mới token")
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
    "hoàn tất email OTP đăng nhập, và theo OAuth callback sau kéo ChatGPT session. "
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
        raise RuntimeError(f"OTP đăng nhập thành công nhưng không có OAuth continue_url: {validate_result}")
    if "about-you" in str(continue_url) or page_type in {"about_you", "about-you"}:
        raise RuntimeError(f"email này sau khi đăng nhập vào trang hồ sơ, có vẻ không phải tài khoản đã đăng ký đầy đủ: page_type={page_type}, continue_url={continue_url}")
    logger.info("[kiểm tra sống] email OTP xác minh hoàn tất, bắt đầu theo OAuth callback")
    return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/email-verification")


def _login_via_password_or_otp(
    session: BrowserSession,
    email: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    "ưu tiên mật khẩu đăng nhập; như vào MFA challenge thì tự động dùng TOTP hoàn tất. "
    password = _account_registration_password(email)
    if not password:
        logger.info("[kiểm tra sống] không thấy mật khẩu đăng ký, tiếp tục dùng email OTP: %s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    logger.info("[kiểm tra sống] tài khoản có mật khẩu, ưu tiên đăng nhập bằng mật khẩu: %s", email)
    password_result = _password_verify(session, password)
    continue_url = _extract_continue_url(password_result)
    page = password_result.get("page") if isinstance(password_result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")

    if "/mfa-challenge/" in continue_url or page_type == "mfa_challenge":
        factor_id = _extract_factor_id(password_result, continue_url)
        secret = _account_totp_secret(email)
        if not factor_id:
            raise RuntimeError(f"sau đăng nhập mật khẩu vào MFA nhưng chưa lấy được factor_id: {password_result}")
        if not secret:
            raise RuntimeError(f"sau đăng nhập mật khẩu vào MFA, nhưng tài khoản không có totp_secret: {email}")
        logger.info("[kiểm tra sống] đã vào MFA challenge, bắt đầu gửi TOTP: %s factor_id=%s", email, factor_id)
        _mfa_issue_challenge(session, factor_id)
        code = _account_totp_code(email)
        if not code:
            raise RuntimeError(f"không cách tạo TOTP mã OTP: {email}")
        mfa_result = _mfa_verify(session, factor_id, code)
        mfa_continue_url = _extract_continue_url(mfa_result) or continue_url
        if not mfa_continue_url:
            raise RuntimeError(f"MFA xác minh thành công nhưng không có continue_url: {mfa_result}")
        return _follow_continue_and_fetch(
            session,
            mfa_continue_url,
            referer=f"https://auth.openai.com/mfa-challenge/{factor_id}",
        )

    if "email-verification" in continue_url or page_type in {"email_verification", "email_otp_send"}:
        logger.info("[kiểm tra sống] sau đăng nhập mật khẩu vẫn vào email OTP, tiếp tục hoàn tất xác minh email: %s", email)
        return _login_via_email_otp(
            session,
            email,
            otp_after_ts,
            email_source=email_source,
        )

    if continue_url:
        logger.info("[kiểm tra sống] đăng nhập mật khẩu trả thẳng địa chỉ callback, tiếp tục hoàn tất callback: %s", email)
        return _follow_continue_and_fetch(session, continue_url, referer="https://auth.openai.com/log-in/password")

    raise RuntimeError(f"đăng nhập mật khẩu thành công nhưng không có continue_url: {password_result}")


def _login_via_full_web_flow(
    email: str,
    proxy: str | None,
    *,
    email_source: str | None,
    fingerprint_state: dict,
) -> tuple[BrowserSession, dict]:
    "theo plus giao thức thuần đăng ký  Web đăng nhập chuỗi thiết lập một bản toàn bộ mới đăng nhập trạng thái. "
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
            f"tài khoản đã hỏng({dead_code}）",
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
                logger.info("[kiểm tra sống] chờ đăng nhập OTP: %s(lần %s/%s lần)", email, attempt, max_otp_attempts)
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
            logger.warning("[kiểm tra sống] OTP không hợp lệ/hết hạn, gửi lại rồi lấy tiếp: %s", str(exc)[:180])
            send_email_otp(session)
            # Lấy mốc mới là “sau khi hoàn tất yêu cầu gửi lại”, tránh mã cũ vừa thất bại bị cửa sổ dung sai after bắt trúng lần nữa.
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
        except Exception as exc:
            # Dao động mạng sau khi gửi OTP (mất kết nối/timeout/biến động proxy): cùng phiên gửi lại mã xác minh rồi xác minh lại một lần.
            if attempt >= max_otp_attempts or not _is_retryable_network_error(exc):
                raise
            last_exc = exc
            logger.warning("[kiểm tra sống] OTP xác minh bị giật mạng, gửi lại rồi lấy tiếp(%s/%s): %s", attempt, max_otp_attempts, str(exc)[:180])
            try:
                send_email_otp(session)
            except Exception:
                raise
            otp_after_ts = time.time()
            current_otp = None
            time.sleep(1)
    raise last_exc if last_exc else RuntimeError("OTP xác minh thất bại")


def check_account_liveness(
    email: str,
    proxy: str | None = None,
    *,
    clear_log: bool = True,
    email_source: str | None = None,
    fingerprint_state: dict | None = None,
) -> dict:
    "\n  lại đăng nhập tài khoản và làm mới mới nhất accessToken. \n\n  trả về: \n  {\n  ok: bool,\n  status: live/deactivated/failed,\n  access_token: str?,\n  session: dict?,\n  checked_at: ISO,\n  error: str?\n  }\n  "
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

        logger.info("[kiểm tra sống] nhật ký file: %s", path)
        logger.info("[kiểm tra sống] bắt đầu đăng nhập lại: %s", email)
        existing_access_token = _stored_access_token(email)
        has_totp = bool(_account_totp_secret(email))
        if existing_access_token and not has_totp:
            # Flow setup 2FA đã verify: trước dùng AT có sẵn warm login state ChatGPT, rồi đi
            # reauth → email OTP → callback. Chuỗi này không phụ thuộc thứ dễ bị CF chặn
            # /api/auth/providers. Tài khoản đã bật TOTP giữ đường mật khẩu → MFA,
            # Tránh nhầm MFA challenge thành trang OTP email.
            logger.info("[kiểm tra sống] quy trình: làm nóng trạng thái đăng nhập → CSRF → Reauth Signin → Authorize → email OTP → OAuth callback → Session/AT")
            session = _new_fingerprint_pinned_session(email, proxy, task_fingerprint_state)
            logger.info(
                "[kiểm tra sống] tạo phiên xong: proxy=%s device_id=%s(tái dùng 2FA ổn định chuỗi)",
                session.proxy or "kết nối trực tiếp/cấu hình ngẫu nhiên",
                session.device_id,
            )
            logger.info("[kiểm tra sống] tóm tắt fingerprint: %s", session.fingerprint_summary_text())
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
                # Retry giai đoạn cùng phiên của reauth/callback đã cạn. Tiếp tục tái sử dụng cái đã circuit-break
                # Cookie Jar không có ý nghĩa; tham khảo đăng ký pure protocol của plus, tạo session sạch và theo
                # /auth/login → providers/session/csrf/session → signin đăng nhập lại đầy đủ.
                failed_proxy = session.proxy if proxy is None else proxy
                logger.warning(
                    "[kiểm tra sống] AT reauth chuỗi thất bại tạm, chuyển sang phiên sạch và đăng nhập đầy đủ bằng giao thức thuần: %s",
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
            # Tương thích bản ghi không có AT cục bộ hoặc đã bật TOTP, tái hiện theo mẫu đăng ký plus thành công
            # document trang đăng nhập và thứ tự gọi NextAuth đầy đủ.
            logger.info(
                "[kiểm tra sống] quy trình: trang đăng nhập → Providers/Session/CSRF/Session → Signin → "
                "Authorize → mật khẩu/email OTP → MFA(nếu có) → OAuth callback → Session/AT"
            )
            session, session_info = _login_via_full_web_flow(
                email,
                proxy,
                email_source=email_source,
                fingerprint_state=task_fingerprint_state,
            )
        access_token = str(session_info.get("accessToken") or "")
        if not access_token:
            raise RuntimeError("sau đăng nhập lại không lấy được accessToken")

        user = session_info.get("user") or {}
        account = session_info.get("account") or {}
        logger.info("[kiểm tra sống] bình thường: %s user_id=%s plan=%s", email, user.get("id"), account.get("planType"))
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
        logger.warning("[kiểm tra sống] đã hỏng: %s %s", email, code)
        return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
    except Exception as exc:
        code = detect_account_unusable_text(_exception_response_text(exc)) or detect_account_unusable_text(str(exc))
        if code:
            logger.warning("[kiểm tra sống] đã hỏng: %s %s", email, code)
            return {"ok": False, "status": "deactivated", "checked_at": checked_at, "error": code}
        logger.warning("[kiểm tra sống] thất bại: %s %s: %s", email, type(exc).__name__, str(exc)[:260])
        return {"ok": False, "status": "failed", "checked_at": checked_at, "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
    finally:
        try:
            logger.info("[kiểm tra sống] kết thúc: %s", email)
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
