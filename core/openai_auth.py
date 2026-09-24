# -*- coding: utf-8 -*-
"""
Module OpenAI Auth
Xử lý request đăng ký dưới domain auth.openai.com (bước 4-5, 7-8, 10, 12)
và request sentinel token của sentinel.openai.com (bước 6, 9, 11)
"""
import json
import logging
import random
import secrets
import time

from config import openai_protocol as _protocol_cfg
from core.session import BrowserSession
from core.sentinel import (
    generate_requirements_token,
    build_sentinel_request_body,
)
from core.sentinel_runner import generate_sentinel_token

logger = logging.getLogger(__name__)


def _rotate_document_navigation_id(session: BrowserSession) -> None:
    rotate = getattr(session, "rotate_document_navigation_id", None)
    if callable(rotate):
        rotate()


class EmailOtpInvalidError(RuntimeError):
    """邮箱验证码无效/过期，可重新发送后重试。"""


class AccountUnusableError(Exception):
    """
    Tài khoản OpenAI tương ứng email đã hỏng (xóa/vô hiệu/cấm), thử lại cũng cùng kết quả.

    Phân biệt với lỗi mạng/kiểm soát rủi ro thông thường: lỗi này nghĩa là bản thân nguyên liệu email không dùng được,
    tầng trên nên đánh dấu email là failed và loại bỏ ngay, không đưa lại available để thử lặp.

    Mang theo error_code để tiện log và điều tra (ví dụ account_deactivated).
    """

    def __init__(self, message: str, error_code: str = ""):
        super().__init__(message)
        self.error_code = error_code


# Khi đầu xa trả các error code này, coi nguyên liệu email đã hỏng, không thử lại.
_ACCOUNT_DEAD_CODES = frozenset({
    "account_deactivated",   # Tài khoản đã xoá/ngừng
    "account_deleted",
    "account_banned",
})

_ACCOUNT_DEAD_TEXT_MARKERS = (
    "account_deactivated",
    "account_deleted",
    "account_banned",
    "account deactivated",
    "account deleted",
    "account banned",
    "account has been deactivated",
    "account has been deleted",
    "account was deactivated",
    "account was deleted",
    "your account has been deactivated",
    "your account has been deleted",
    "your account was deactivated",
    "your account was deleted",
    "账号已停用",
    "账号已禁用",
    "账号已删除",
    "账户已停用",
    "账户已禁用",
    "账户已删除",
)


def detect_account_unusable_text(text: str) -> str:
    """Nhận diện tài khoản đã hỏng từ trang trình duyệt/văn bản ngoại lệ, trả về error_code chuẩn; không khớp thì trả về chuỗi rỗng."""
    low = str(text or "").lower()
    for code in _ACCOUNT_DEAD_CODES:
        if code in low:
            return code
    if any(marker in low for marker in _ACCOUNT_DEAD_TEXT_MARKERS):
        if "delete" in low or "删除" in low:
            return "account_deleted"
        if "ban" in low or "封" in low:
            return "account_banned"
        return "account_deactivated"
    return ""


def detect_account_unusable_response_body(body: str) -> str:
    """
    Theo cùng logic với chế độ thuần protocol, nhận diện tài khoản đã bị phế từ error.code trong JSON phản hồi API.

    Đây không phải nhận dạng chữ trên trang; dùng sau khi trình duyệt/trình duyệt fingerprint chặn
    phản hồi /api/accounts/email-otp/validate, đọc mã lỗi có cấu trúc trong body phản hồi.
    """
    try:
        payload = json.loads(body or "")
    except Exception:
        return ""
    err = payload.get("error") if isinstance(payload, dict) else None
    code = ""
    if isinstance(err, dict):
        code = str(err.get("code") or "")
    elif isinstance(payload, dict):
        code = str(payload.get("code") or payload.get("error_code") or "")
    return code if code in _ACCOUNT_DEAD_CODES else ""


def _extract_error_code(resp) -> str:
    """Trích error.code từ JSON thân phản hồi (trả về chuỗi rỗng nếu không lấy được)."""
    try:
        payload = resp.json()
    except Exception:
        return ""
    err = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(err, dict):
        return str(err.get("code") or "")
    return ""


def _proxy_retry_config() -> tuple[int, float]:
    """Đọc cấu hình thử lại mạng proxy có thể hot-reload, và ràng buộc các giá trị cấu hình bất thường."""
    attempts = max(1, int(getattr(_protocol_cfg, "OPENAI_PROXY_RETRY_MAX_ATTEMPTS", 3)))
    delay = max(0.0, float(getattr(_protocol_cfg, "OPENAI_PROXY_RETRY_DELAY", 1.0)))
    return attempts, delay


def _is_transient_network_error(exc: Exception) -> bool:
    """Nhận diện lỗi mạng tạm thời có thể thử lại (TLS / hết thời gian kết nối / kết nối bị đặt lại / proxy từ chối)."""
    name = type(exc).__name__
    msg = str(exc).lower()
    transient_classes = ("SSLError", "ConnectionError", "Timeout", "CurlError", "ProxyError")
    if any(t.lower() in name.lower() for t in transient_classes):
        return True
    transient_keywords = (
        "wrong_version_number",      # Proxy trả response không phải TLS
        "tls connect",
        "ssl",
        "connection reset",
        "connection refused",
        "timed out",
        "proxy",
        "curl: (97)",                # SOCKS5 kết nối host đích thất bại
        "curl: (35)",
        "curl: (52)",                # empty reply from server
        "curl: (56)",                # network recv failure
    )
    return any(k in msg for k in transient_keywords)


def _is_retryable_authorize_error(exc: Exception) -> bool:
    """403/429/5xx của điều hướng authorize có thể tái sử dụng CF Cookie mới trong cùng phiên để thử lại."""
    response = getattr(exc, "response", None)
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    if status in (403, 408, 425, 429) or status >= 500:
        return True
    text = str(exc or "").lower()
    return _is_transient_network_error(exc) or any(
        marker in text for marker in (
            "http 403", "http error 403", "status=403",
            "http 429", "http error 429", "status=429", "熔断冷却",
        )
    )


def _reset_retryable_circuit(session: BrowserSession) -> None:
    """Chỉ xóa cầu chì cục bộ, giữ Cookie Jar của Session hiện tại và toàn bộ ngữ cảnh danh tính."""
    reset = getattr(session, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
    else:
        session.blocked_until = 0.0
        session.blocked_reason = ""


def _check_stop_requested() -> None:
    """Lazy-load dịch vụ task, tránh phụ thuộc vòng main/registration_service ở giai đoạn import module."""
    from core.registration_service import check_stop_requested
    check_stop_requested()


def _interruptible_sleep(seconds: float, interval: float = 0.25) -> None:
    """分段等待，使 WebUI 手动停止无需等完整指数退避结束。"""
    deadline = time.monotonic() + max(0.0, float(seconds))
    while True:
        _check_stop_requested()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(max(0.01, interval), remaining))


def _request_with_proxy_retry(session: BrowserSession, label: str, fn):
    """Retry lùi mũ hữu hạn cho proxy/TLS/timeout và lỗi HTTP có thể phục hồi."""
    max_attempts, retry_delay = _proxy_retry_config()
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        _check_stop_requested()
        try:
            response = fn()
            response.raise_for_status()
            if attempt > 1:
                logger.info("[%s] chuỗi proxy thử lại thành công (%s/%s)", label, attempt, max_attempts)
            return response
        except Exception as exc:
            last_exc = exc
            if not _is_retryable_authorize_error(exc) or attempt >= max_attempts:
                raise
            _reset_retryable_circuit(session)
            backoff = retry_delay * (2 ** (attempt - 1))
            logger.warning(
                "[%s] chuỗi proxy thất bại tạm thời (%s/%s): %s: %s, giữ session hiện tại, %.1fs thử lại sau",
                label, attempt, max_attempts, type(exc).__name__, str(exc)[:180], backoff,
            )
            _interruptible_sleep(backoff)
    raise last_exc if last_exc else RuntimeError(f"{label} thử lại hết nhưng không có bản ghi bất thường")


def network_preflight(session: BrowserSession) -> None:
    """
    Kiểm tra mạng trước đăng ký: chỉ thiết lập node biên/cookie/kết nối cơ bản, không mang email, không kích hoạt OTP.

    Như vậy trước khi redirect authorize thực sự “đốt email” xảy ra, đã xác nhận proxy hiện tại, TLS
    impersonate, ba đoạn liên kết ChatGPT/Auth/Sentinel đều tới được.
    """
    # Luồng Roxy thành công trước OAuth authorize chỉ truy cập trang đăng nhập ChatGPT; đánh thẳng sớm
    # auth/log-in và frame Sentinel sẽ tạo chuỗi truy cập cross-site không tồn tại trong trình duyệt.
    timeout = max(1.0, float(getattr(_protocol_cfg, "OPENAI_PREFLIGHT_TIMEOUT", 12.0)))
    checks = [
        ("chatgpt-auth-login", lambda: session.get(
            "https://chatgpt.com/auth/login",
            # Mẫu trình duyệt thành công là điều hướng cấp thanh địa chỉ top-level: không có Referer,
            # Sec-Fetch-Site=none. Giả mạo Referer cùng nguồn/header làm mới cache sẽ kích hoạt CF challenge.
            headers=session.get_chatgpt_navigate_headers(referer=""),
            allow_redirects=True,
            timeout=timeout,
        )),
    ]
    for label, fn in checks:
        resp = _request_with_proxy_retry(session, f"kiểm tra trước:{label}", fn)
        observe = getattr(session, "observe_chatgpt_document", None)
        if callable(observe):
            observe(resp)


def follow_authorize(session: BrowserSession, authorize_url: str) -> str:
    """
    Bước 4: Theo redirect của authorize URL.
    GET auth.openai.com/api/accounts/authorize?...

    Request này tạo một loạt redirect, thiết lập session cookies của auth.openai.com.
    Gặp lỗi mạng tạm thời (proxy lỗi / bắt tay TLS thất bại v.v.) sẽ tự thử lại.

    Args:
        session: phiên trình duyệt
        authorize_url: authorize URL lấy từ bước 3
    """
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")

    max_attempts, retry_delay = _proxy_retry_config()
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"[bước4] theo authorize URL chuyển hướng (Thử {attempt}/{max_attempts})...")
            resp = session.get(authorize_url, headers=headers, allow_redirects=True)
            resp.raise_for_status()
            final_url = str(getattr(resp, "url", "") or "")
            _rotate_document_navigation_id(session)
            logger.info(f"[bước4] chuyển hướng hoàn tất, cuối cùngURL: {final_url}")
            return final_url
        except Exception as exc:
            last_exc = exc
            if not _is_retryable_authorize_error(exc):
                # Lỗi không tạm thời (ví dụ lỗi nghiệp vụ 4xx) ném trực tiếp, không thử lại
                raise
            if attempt >= max_attempts:
                break
            # Lần 403 đầu tiên thường đồng thời làm mới __cf_bm; giữ cùng một BrowserSession/Cookie
            # Jar, chỉ xóa cầu chì cục bộ rồi thử lại, không được tạo lại phiên làm mất Cookie này.
            _reset_retryable_circuit(session)
            backoff = retry_delay * (2 ** (attempt - 1))
            logger.warning(
                f"[bước4] authorize thất bại tạm thời ({type(exc).__name__}: {str(exc)[:120]})，"
                f"giữ session/deviceId/CF Cookie hiện tại, {backoff:.1f}s thử lại sau..."
            )
            time.sleep(backoff)

    # Cả ba lần đều thất bại: ném ngoại lệ lần cuối
    raise last_exc if last_exc else RuntimeError("bước4 thử lại hết nhưng không có bản ghi bất thường")


def request_sentinel_token(session: BrowserSession, flow: str) -> dict:
    """
    Bước 6/9/11: Yêu cầu Sentinel Token.
    POST https://sentinel.openai.com/backend-api/sentinel/req

    Args:
        session: phiên trình duyệt
        flow: loại luồng
            - "username_password_create": bước 6
            - "email_otp_validate": bước 9
            - "oauth_create_account": bước 11

    Returns:
        JSON phản hồi sentinel, gồm token, turnstile, proofofwork, v.v.
    """
    iframe_flow = flow == "username_password_create"
    context_name = "password" if iframe_flow else "top_level"
    ready_contexts = getattr(session, "_sentinel_frame_contexts", None)
    if not isinstance(ready_contexts, set):
        ready_contexts = set()
        setattr(session, "_sentinel_frame_contexts", ready_contexts)
    if context_name not in ready_contexts:
        # Trình duyệt thành công sẽ tải cùng một iframe Sentinel trước req đầu tiên của hai instance SDK.
        # Đặt sau authorize, chạy on-demand; tránh precheck tạo chuỗi cross-site access không tồn tại.
        from config import SENTINEL_SV
        frame_url = f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SV}"
        frame_headers = session.get_sentinel_frame_headers(user_initiated=iframe_flow)
        frame_resp = _request_with_proxy_retry(
            session,
            f"Sentinel iframe:{flow}",
            lambda: session.get(frame_url, headers=frame_headers, allow_redirects=True),
        )
        ready_contexts.add(context_name)

    url = "https://sentinel.openai.com/backend-api/sentinel/req"

    # Tạo trường p (fingerprint trình duyệt)
    sentinel_sid = getattr(
        session,
        "sentinel_iframe_sid" if iframe_flow else "sentinel_sid",
        session.device_id,
    )
    profile = dict(getattr(session, "browser_profile", None) or {})
    profile["build_id"] = None
    # frame.html bản thân nằm ở /backend-api/, nhưng SDK thật khi sinh p[5] lấy được là
    # /sentinel/<sv>/sdk.js có số phiên bản. iframe mật khẩu giống context cấp cao sau đó.
    profile["script_src_samples"] = [
        f"https://sentinel.openai.com/sentinel/{__import__('config', fromlist=['SENTINEL_SV']).SENTINEL_SV}/sdk.js"
    ]
    context_p = getattr(session, "_sentinel_context_p", None)
    if not isinstance(context_p, dict):
        context_p = {}
        setattr(session, "_sentinel_context_p", context_p)
    p = context_p.get(context_name)
    if not p:
        p = generate_requirements_token(sentinel_sid, profile=profile)
        context_p[context_name] = p

    # Xây dựng body yêu cầu
    body = build_sentinel_request_body(p, session.device_id, flow)

    headers = session.get_sentinel_headers()

    logger.info(f"[Sentinel] yêu cầu sentinel token, flow={flow}")
    resp = _request_with_proxy_retry(
        session,
        f"Sentinel token:{flow}",
        lambda: session.post(url, headers=headers, data=body),
    )

    data = resp.json()
    if isinstance(data, dict):
        # turnstile.dx gắn với p requirements lần này. Node runner phải dùng cùng một bản p
        # Trả lại SDK dưới dạng cachedProof, không dùng proof khác được lấy mẫu lại trong VM.
        data = dict(data)
        data["_request_p"] = p
    logger.info(f"[Sentinel] lấy sentinel token thành công, persona={data.get('persona')}")

    if data.get("proofofwork", {}).get("required"):
        seed = data["proofofwork"]["seed"]
        difficulty = data["proofofwork"]["difficulty"]
        logger.info(f"[Sentinel] cần PoW: seed={seed}, difficulty={difficulty}")

    # Tăng cường chẩn đoán: cơ chế chống crawler nào được yêu cầu
    requires = []
    if data.get("turnstile", {}).get("required"):
        requires.append("turnstile")
    if data.get("so", {}).get("required"):
        requires.append("so")
    if data.get("proofofwork", {}).get("required"):
        requires.append("pow")
    logger.info(f"[Sentinel] mục server yêu cầu: {requires or '无'}")

    return data


def request_password_sentinel_bundle(session: BrowserSession) -> dict:
    """Tái hiện Sentinel flow bundle khi iframe trang mật khẩu tải lần đầu.

    Trang Web hiện tại dùng cùng một instance iframe SDK, cùng một ``p`` và cùng một SID lần lượt
    dò ``email_otp_validate``, ``username_password_create``,
    ``authorize_continue``. Khi thực sự submit user/register chỉ tiêu thụ challenge của password flow;
    hai phản hồi còn lại chỉ để server thấy khởi tạo capability nhất quán với trang.
    """
    context_name = "password"
    ready_contexts = getattr(session, "_sentinel_frame_contexts", None)
    if not isinstance(ready_contexts, set):
        ready_contexts = set()
        setattr(session, "_sentinel_frame_contexts", ready_contexts)
    if context_name not in ready_contexts:
        from config import SENTINEL_SV
        frame_url = f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SV}"
        _request_with_proxy_retry(
            session,
            "Sentinel iframe:password bundle",
            lambda: session.get(
                frame_url,
                headers=session.get_sentinel_frame_headers(user_initiated=True),
                allow_redirects=True,
            ),
        )
        ready_contexts.add(context_name)

    profile = dict(getattr(session, "browser_profile", None) or {})
    profile["build_id"] = None
    from config import SENTINEL_SV
    profile["script_src_samples"] = [
        f"https://sentinel.openai.com/sentinel/{SENTINEL_SV}/sdk.js"
    ]
    sid = getattr(session, "sentinel_iframe_sid", session.device_id)
    # Ba req của mẫu trình duyệt mang cùng một p hoàn toàn giống nhau, thay vì mỗi flow random lại một lần.
    p = generate_requirements_token(sid, profile=profile)
    context_p = getattr(session, "_sentinel_context_p", None)
    if not isinstance(context_p, dict):
        context_p = {}
        setattr(session, "_sentinel_context_p", context_p)
    context_p[context_name] = p
    responses: dict[str, dict] = {}
    for flow in (
        "email_otp_validate",
        "username_password_create",
        "authorize_continue",
    ):
        body = build_sentinel_request_body(p, session.device_id, flow)
        resp = _request_with_proxy_retry(
            session,
            f"Sentinel password bundle:{flow}",
            lambda body=body: session.post(
                "https://sentinel.openai.com/backend-api/sentinel/req",
                headers=session.get_sentinel_headers(),
                data=body,
            ),
        )
        response_data = resp.json()
        if isinstance(response_data, dict):
            response_data = dict(response_data)
            response_data["_request_p"] = p
        responses[flow] = response_data
    logger.info("[Sentinel] Trang mật khẩu flow bundle khởi tạo xong")
    return responses["username_password_create"]


def build_sentinel_header(session: BrowserSession, sentinel_resp: dict, flow: str) -> tuple:
    """
    Xây dựng giá trị header openai-sentinel-token và openai-sentinel-so-token từ phản hồi sentinel.

    Chiến lược triển khai: đưa challenge vào sentinel-runner.js (Node + sdk.js chạy trong sandbox vm),
    để SDK thật tự tạo token cuối gồm turnstile / so / pow, tránh nhét cứng dx bị chống gian lận từ chối.

    Args:
        session: phiên trình duyệt (cung cấp device_id và user_agent, phải khớp với các HTTP request sau)
        sentinel_resp: JSON phản hồi của sentinel/req
        flow: loại luồng, phải khớp hoàn toàn với flow đã truyền khi request challenge

    Returns:
        tuple (sentinel_header, so_header)
        sentinel_header: giá trị header openai-sentinel-token (chuỗi JSON do runner tạo trực tiếp)
        so_header: giá trị header openai-sentinel-so-token (điền nếu output SDK có trường so, ngược lại là None)
    """
    from config import USER_AGENT

    iframe_flow = flow == "username_password_create"
    sentinel_sid = getattr(
        session,
        "sentinel_iframe_sid" if iframe_flow else "sentinel_sid",
        None,
    )
    header_value = generate_sentinel_token(
        challenge=sentinel_resp,
        flow=flow,
        device_id=session.device_id,
        user_agent=(getattr(session, "browser_profile", {}) or {}).get("user_agent") or USER_AGENT,
        browser_profile=getattr(session, "browser_profile", None),
        sentinel_sid=sentinel_sid,
        react_listening_key=getattr(session, "react_listening_key", None),
        react_container_key=getattr(session, "react_container_key", None),
        react_resources_key=getattr(session, "react_resources_key", None),
        cookie=session.auth_cookie_header() if hasattr(session, "auth_cookie_header") else f"oai-did={session.device_id}",
    )

    # Parse output của runner, tách riêng trường so để điền openai-sentinel-so-token
    so_header = None
    try:
        parsed = json.loads(header_value)
        # _so của runner chỉ dùng để truyền giữa các process, không được trộn vào header request sentinel-token chính.
        so_value = parsed.pop("_so", None) or parsed.pop("so", None)
        header_value = json.dumps(parsed, separators=(',', ':'))
        if so_value:
            so_header = json.dumps(
                {
                    "so": so_value,
                    "c": parsed.get("c", sentinel_resp.get("token", "")),
                    "id": session.device_id,
                    "flow": flow,
                },
                separators=(',', ':'),
            )
            logger.info(f"[Sentinel] Đã phát hiện SO trường, đã dựng so-token header")
    except (ValueError, TypeError) as exc:
        logger.warning(f"[Sentinel] runner phân tích đầu ra thất bại: {exc}")

    return header_value, so_header


def generate_registration_password(length: int = 14) -> str:
    """Tạo mật khẩu mạnh nhất quán với đăng ký Roxy; ưu tiên dùng khi đã cấu hình REGISTER_PASSWORD."""
    try:
        from config import register as register_cfg
        configured = str(getattr(register_cfg, "REGISTER_PASSWORD", "") or "").strip()
        if configured:
            return configured
    except Exception:
        pass
    length = max(8, min(int(length), 64))
    groups = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "abcdefghjkmnpqrstuvwxyz",
        "23456789",
        "!@#$%^&*?_-+=",
    )
    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    random.SystemRandom().shuffle(chars)
    return "".join(chars)


def register_user(
    session: BrowserSession,
    email: str,
    password: str,
    sentinel_header: str,
    so_header: str | None = None,
) -> dict:
    """Gửi email và mật khẩu theo mẫu Roxy thành công, trả về địa chỉ điều hướng gửi OTP."""
    url = "https://auth.openai.com/api/accounts/user/register"
    headers = session.get_auth_headers(referer="https://auth.openai.com/create-account/password")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    body = json.dumps({"password": password, "username": email}, separators=(",", ":"))
    logger.info("[bước7] gửi email và mật khẩu: %s", email)
    resp = session.post(url, headers=headers, data=body)
    if resp.status_code != 200:
        logger.error("[bước7] user/register Thất bại status=%s body=%s", resp.status_code, (resp.text or "")[:500])
        resp.raise_for_status()
    data = resp.json()
    return data


def navigate_email_otp_send(session: BrowserSession, continue_url: str | None = None) -> str:
    """Gửi OTP theo địa chỉ trả về của user/register và thiết lập trạng thái document trang xác minh mới."""
    url = str(continue_url or "https://auth.openai.com/api/accounts/email-otp/send")
    if url.startswith("/"):
        url = "https://auth.openai.com" + url
    headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/create-account/password")
    headers["sec-fetch-site"] = "same-origin"
    headers["sec-fetch-user"] = "?1"
    resp = session.get(url, headers=headers, allow_redirects=True)
    resp.raise_for_status()
    _rotate_document_navigation_id(session)
    final_url = str(getattr(resp, "url", "") or "")
    if "/email-verification" not in final_url:
        raise RuntimeError(f"OTP điểm rơi gửi điều hướng bất thường: {final_url}")
    return final_url

# def get_create_account_page(session: BrowserSession) -> None:
#     """
#     [Dự phòng] Bước 5: Truy cập trang tạo tài khoản-mật khẩu (nhánh mật khẩu).
#     GET https://auth.openai.com/create-account/password
#     """
#     url = "https://auth.openai.com/create-account/password"
#     headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
#     headers["sec-fetch-site"] = "same-origin"
#
#     logger.info("[Bước 5] Truy cập trang tạo tài khoản-mật khẩu (chuyển nhánh mật khẩu)...")
#     resp = session.get(url, headers=headers, allow_redirects=True)
#     resp.raise_for_status()
#     logger.info(f"[Bước 5] Tạo tài khoản-truy cập trang mật khẩu thành công, điểm đến: {resp.url}")


# def register_user(session: BrowserSession, email: str, password: str, sentinel_header: str) -> dict:
#     """
#     [Dự phòng] Bước 7: Gửi yêu cầu đăng ký (email+mật khẩu).
#     POST https://auth.openai.com/api/accounts/user/register
#
#     Returns:
#         JSON phản hồi đăng ký, ví dụ:
#         {
#             "continue_url": "https://auth.openai.com/api/accounts/email-otp/send",
#             "method": "GET",
#             "page": {"type": "email_otp_send", "backstack_behavior": "default"}
#         }
#     """
#     url = "https://auth.openai.com/api/accounts/user/register"
#
#     headers = session.get_auth_headers(referer="https://auth.openai.com/create-account/password")
#     headers["openai-sentinel-token"] = sentinel_header
#
#     body = json.dumps({
#         "password": password,
#         "username": email,
#     })
#
#     logger.info(f"[Bước 7] Gửi yêu cầu đăng ký, email: {email}")
#     resp = session.post(url, headers=headers, data=body)
#
#     if resp.status_code != 200:
#         logger.error(f"[Bước 7] Yêu cầu thất bại, mã trạng thái: {resp.status_code}")
#         logger.error(f"[Bước 7] Nội dung phản hồi: {resp.text}")
#         resp.raise_for_status()
#
#     data = resp.json()
#     logger.info(f"[Bước 7] Yêu cầu đăng ký thành công: {data.get('page', {}).get('type')}")
#     return data


# def send_email_otp(session: BrowserSession) -> None:
#     """
#     [Dự phòng] Bước 8: kích hoạt gửi mã xác minh email.
#     GET https://auth.openai.com/api/accounts/email-otp/send
#     """
#     url = "https://auth.openai.com/api/accounts/email-otp/send"
#
#     headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/create-account/password")
#     headers["sec-fetch-site"] = "same-origin"
#     headers["sec-fetch-user"] = "?1"
#
#     logger.info("[Bước 8] Kích hoạt gửi mã xác minh email...")
#     resp = session.get(url, headers=headers, allow_redirects=True)
#     logger.info(f"[Bước 8] Yêu cầu gửi mã xác minh hoàn tất, mã trạng thái: {resp.status_code}")


def navigate_about_you(session: BrowserSession, about_url: str | None = None) -> str:
    """Vào trạng thái trang about-you; khi máy chủ không trả về continue_url thì dùng URL trang mặc định làm dự phòng."""
    url = str(about_url or "https://auth.openai.com/about-you")
    if url.startswith("/"):
        url = "https://auth.openai.com" + url
    headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
    headers["sec-fetch-site"] = "same-origin"
    logger.info("[bước10.5] điều hướng đến about-you trang, thiết lập trạng thái trang profile")
    resp = session.get(url, headers=headers, allow_redirects=True)
    if resp.status_code >= 400:
        raise RuntimeError(f"about-you điều hướng thất bại status={resp.status_code}: {(resp.text or '')[:240]}")
    final_url = str(getattr(resp, "url", "") or url)
    if "/api/accounts/user/register" in final_url or "/create-account/password" in final_url:
        raise RuntimeError(f"about-you điều hướng rơi vào đường dẫn đăng ký mật khẩu cũ: {final_url}")
    logger.info(f"[bước10.5] about-you điều hướng xong, điểm đến: {final_url}")
    return final_url


def send_email_otp(session: BrowserSession, referer: str = "https://auth.openai.com/email-verification") -> None:
    """重新发送邮箱验证码。用于验证码错误/过期后重新取码。"""
    url = "https://auth.openai.com/api/accounts/email-otp/send"
    headers = session.get_auth_navigate_headers(referer=referer)
    headers["sec-fetch-site"] = "same-origin"
    headers["sec-fetch-user"] = "?1"
    logger.info("[OTP] yêu cầu gửi lại mã OTP email...")
    resp = session.get(url, headers=headers, allow_redirects=True)
    if resp.status_code >= 400:
        logger.warning("[OTP] gửi lại mã OTP thất bại status=%s: %s", resp.status_code, (resp.text or '')[:300])
        resp.raise_for_status()
    _rotate_document_navigation_id(session)
    logger.info("[OTP] yêu cầu gửi lại mã OTP xong, status=%s", resp.status_code)


def validate_email_otp(session: BrowserSession, code: str, sentinel_header: str | None = None, so_header: str | None = None) -> dict:
    """
    步骤10: 提交邮箱验证码验证。
    POST https://auth.openai.com/api/accounts/email-otp/validate

    Args:
        session: 浏览器会话
        code: 6位数字验证码
        sentinel_header: openai-sentinel-token 头的值（email_otp_validate flow）

    Returns:
        验证响应 JSON，例如:
        {
            "continue_url": "https://auth.openai.com/about-you",
            "method": "GET",
            "page": {"type": "about_you", "backstack_behavior": "default"}
        }
    """
    url = "https://auth.openai.com/api/accounts/email-otp/validate"

    headers = session.get_auth_headers(referer="https://auth.openai.com/email-verification")
    if sentinel_header:
        headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
        logger.info("[bước10] đã thêm openai-sentinel-so-token header")

    body = json.dumps({"code": code})

    logger.info(f"[bước10] gửi mã OTP email: {code}")
    resp = session.post(url, headers=headers, data=body)

    if resp.status_code != 200:
        logger.error(f"[bước10] Yêu cầu thất bại, mã trạng thái: {resp.status_code}")
        logger.error(f"[bước10] nội dung phản hồi: {resp.text}")
        # Trước tiên kiểm tra xem có phải "tài khoản đã hủy"——loại email này thử lại cũng vô ích, ném riêng để tầng trên đánh dấu failed
        err_code = _extract_error_code(resp)
        if err_code in _ACCOUNT_DEAD_CODES:
            raise AccountUnusableError(
                f"tài khoản đã bỏ ({err_code}), email không dùng lại được", error_code=err_code,
            )
        low = (resp.text or '').lower()
        if resp.status_code in (400, 401, 422) and any(k in low for k in (
            'invalid', 'incorrect', 'expired', 'code', 'otp', 'verification',
            '验证码', '認証コード', '確認コード', 'コード'
        )):
            raise EmailOtpInvalidError(f"mã OTP email không hợp lệ hoặc đã hết hạn: status={resp.status_code}, body={(resp.text or '')[:240]}")
        resp.raise_for_status()

    data = resp.json()
    page_type = data.get('page', {}).get('type')
    logger.info(f"[bước10] xác minh mã OTP thành công: {page_type}")
    logger.info(f"[bước10] tóm tắt phản hồi xác minh: {json.dumps(data, ensure_ascii=False)[:1000]}")
    return data


def create_account(session: BrowserSession, name: str, birthday: str, sentinel_header: str, so_header: str = None) -> dict:
    """
    Bước 12: Gửi thông tin người dùng, hoàn tất đăng ký.
    POST https://auth.openai.com/api/accounts/create_account

    Args:
        session: phiên trình duyệt
        name: tên hiển thị người dùng
        birthday: ngày sinh, định dạng "YYYY-MM-DD"
        sentinel_header: giá trị header openai-sentinel-token
        so_header: giá trị header openai-sentinel-so-token

    Returns:
        JSON phản hồi tạo tài khoản
    """
    url = "https://auth.openai.com/api/accounts/create_account"

    headers = session.get_auth_headers(referer="https://auth.openai.com/about-you")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
        logger.info(f"[bước12] đã thêm openai-sentinel-so-token header")

    body = json.dumps({
        "name": name,
        "birthdate": birthday,
    })

    logger.info(f"[bước12] gửi thông tin người dùng, tên: {name}, ngày sinh: {birthday}")
    resp = session.post(url, headers=headers, data=body)

    if resp.status_code != 200:
        logger.error(f"[bước12] Yêu cầu thất bại, mã trạng thái: {resp.status_code}")
        logger.error(f"[bước12] nội dung phản hồi: {resp.text}")
        resp.raise_for_status()

    data = resp.json()
    log_cookies = getattr(session, "log_cookie_names", None)
    if callable(log_cookies):
        log_cookies("create_account_complete")
    logger.info("[bước12] API tạo trả về thành công, chờ OAuth callback thiết lập trạng thái đăng nhập")
    return data
