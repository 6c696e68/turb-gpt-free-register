# -*- coding: utf-8 -*-
"""ChatGPT tài khoảnemailđổi emailnềnhàng đợi。"""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from core import db
from core.email_provider import (
    acquire_email_from_source, email_material_line,
    release_email_if_unconsumed, wait_for_otp,
)
from core.session import BrowserSession, close_browser_session

logger = logging.getLogger(__name__)
_EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="email-change")
_SLOTS = threading.BoundedSemaphore(100)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"


def log_path(account_id: int) -> Path:
    return _LOG_DIR / f"email-change-{int(account_id)}.log"


def _append_log(account_id: int, message: str, *, clear: bool = False) -> None:
    path = log_path(account_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if clear else "a"
    with path.open(mode, encoding="utf-8") as fh:
        fh.write(f"{datetime.now().strftime('%H:%M:%S')} [INFO] {message}\n")


def _proxy(value: str | None) -> str:
    text = str(value or "").strip()
    return text if text.lower().startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://")) else ""


def _proxy_label(value: str | None) -> str:
    """nhật kýdùng proxytrích cần ，giữ giữ đường do tin tin nhưng ẩn giấu xác thựcmật khẩu。"""
    text = str(value or "").strip()
    if not text:
        return "direct"
    try:
        parsed = urlparse(text)
        auth = "***:***@" if parsed.username or parsed.password else ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{auth}{parsed.hostname or '?'}{port}"
    except Exception:
        return "proxy://***"


def _cost(started: float) -> str:
    return f"{time.monotonic() - started:.2f}s"


def _new_session(account_id: int, proxy, *, email: str = "") -> BrowserSession:
    # 与 2FA/查活统一使用账号级种子。同一账号做敏感操作时保持 device_id、
    # Sentinel sid、浏览器画像稳定，而不是为“换绑”另造一套新设备指纹。
    seed = f"account:{email.lower()}" if email else f"email-change:{account_id}"
    return BrowserSession(proxy=proxy, fingerprint_seed=seed)


def _response_error(resp) -> str:
    try:
        data = resp.json()
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            return str(err.get("message") or err.get("code") or data)
        return str(err or data)
    except Exception:
        return str(getattr(resp, "text", "") or f"HTTP {resp.status_code}")[:500]


def _is_reauth_required(exc: BaseException) -> bool:
    text = str(exc or "").lower()
    return "reauth_required" in text or "recent login required" in text


def _post(session: BrowserSession, path: str, token: str, payload: dict) -> dict:
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers.update({
        "authorization": f"Bearer {token}", "oai-device-id": session.device_id,
        "oai-language": session.navigator_language(), "origin": "https://chatgpt.com",
    })
    resp = session.post(f"https://chatgpt.com{path}", headers=headers, data=json.dumps(payload))
    if resp.status_code != 200:
        raise RuntimeError(f"{path} trả về {resp.status_code}: {_response_error(resp)}")
    data = resp.json()
    if not isinstance(data, dict) or not data.get("success"):
        raise RuntimeError(f"{path} trả về thất bại: {data}")
    return data


def _post_with_network_retry(
    session: BrowserSession, *, account_id: int, path: str, token: str, payload: dict,
    fingerprint_email: str = "",
) -> tuple[dict, BrowserSession]:
    """TLS reset/quá hạn v.v.truyền nhập cố cản khiđổi phiênthử lại，cuốimột rõ xác nhận Fallback kết nối trực tiếp。"""
    last_exc: Exception | None = None
    current = session
    for attempt in range(1, 4):
        attempt_started = time.monotonic()
        _append_log(
            account_id,
            f"Bắt đầu request HTTP: path={path} attempt={attempt}/3 "
            f"route={_proxy_label(getattr(current, 'proxy', None))} "
            f"device_id={str(getattr(current, 'device_id', '') or '')[:12]}...",
        )
        try:
            result = _post(current, path, token, payload)
            _append_log(
                account_id,
                f"Request HTTP thành công: path={path} status=200 attempt={attempt}/3 cost={_cost(attempt_started)}",
            )
            return result, current
        except Exception as exc:
            last_exc = exc
            text = str(exc)
            _append_log(
                account_id,
                f"Request HTTP thất bại: path={path} attempt={attempt}/3 cost={_cost(attempt_started)} "
                f"error={type(exc).__name__}: {text[:300]}",
            )
            # 明确的业务 4xx 不重复提交；网络错误、429 和 5xx 才重试。
            business_4xx = (
                ("返回 4" in text and "返回 429" not in text)
                or ("trả về 4" in text and "trả về 429" not in text)
            )
            if isinstance(exc, RuntimeError) and business_4xx:
                raise
            if attempt >= 3:
                break
            delay = attempt * 2
            next_route = "Phiên mới từ pool proxy" if attempt == 1 else "Fallback kết nối trực tiếp"
            _append_log(
                account_id,
                f"Request lỗi (lần {attempt}/3): {type(exc).__name__}: {text[:300]}；"
                f"{delay}s sau chuyển sang{next_route}thử lại",
            )
            logger.warning("[Đổi email] %s attempt=%s failed: %s", path, attempt, text[:300])
            time.sleep(delay)
            # 第二次从代理池重新选择出口；第三次明确直连，避免坏代理持续 reset。
            current = _new_session(
                account_id, None if attempt == 1 else "", email=fingerprint_email,
            )
    assert last_exc is not None
    raise last_exc


def _enqueue_live_check_after_change(account_id: int, email: str) -> dict:
    """đổi emailthành công saungayxếp hàngkiểm tra sống，dùng email mớilại mới đăng nhập và làm mới mới mất hiệu AT。"""
    from core import live_check_service

    result = live_check_service.enqueue_account_live_check(
        account_id=int(account_id), email=str(email),
        trigger="email_change_auto", proxy=None,
    )
    if result.get("accepted"):
        logger.info("[Đổi email] đã tự thêm vào hàng đợi kiểm tra sống account_id=%s email=%s", account_id, email)
        _append_log(account_id, f"Tự kiểm tra sống đã vào hàng đợi: email={email}")
    else:
        logger.warning(
            "[Đổi email] đổi email thành công nhưng vào hàng đợi tự kiểm tra sống thất bại account_id=%s email=%s error=%s",
            account_id, email, result.get("error") or "Lỗi không rõ",
        )
        _append_log(account_id, f"Vào hàng đợi tự kiểm tra sống thất bại: {result.get('error') or 'Lỗi không rõ'}")
    return result


def _refresh_recent_login(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
) -> tuple[BrowserSession, str]:
    """theo kiểm tra sống đầy đủđăng nhậpchuỗi lại mới đăng nhập，dựng đứng servernhận có thể Recent Login。

change_email reauth chuỗi sẽ không mụcmục tới email cũgửi OTP，tức khiến tài khoảnđãlưu
đăng kýmật khẩu。này trong sửa là tái sử dụngkiểm tra sống dự phòngđăng nhậpchuỗi ：ưu trước mật khẩu（để và TOTP），chỉ tại
trang đăng nhậpxác nhận thật cần yêu cầu emailxác thực khi mới đọcemail cũ OTP。
"""
    # 延迟导入，避免 account_liveness 初始化时形成模块循环。
    from core.account_liveness import (
        _login_via_password_or_otp,
        _network_preflight_with_retry,
    )
    from core.openai_auth import (
        AccountUnusableError,
        detect_account_unusable_text,
        follow_authorize,
    )

    _append_log(
        account_id,
        "Recent Login bắt đầu: tái sử dụng logic đăng nhập lại của kiểm tra sống (CSRF → signin → authorize → mật khẩu/OTP/MFA → OAuth callback → session/AT)",
    )

    # 保留本次换绑已经生成的账号级设备身份和浏览器画像，同时让查活预检
    # 创建干净的登录 Cookie Jar，并获得其网络重试能力。
    fingerprint_state = {
        "fingerprint_seed": f"account:{email.lower()}",
    }
    for key in (
        "device_id", "auth_session_logging_id", "oai_session_id", "sentinel_sid",
    ):
        value = str(getattr(session, key, "") or "").strip()
        if value:
            fingerprint_state[key] = value
    browser_profile = getattr(session, "browser_profile", None)
    if isinstance(browser_profile, dict):
        fingerprint_state["browser_profile"] = dict(browser_profile)

    login_started = time.monotonic()
    selected_proxy = getattr(session, "proxy", None)
    # 与后台查活一致：代理路线的完整认证链只要收到 403，就用一套完全
    # 独立的直连会话重跑。OAuth callback 的 403 会让当前 BrowserSession
    # 进入 15 分钟熔断；仅清除熔断后继续请求既不能修复出口，也容易复用
    # 已污染的 CF Cookie，因此必须从 CSRF 开始重新登录。
    routes = [(selected_proxy, fingerprint_state, "Tuyến proxy hiện tại")]
    if selected_proxy:
        routes.append(("", {}, "Fallback kết nối trực tiếp độc lập"))

    last_exc: BaseException | None = None
    for route_index, (route_proxy, route_state, route_label) in enumerate(routes):
        login_session: BrowserSession | None = None
        try:
            _append_log(account_id, f"Recent Login bắt đầu tuyến: {route_label}")
            login_session, authorize_url = _network_preflight_with_retry(
                email,
                route_proxy,
                fingerprint_state=route_state,
            )
            otp_after_ts = time.time()
            final_url = follow_authorize(login_session, authorize_url)
            dead_code = detect_account_unusable_text(final_url)
            if dead_code:
                raise AccountUnusableError(
                    f"Tài khoản đã bị huỷ ({dead_code}）",
                    error_code=dead_code,
                )
            info = _login_via_password_or_otp(
                login_session,
                email,
                otp_after_ts,
                email_source=email_source or None,
            )
            fresh_token = str((info or {}).get("accessToken") or "").strip()
            if not fresh_token:
                raise RuntimeError("Recent Login đăng nhập lại xong nhưng chưa lấy được access_token mới")
            _append_log(
                account_id,
                f"Recent Login xong: route={route_label}, đã lấy AT mới, cost={_cost(login_started)}",
            )
            return login_session, fresh_token
        except AccountUnusableError:
            raise
        except Exception as exc:
            last_exc = exc
            is_proxy_403 = route_index == 0 and bool(selected_proxy) and "403" in str(exc)
            if not is_proxy_403:
                raise
            _append_log(
                account_id,
                "Recent Login proxyđường tuyến nhận đến 403/phiênngắt mạch，"
                f"đóngthất bạiphiên và từ CSRF bắt đầudùngFallback kết nối trực tiếp độc lập：{type(exc).__name__}: {str(exc)[:260]}",
            )
            if login_session is not None:
                try:
                    close_browser_session(login_session)
                except Exception:
                    pass

    assert last_exc is not None
    raise last_exc


def _begin_change_with_optional_reauth(
    session: BrowserSession,
    *,
    account_id: int,
    current_email: str,
    current_source: str,
    new_email: str,
    access_token: str,
) -> tuple[BrowserSession, str, float, bool]:
    """ưu trước trực tiếp begin；chỉ tại serverrõ xác nhận cần yêu cầu Recent Login khixác thựcemail cũ。"""
    otp_after_ts = time.time()
    try:
        _, session = _post_with_network_retry(
            session,
            account_id=account_id,
            path="/backend-api/accounts/change_email/begin",
            token=access_token,
            payload={"email": new_email},
            fingerprint_email=current_email,
        )
        _append_log(account_id, "AT hiện có đủ yêu cầu Recent Login, đã bỏ qua reauth OTP email cũ")
        return session, access_token, otp_after_ts, False
    except Exception as exc:
        if not _is_reauth_required(exc):
            raise

    _append_log(account_id, "Server trả reauth_required, bắt đầu đăng nhập lại tài khoản cũ theo logic kiểm tra sống")
    session, fresh_token = _refresh_recent_login(
        session,
        account_id=account_id,
        email=current_email,
        email_source=current_source,
    )
    # 新邮箱 OTP 的时间基准必须放在第二次 begin 之前，不能沿用重认证前时间。
    otp_after_ts = time.time()
    _, session = _post_with_network_retry(
        session,
        account_id=account_id,
        path="/backend-api/accounts/change_email/begin",
        token=fresh_token,
        payload={"email": new_email},
        fingerprint_email=current_email,
    )
    _append_log(account_id, "Đăng nhập lại tài khoản cũ xong, dùng AT mới thử lại begin thành công")
    return session, fresh_token, otp_after_ts, True


def _check_live_in_current_session(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
) -> dict:
    """đổi email sautái sử dụnghiện tạiđã thông qua CF/reauth phiênlại mới đăng nhập và làm mới mới AT。"""
    from core.account_liveness import (
        _login_via_password_or_otp,
        _safe_fingerprint_for_account,
        _safe_fingerprint_text_for_account,
    )
    from core.chatgpt_auth import get_csrf_token, signin_openai
    from core.openai_auth import follow_authorize

    live_started = time.monotonic()
    _append_log(account_id, "Bắt đầu kiểm tra sống phiên cũ: tái sử dụng Cookie, trạng thái CF, egress và vân tay hiện tại")
    step_started = time.monotonic()
    csrf = get_csrf_token(session)
    _append_log(account_id, f"Kiểm tra sống phiên cũ: lấy CSRF thành công, cost={_cost(step_started)}")
    step_started = time.monotonic()
    authorize_url = signin_openai(session, csrf, email)
    _append_log(account_id, f"Kiểm tra sống phiên cũ: signin thành công và lấy authorize URL, cost={_cost(step_started)}")
    otp_after_ts = time.time()
    step_started = time.monotonic()
    follow_authorize(session, authorize_url)
    _append_log(account_id, f"Kiểm tra sống phiên cũ: follow authorize xong, vào giai đoạn mật khẩu/OTP/MFA, cost={_cost(step_started)}")
    step_started = time.monotonic()
    session_info = _login_via_password_or_otp(
        session,
        email,
        otp_after_ts,
        email_source=email_source or None,
    )
    access_token = str((session_info or {}).get("accessToken") or "").strip()
    if not access_token:
        raise RuntimeError("Sau đổi email, kiểm tra sống phiên cũ không lấy được access_token")
    _append_log(account_id, f"Kiểm tra sống phiên cũ: xác thực đăng nhập và lấy session thành công, cost={_cost(step_started)}")
    result = {
        "ok": True,
        "status": "live",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "access_token": access_token,
        "session": session_info,
        "proxy_used": session.proxy or None,
        "fingerprint": _safe_fingerprint_for_account(session),
        "fingerprint_text": _safe_fingerprint_text_for_account(session),
    }
    db.update_account_liveness(account_id, result)
    _append_log(account_id, f"Kiểm tra sống phiên cũ thành công: AT mới đã ghi lại, total={_cost(live_started)}")
    return result


def _run(account_id: int, source: str) -> dict:
    new_email = ""
    task_started = time.monotonic()
    stage = "Khởi tạo"
    with _LOCK:
        _RUNNING.add(account_id)
    try:
        _append_log(account_id, f"Bắt đầu chạy tác vụ: account_id={account_id} source={source}")
        stage = "Đọc tài khoản"
        account = db.get_account(account_id)
        if not account:
            raise RuntimeError("Tài khoản không tồn tại")
        token = str(account.get("access_token") or "").strip()
        if not token:
            raise RuntimeError("Tài khoản thiếu access_token, hãy kiểm tra sống để làm mới AT trước")
        stage = "Lấy email mới"
        acquire_started = time.monotonic()
        new_email = acquire_email_from_source(source)
        _append_log(account_id, f"Lấy email mới thành công: source={source} email={new_email} cost={_cost(acquire_started)}")
        if new_email.lower() == str(account.get("email") or "").lower():
            raise RuntimeError("Email vừa lấy trùng email hiện tại")
        if not db.mark_account_email_change_running(account_id, new_email):
            raise RuntimeError("Trạng thái tác vụ đổi email đã hết hiệu lực")

        stage = "Tạo phiên mạng"
        saved_proxy = _proxy(account.get("proxy_used"))
        # 账号没有可复用的真实代理 URL 时，先按全局代理池选路，而不是直接裸连。
        current_email = str(account.get("email") or "").strip()
        current_source = str(account.get("email_source") or "").strip().lower()
        session = _new_session(account_id, saved_proxy or None, email=current_email)
        _append_log(
            account_id,
            f"Phiên mạng đã tạo: route={'Proxy tài khoản' if saved_proxy else 'Pool proxy toàn cục / mạng mặc định'} "
            f"proxy={_proxy_label(getattr(session, 'proxy', None))}",
        )
        _append_log(account_id, f"Tóm tắt vân tay: {session.fingerprint_summary_text()}")

        logger.info("[Đổi email] begin account_id=%s old=%s new=%s source=%s", account_id, account.get("email"), new_email, source)
        _append_log(account_id, f"Bắt đầu đổi email: email cũ={account.get('email') or '-'}, email mới={new_email}, nguồn={source}")
        stage = "Gửi mã OTP email mới / reauth khi cần"
        session, token, after_ts, reauthenticated = _begin_change_with_optional_reauth(
            session,
            account_id=account_id,
            current_email=current_email,
            current_source=current_source,
            new_email=new_email,
            access_token=token,
        )
        _append_log(
            account_id,
            f"Gửi mã OTP email mới thành công, bắt đầu chờ OTP; reauth={'yes' if reauthenticated else 'no'}",
        )
        stage = "Chờ OTP email mới"
        otp_started = time.monotonic()
        otp = wait_for_otp(new_email, after_ts=after_ts, email_source=source, force_service=True)
        _append_log(account_id, f"Lấy OTP email mới thành công: source={source} cost={_cost(otp_started)} (không ghi mã OTP vào nhật ký)")
        stage = "Xác thực OTP email mới"
        _, session = _post_with_network_retry(
            session, account_id=account_id,
            path="/backend-api/accounts/change_email/verify", token=token,
            payload={"email": new_email, "code": otp},
            fingerprint_email=current_email,
        )
        _append_log(account_id, "Server xác thực OTP email mới thành công, bắt đầu cập nhật bản ghi tài khoản local")

        stage = "Cập nhật tài khoản local"
        db_started = time.monotonic()
        db.finish_account_email_change(
            account_id, ok=True, new_email=new_email, source=source,
            material_line=email_material_line(new_email, source),
        )
        _append_log(account_id, f"Cập nhật tài khoản local thành công: current_email={new_email}, AT cũ đã xoá, cost={_cost(db_started)}")
        # 抓包显示 verify 后旧 AT 会立刻 401，但当前会话中的 __cf_bm、OAuth
        # Cookie 和出口连续性仍然有效。优先在该会话内重新登录，避免另建会话后
        # `/api/auth/csrf` 被 CF 403；原会话失败时再退回后台查活队列。
        stage = "Tự kiểm tra sống sau đổi email"
        try:
            live_result = _check_live_in_current_session(
                session,
                account_id=account_id,
                email=new_email,
                email_source=source,
            )
            live_mode = "same_session"
        except Exception as live_exc:
            _append_log(
                account_id,
                f"Kiểm tra sống phiên cũ thất bại: {type(live_exc).__name__}: {str(live_exc)[:300]}; chuyển sang hàng đợi kiểm tra sống nền",
            )
            logger.warning("[Đổi email] kiểm tra sống phiên cũ thất bại account_id=%s: %s", account_id, str(live_exc)[:300])
            live_result = _enqueue_live_check_after_change(account_id, new_email)
            live_mode = "queued"
        logger.info("[Đổi email] thành công account_id=%s new=%s；đã chạy kiểm tra sống sau đổi email", account_id, new_email)
        _append_log(account_id, f"Tác vụ đổi email xong: live_check_mode={live_mode} total={_cost(task_started)}")
        return {
            "ok": True, "id": account_id, "email": new_email,
            "live_check_started": bool(live_result.get("ok") or live_result.get("accepted")),
            "live_check_mode": live_mode,
            "live_check_error": None if (live_result.get("ok") or live_result.get("accepted")) else live_result.get("error"),
        }
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        db.finish_account_email_change(account_id, ok=False, new_email=new_email or None, source=source, error=error)
        _append_log(account_id, f"Đổi email thất bại: stage={stage} total={_cost(task_started)} error={error}")
        if new_email:
            try:
                release_email_if_unconsumed(new_email, note=f"Tài khoản #{account_id} đổi email thất bại: {error[:300]}")
                _append_log(account_id, f"Xử lý email thất bại xong: đã yêu cầu thu hồi email={new_email}")
            except Exception:
                _append_log(account_id, f"Thu hồi email thất bại lỗi: email={new_email}")
                logger.exception("[Đổi email] thu hồi email mới thất bại: %s", new_email)
        logger.exception("[Đổi email] thất bại account_id=%s", account_id)
        return {"ok": False, "id": account_id, "error": error}
    finally:
        with _LOCK:
            _RUNNING.discard(account_id)
        _SLOTS.release()


def enqueue(account_id: int, source: str, trigger: str = "manual") -> dict:
    account_id = int(account_id)
    source = str(source or "").strip().lower()
    if not _SLOTS.acquire(blocking=False):
        return {"accepted": False, "error": "Hàng đợi đổi email đã đầy"}
    if not db.claim_account_email_change(account_id, source, trigger):
        _SLOTS.release()
        return {"accepted": False, "busy": True, "error": "Tài khoản đang đổi email hoặc không tồn tại"}
    _append_log(account_id, f"Tác vụ đổi email đã vào hàng đợi: source={source} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(_run, account_id, source)
        return {"accepted": True, "future": future}
    except Exception as exc:
        _SLOTS.release()
        db.finish_account_email_change(account_id, ok=False, error=str(exc))
        _append_log(account_id, f"Gửi tác vụ đổi email thất bại: {type(exc).__name__}: {exc}")
        return {"accepted": False, "error": str(exc)}


def is_running(account_id: int) -> bool:
    with _LOCK:
        return int(account_id) in _RUNNING
