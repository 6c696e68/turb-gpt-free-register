# -*- coding: utf-8 -*-
"ChatGPT tài khoản đổi email sau nền hàng đợi. "
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
    "nhật ký dùng proxy tóm tắt cần, giữ tuyến thông tin nhưng ẩn xác thực mật khẩu. "
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
    # Thống nhất dùng seed cấp tài khoản với 2FA/kiểm tra sống. Khi cùng tài khoản thực hiện thao tác nhạy cảm giữ device_id,
    # Sentinel sid、hình ảnh trình duyệt ổn định, thay vì tạo bộ fingerprint thiết bị mới cho “đổi liên kết”.
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
    "TLS reset/timeout v.v.lỗi truyền khi đổi phiên thử lại, cuối một lần rõ kết nối trực tiếp dự phòng. "
    last_exc: Exception | None = None
    current = session
    for attempt in range(1, 4):
        attempt_started = time.monotonic()
        _append_log(
            account_id,
            f"HTTP request bắt đầu: path={path} attempt={attempt}/3 "
            f"route={_proxy_label(getattr(current, 'proxy', None))} "
            f"device_id={str(getattr(current, 'device_id', '') or '')[:12]}...",
        )
        try:
            result = _post(current, path, token, payload)
            _append_log(
                account_id,
                f"HTTP request thành công: path={path} status=200 attempt={attempt}/3 cost={_cost(attempt_started)}",
            )
            return result, current
        except Exception as exc:
            last_exc = exc
            text = str(exc)
            _append_log(
                account_id,
                f"HTTP request thất bại: path={path} attempt={attempt}/3 cost={_cost(attempt_started)} "
                f"error={type(exc).__name__}: {text[:300]}",
            )
            # 4xx nghiệp vụ rõ ràng không gửi lại; chỉ lỗi mạng, 429 và 5xx mới thử lại.
            if isinstance(exc, RuntimeError) and "trả về 4" in text and "trả về 429" not in text:
                raise
            if attempt >= 3:
                break
            delay = attempt * 2
            next_route = "phiên mới của kho proxy" if attempt == 1 else "kết nối trực tiếp dự phòng"
            _append_log(
                account_id,
                f"request ngoại lệ(lần {attempt}/3 lần): {type(exc).__name__}: {text[:300]}；"
                f"{delay}s sau chuyển đến {next_route} thử lại",
            )
            logger.warning("[đổi email] %s attempt=%s failed: %s", path, attempt, text[:300])
            time.sleep(delay)
            # Lần hai chọn lại cổng ra từ pool proxy; lần ba rõ ràng kết nối trực tiếp, tránh proxy hỏng liên tục reset.
            current = _new_session(
                account_id, None if attempt == 1 else "", email=fingerprint_email,
            )
    assert last_exc is not None
    raise last_exc


def _enqueue_live_check_after_change(account_id: int, email: str) -> dict:
    "đổi email thành công sau ngay xếp hàng kiểm tra sống, dùng email mới lại đăng nhập và làm mới hết hiệu lực  AT. "
    from core import live_check_service

    result = live_check_service.enqueue_account_live_check(
        account_id=int(account_id), email=str(email),
        trigger="email_change_auto", proxy=None,
    )
    if result.get("accepted"):
        logger.info("[đổi email] đã tự thêm vào hàng đợi kiểm tra sống account_id=%s email=%s", account_id, email)
        _append_log(account_id, f"đã xếp hàng tự kiểm tra sống: email={email}")
    else:
        logger.warning(
            "[đổi email] đổi email thành công, nhưng xếp hàng tự kiểm tra sống thất bại account_id=%s email=%s error=%s",
            account_id, email, result.get("error") or "Lỗi không xác định",
        )
        _append_log(account_id, f"xếp hàng tự kiểm tra sống thất bại: {result.get('error') or "Lỗi không xác định"}")
    return result


def _refresh_recent_login(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
) -> tuple[BrowserSession, str]:
    "theo kiểm tra sống đầy đủ đăng nhập chuỗi lại đăng nhập, thiết lập máy chủ nhận có thể  Recent Login. \n\n  change_email  reauth chuỗi sẽ không mục mục tới email gốc gửi OTP, tức để tài khoản đã qua lưu \n  đăng ký mật khẩu. này trong đổi là tái dùng kiểm tra sống dự phòng đăng nhập chuỗi: ưu tiên mật khẩu(và TOTP), chỉ ở\n  trang đăng nhập thật sự yêu cầu email xác minh khi mới đọc email gốc OTP. \n  "
    # Import trì hoãn, tránh vòng lặp module khi khởi tạo account_liveness.
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
        "Recent Login bắt đầu: tái dùng logic đăng nhập lại của kiểm tra sống(CSRF → signin → authorize → mật khẩu/OTP/MFA → OAuth callback → session/AT)",
    )

    # Giữ danh tính thiết bị cấp tài khoản và hồ sơ trình duyệt đã tạo trong lần đổi liên kết này, đồng thời để kiểm tra trước trạng thái hoạt động
    # Tạo Cookie Jar đăng nhập sạch và có được khả năng thử lại mạng của nó.
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
    # Nhất quán với kiểm tra sống backend: chuỗi xác thực đầy đủ của tuyến proxy chỉ cần nhận 403, dùng một bộ hoàn toàn
    # Chạy lại phiên kết nối trực tiếp độc lập. 403 của OAuth callback sẽ khiến BrowserSession hiện tại
    # Vào cầu chì 15 phút; chỉ xóa cầu chì rồi tiếp tục request vừa không sửa được cổng ra, vừa dễ tái dùng
    # CF Cookie đã bị nhiễm, vì vậy phải đăng nhập lại từ CSRF.
    routes = [(selected_proxy, fingerprint_state, "tuyến proxy hiện tại")]
    if selected_proxy:
        routes.append(("", {}, "dự phòng kết nối trực tiếp độc lập"))

    last_exc: BaseException | None = None
    for route_index, (route_proxy, route_state, route_label) in enumerate(routes):
        login_session: BrowserSession | None = None
        try:
            _append_log(account_id, f"Recent Login tuyến bắt đầu: {route_label}")
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
                    f"tài khoản đã hỏng({dead_code}）",
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
                raise RuntimeError("Recent Login đăng nhập lại xong, nhưng chưa lấy được mới access_token")
            _append_log(
                account_id,
                f"Recent Login hoàn tất: route={route_label}, đã lấy mới AT, cost={_cost(login_started)}",
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
                "Recent Login tuyến proxy nhận 403/phiên ngắt mạch, "
                f"đóng phiên thất bại và từ CSRF bắt đầu dùng dự phòng kết nối trực tiếp độc lập: {type(exc).__name__}: {str(exc)[:260]}",
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
    "ưu tiên trực tiếp begin; chỉ ở máy chủ rõ yêu cầu Recent Login khi xác minh email gốc. "
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
        _append_log(account_id, "hiện có AT đáp ứng Recent Login yêu cầu, đã bỏ qua email gốc OTP xác thực lại")
        return session, access_token, otp_after_ts, False
    except Exception as exc:
        if not _is_reauth_required(exc):
            raise

    _append_log(account_id, "máy chủ trả về reauth_required, bắt đầu đăng nhập lại tài khoản gốc theo logic kiểm tra sống")
    session, fresh_token = _refresh_recent_login(
        session,
        account_id=account_id,
        email=current_email,
        email_source=current_source,
    )
    # Mốc thời gian OTP email mới phải đặt trước lần begin thứ hai, không được dùng lại thời gian trước tái xác thực.
    otp_after_ts = time.time()
    _, session = _post_with_network_retry(
        session,
        account_id=account_id,
        path="/backend-api/accounts/change_email/begin",
        token=fresh_token,
        payload={"email": new_email},
        fingerprint_email=current_email,
    )
    _append_log(account_id, "đăng nhập lại tài khoản gốc xong, dùng mới AT thử lại begin thành công")
    return session, fresh_token, otp_after_ts, True


def _check_live_in_current_session(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
) -> dict:
    "đổi email rồi tái dùng hiện tại đã qua CF/reauth  phiên lại đăng nhập và làm mới AT. "
    from core.account_liveness import (
        _login_via_password_or_otp,
        _safe_fingerprint_for_account,
        _safe_fingerprint_text_for_account,
    )
    from core.chatgpt_auth import get_csrf_token, signin_openai
    from core.openai_auth import follow_authorize

    live_started = time.monotonic()
    _append_log(account_id, "bắt đầu kiểm tra sống bằng phiên gốc: tái dùng Cookie, CF trạng thái, đầu ra và fingerprint hiện tại")
    step_started = time.monotonic()
    csrf = get_csrf_token(session)
    _append_log(account_id, f"kiểm tra sống bằng phiên gốc: CSRF lấy thành công, cost={_cost(step_started)}")
    step_started = time.monotonic()
    authorize_url = signin_openai(session, csrf, email)
    _append_log(account_id, f"kiểm tra sống bằng phiên gốc: signin thành công và lấy được authorize URL, cost={_cost(step_started)}")
    otp_after_ts = time.time()
    step_started = time.monotonic()
    follow_authorize(session, authorize_url)
    _append_log(account_id, f"kiểm tra sống bằng phiên gốc: authorize theo hoàn tất, vào mật khẩu/OTP/MFA giai đoạn, cost={_cost(step_started)}")
    step_started = time.monotonic()
    session_info = _login_via_password_or_otp(
        session,
        email,
        otp_after_ts,
        email_source=email_source or None,
    )
    access_token = str((session_info or {}).get("accessToken") or "").strip()
    if not access_token:
        raise RuntimeError("kiểm tra sống bằng phiên gốc sau đổi email không lấy được access_token")
    _append_log(account_id, f"kiểm tra sống bằng phiên gốc: xác minh đăng nhập và session lấy thành công, cost={_cost(step_started)}")
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
    _append_log(account_id, f"kiểm tra sống bằng phiên gốc thành công: mới nhất AT đã ghi lại, total={_cost(live_started)}")
    return result


def _run(account_id: int, source: str) -> dict:
    new_email = ""
    task_started = time.monotonic()
    stage = "khởi tạo"
    with _LOCK:
        _RUNNING.add(account_id)
    try:
        _append_log(account_id, f"bắt đầu thực thi tác vụ: account_id={account_id} source={source}")
        stage = "đọc tài khoản"
        account = db.get_account(account_id)
        if not account:
            raise RuntimeError("Tài khoản không tồn tại")
        token = str(account.get("access_token") or "").strip()
        if not token:
            raise RuntimeError("tài khoản thiếu access_token, hãy kiểm tra sống để làm mới trước AT")
        stage = "lấy email mới"
        acquire_started = time.monotonic()
        new_email = acquire_email_from_source(source)
        _append_log(account_id, f"lấy email mới thành công: source={source} email={new_email} cost={_cost(acquire_started)}")
        if new_email.lower() == str(account.get("email") or "").lower():
            raise RuntimeError("email vừa lấy trùng email hiện tại")
        if not db.mark_account_email_change_running(account_id, new_email):
            raise RuntimeError("trạng thái tác vụ đổi email đã hết hiệu lực")

        stage = "tạo phiên mạng"
        saved_proxy = _proxy(account.get("proxy_used"))
        # Khi tài khoản không có URL proxy thật có thể tái sử dụng, chọn đường theo pool proxy toàn cục trước, thay vì kết nối trần trực tiếp.
        current_email = str(account.get("email") or "").strip()
        current_source = str(account.get("email_source") or "").strip().lower()
        session = _new_session(account_id, saved_proxy or None, email=current_email)
        _append_log(
            account_id,
            f"đã tạo phiên mạng: route={"tài khoản proxy" if saved_proxy else "kho proxy toàn cục/mặc định mạng"} "
            f"proxy={_proxy_label(getattr(session, 'proxy', None))}",
        )
        _append_log(account_id, f"tóm tắt fingerprint: {session.fingerprint_summary_text()}")

        logger.info("[đổi email] begin account_id=%s old=%s new=%s source=%s", account_id, account.get("email"), new_email, source)
        _append_log(account_id, f"bắt đầu đổi email: email gốc={account.get('email') or '-'}, email mới={new_email}, nguồn={source}")
        stage = "gửi mã OTP email mới/xác thực lại khi cần"
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
            f"đã gửi mã OTP email mới thành công, bắt đầu chờ OTP; reauth={'yes' if reauthenticated else 'no'}",
        )
        stage = "chờ email mới OTP"
        otp_started = time.monotonic()
        otp = wait_for_otp(new_email, after_ts=after_ts, email_source=source, force_service=True)
        _append_log(account_id, f"email mới OTP lấy thành công: source={source} cost={_cost(otp_started)}(không ghi mã OTP vào nhật ký)")
        stage = "xác minh email mới OTP"
        _, session = _post_with_network_retry(
            session, account_id=account_id,
            path="/backend-api/accounts/change_email/verify", token=token,
            payload={"email": new_email, "code": otp},
            fingerprint_email=current_email,
        )
        _append_log(account_id, "email mới OTP máy chủ xác minh thành công, bắt đầu cập nhật bản ghi tài khoản cục bộ")

        stage = "cập nhật tài khoản cục bộ"
        db_started = time.monotonic()
        db.finish_account_email_change(
            account_id, ok=True, new_email=new_email, source=source,
            material_line=email_material_line(new_email, source),
        )
        _append_log(account_id, f"cập nhật tài khoản cục bộ thành công: current_email={new_email}, cũ AT đã xoá trống, cost={_cost(db_started)}")
        # Bắt gói cho thấy sau verify AT cũ sẽ ngay lập tức 401, nhưng __cf_bm, OAuth trong phiên hiện tại
        # Cookie và tính liên tục đầu ra vẫn còn hiệu lực. Ưu tiên đăng nhập lại trong phiên đó, tránh sau khi tạo phiên khác
        # `/api/auth/csrf` bị CF 403; khi phiên gốc thất bại thì quay lại hàng đợi kiểm tra sống ở backend.
        stage = "tự kiểm tra sống sau đổi email"
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
                f"kiểm tra sống bằng phiên gốc thất bại: {type(live_exc).__name__}: {str(live_exc)[:300]}; chuyển sang hàng đợi kiểm tra sống nền",
            )
            logger.warning("[đổi email] kiểm tra sống bằng phiên gốc thất bại account_id=%s: %s", account_id, str(live_exc)[:300])
            live_result = _enqueue_live_check_after_change(account_id, new_email)
            live_mode = "queued"
        logger.info("[đổi email] thành công account_id=%s new=%s; đã kiểm tra sống sau đổi email", account_id, new_email)
        _append_log(account_id, f"tác vụ đổi email hoàn tất: live_check_mode={live_mode} total={_cost(task_started)}")
        return {
            "ok": True, "id": account_id, "email": new_email,
            "live_check_started": bool(live_result.get("ok") or live_result.get("accepted")),
            "live_check_mode": live_mode,
            "live_check_error": None if (live_result.get("ok") or live_result.get("accepted")) else live_result.get("error"),
        }
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        db.finish_account_email_change(account_id, ok=False, new_email=new_email or None, source=source, error=error)
        _append_log(account_id, f"đổi email thất bại: stage={stage} total={_cost(task_started)} error={error}")
        if new_email:
            try:
                release_email_if_unconsumed(new_email, note=f"tài khoản #{account_id} đổi email thất bại: {error[:300]}")
                _append_log(account_id, f"xử lý email thất bại xong: đã yêu cầu thu hồi email={new_email}")
            except Exception:
                _append_log(account_id, f"thu hồi email thất bại gặp ngoại lệ: email={new_email}")
                logger.exception("[đổi email] thu hồi email mới thất bại: %s", new_email)
        logger.exception("[đổi email] thất bại account_id=%s", account_id)
        return {"ok": False, "id": account_id, "error": error}
    finally:
        with _LOCK:
            _RUNNING.discard(account_id)
        _SLOTS.release()


def enqueue(account_id: int, source: str, trigger: str = "manual") -> dict:
    account_id = int(account_id)
    source = str(source or "").strip().lower()
    if not _SLOTS.acquire(blocking=False):
        return {"accepted": False, "error": "hàng đợi đổi email đã đầy"}
    if not db.claim_account_email_change(account_id, source, trigger):
        _SLOTS.release()
        return {"accepted": False, "busy": True, "error": "tài khoản đang đổi email hoặc không tồn tại"}
    _append_log(account_id, f"đã xếp hàng tác vụ đổi email: source={source} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(_run, account_id, source)
        return {"accepted": True, "future": future}
    except Exception as exc:
        _SLOTS.release()
        db.finish_account_email_change(account_id, ok=False, error=str(exc))
        _append_log(account_id, f"gửi tác vụ đổi email thất bại: {type(exc).__name__}: {exc}")
        return {"accepted": False, "error": str(exc)}


def is_running(account_id: int) -> bool:
    with _LOCK:
        return int(account_id) in _RUNNING
