# -*- coding: utf-8 -*-
"""
Cổng luồng đăng ký giao thức ChatGPT
Nối 12 bước, tự hoàn tất đăng ký tài khoản ChatGPT
"""
import sys
import argparse
import logging
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Callable

from config import REGISTER_EMAIL, REGISTER_NAME  # hai giá trị này thường không sửa trên WebUI
# Cấu hình hot-reload, đọc theo thuộc tính module
from config import twofa as _twofa_cfg
from config import email as _email_cfg
from config import roxybrowser as _roxy_cfg
from config import openai_protocol as _protocol_cfg
from core.session import BrowserSession
from core.chatgpt_auth import get_providers, get_csrf_token, signin_openai
from core.openai_auth import (
    follow_authorize,
    request_sentinel_token,
    build_sentinel_header,
    validate_email_otp,
    send_email_otp,
    network_preflight,
    navigate_about_you,
    EmailOtpInvalidError,
    create_account,
)
from core.account_export import (
    follow_oauth_callback,
    fetch_session,
    setup_2fa,
    save_account_data,
    create_batch_archive_dir,
)
from core.email_provider import acquire_email, wait_for_otp
from core.humanize import delay as human_delay
from core.name_samples import random_display_name
from core.profile_utils import generate_random_birthday

# Cấu hình log
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

_FINALIZE_SESSION_MAX_ATTEMPTS = 5
_FINALIZE_SESSION_BACKOFF_BASE = 2.0


def configure_logging(verbose: bool = False) -> None:
    """Cấu hình log CLI: mặc định gọn, --verbose thì hiện đủ chi tiết bước."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    for handler in root.handlers:
        handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    if verbose:
        logging.getLogger("core").setLevel(logging.DEBUG)
        return

    logging.getLogger("core").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def _is_success(result: dict) -> bool:
    """Phán một lần đăng ký có thành công không, gom rule thống kê hàng loạt."""
    return isinstance(result, dict) and bool(result.get("success"))


def _finalize_registration_session(
    session: BrowserSession,
    continue_url: str,
    email: str,
    callback_referer: str = "https://auth.openai.com/about-you",
) -> tuple[dict, str]:
    """
    Hoàn tất callback OAuth và kéo accessToken.

    create_account trả về chỉ nghĩa là API tạo đã qua. Dùng được phải đợi chatgpt.com
    ghi cookie phiên đăng nhập và /api/auth/session trả accessToken.
    """
    if not continue_url:
        raise RuntimeError("Phản hồi create_account thiếu continue_url, không hoàn tất được callback OAuth")

    last_exc: Exception | None = None
    for attempt in range(1, _FINALIZE_SESSION_MAX_ATTEMPTS + 1):
        try:
            logger.info(
                f"[Phiên] Hoàn tất callback OAuth và kéo Token: {email} "
                f"(lần {attempt}/{_FINALIZE_SESSION_MAX_ATTEMPTS})"
            )
            follow_oauth_callback(session, continue_url, referer=callback_referer)
            human_delay("post_auth")
            session_info = fetch_session(session)
            access_token = session_info.get("accessToken")
            if not access_token:
                raise RuntimeError("Phản hồi session thiếu accessToken")
            logger.info(f"[Phiên] Đã có accessToken: {email}")
            return session_info, access_token
        except Exception as exc:
            last_exc = exc
            if attempt >= _FINALIZE_SESSION_MAX_ATTEMPTS:
                break
            backoff = _FINALIZE_SESSION_BACKOFF_BASE ** (attempt - 1)
            logger.warning(
                f"[Phiên] Callback hoặc kéo Token thất bại: {email}, "
                f"{type(exc).__name__}: {str(exc)[:180]}, thử lại sau {backoff:.1f}s"
            )
            time.sleep(backoff)

    raise RuntimeError(
        f"Hết lần thử callback OAuth/kéo Token: {email}, "
        f"lỗi cuối: {type(last_exc).__name__ if last_exc else 'Unknown'}: {last_exc}"
    ) from last_exc


def generate_display_name() -> str:
    """Sinh tên hiển thị chỉ gồm chữ Latin và khoảng trắng, đúng giới hạn API đăng ký."""
    return random_display_name()


def prepare_registration_inputs() -> tuple[str | None, str, str]:
    """Chuẩn bị email, tên hiển thị và ngày sinh cho một lần đăng ký theo rule CLI."""
    email = REGISTER_EMAIL
    name = REGISTER_NAME
    birthday = generate_random_birthday()

    # Email: chế độ tự động để trống trước; driver trình duyệt lấy khi trang có ô email,
    # driver protocol lấy trước khi run_registration bắt đầu xác thực.
    if not email:
        if not _email_cfg.USE_EMAIL_SERVICE:
            email = input("Nhập email đăng ký: ").strip()

    # Tên hiển thị: chưa điền thì sinh ngẫu nhiên
    # Giới hạn OpenAI: name_invalid_chars — chỉ chữ và khoảng trắng, không số/dấu câu
    if not name:
        if _email_cfg.USE_EMAIL_SERVICE:
            name = generate_display_name()
            logger.debug(f"Tự sinh tên hiển thị: {name}")
        else:
            name = input("Nhập tên hiển thị: ").strip()

    if not name:
        raise RuntimeError("Tên hiển thị không được trống")
    if not email and not _email_cfg.USE_EMAIL_SERVICE:
        raise RuntimeError("Email không được trống")

    return email, name, birthday


def run_registration(
    email: str | None,
    name: str,
    birthday: str | None = None,
    proxy: str = None,
    otp_code: str = None,
    batch_dir=None,
    on_email_acquired: Callable[[str], None] | None = None,
):
    """
    Chạy luồng đăng ký ChatGPT đầy đủ (OTP-only, không mật khẩu).

    Luồng mặc định OpenAI hiện tại: signin mang login_hint+screen_hint=login_or_signup
    → chuỗi redirect follow_authorize rơi vào /email-verification và kích hoạt gửi OTP
    → người dùng nhập mã OTP → validate_email_otp → about-you gửi biệt danh/ngày sinh → xong.

    Args:
        email: email đăng ký
        name: tên hiển thị
        birthday: ngày sinh, định dạng YYYY-MM-DD
        proxy: địa chỉ proxy (không truyền thì rút ngẫu nhiên từ PROXY_POOL)
        otp_code: mã OTP email (None thì chờ nhập tay)
    """
    # Driver đăng ký:
    #   protocol     = giao thức thuần gốc (curl_cffi)
    #   roxy         = RoxyBrowser fingerprint + Selenium
    #   cloak        = CloakBrowser + lớp thích ứng Playwright/Selenium
    #   browser_use  = Browser Use Cloud stealth Chromium + Playwright
    #   skyvern      = Skyvern Browser Sessions + Playwright
    driver_mode = str(getattr(_roxy_cfg, "REGISTRATION_DRIVER", "protocol") or "protocol").strip().lower()
    if driver_mode in ("roxy", "roxybrowser", "fingerprint", "browser"):
        from core.roxy_registration import run_roxy_registration
        return run_roxy_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode in ("cloak", "cloakbrowser"):
        from core.cloakbrowser_registration import run_cloak_registration
        return run_cloak_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode in ("browser_use", "browseruse", "browser-use", "bu"):
        from core.browser_use_registration import run_browser_use_registration
        return run_browser_use_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode in ("skyvern", "sv"):
        from core.skyvern_registration import run_skyvern_registration
        return run_skyvern_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode not in ("protocol", "api", "http"):
        raise RuntimeError(
            f"REGISTRATION_DRIVER={driver_mode!r} không hỗ trợ, chọn protocol / roxy / cloak / browser_use / skyvern"
        )

    # Driver giao thức thuần không có "ô nhập email" để chờ, nên lấy email trước khi tạo BrowserSession.
    if not str(email or "").strip():
        if not _email_cfg.USE_EMAIL_SERVICE:
            raise RuntimeError(
                "Chế độ thủ công chưa cấu hình email. Đặt REGISTER_EMAIL trên trang cấu hình WebUI, "
                "hoặc bật USE_EMAIL_SERVICE và lấy từ kho email."
            )
        email = acquire_email()
        if on_email_acquired:
            on_email_acquired(email)

    # Tạo phiên trình duyệt (proxy=None thì rút ngẫu nhiên một proxy từ config.PROXY_POOL)
    session = BrowserSession(proxy=proxy)

    # Rút đoạn sid từ URL proxy để log, tránh in đủ tài khoản/mật khẩu
    proxy_label = "không"
    if session.proxy:
        # Dạng socks5h://user-region-JP-sid-XXXX-t-5:pass@host:port
        try:
            sid_part = next(
                (seg for seg in session.proxy.split("@")[0].split("-") if len(seg) == 8),
                "***",
            )
            proxy_label = f"{session.proxy.split('://')[0]}://...sid-{sid_part}...@{session.proxy.split('@')[-1]}"
        except Exception:
            proxy_label = "đã cấu hình"

    if not birthday:
        birthday = generate_random_birthday()

    logger.info(f"[Đăng ký] Bắt đầu: {email}, proxy={proxy_label}")
    logger.info(f"[Đăng ký] Ngày sinh ngẫu nhiên lần này: {birthday}")
    logger.debug(f"[Đăng ký] deviceID={session.device_id}, sessionLogID={session.auth_session_logging_id}")

    create_acknowledged = False
    try:
        # Preflight mạng phải xong trước signin/follow_authorize; preflight không mang email, không kích hoạt OTP.
        network_preflight(session)
        human_delay("navigate")

        # Bổ sung chuỗi warmup màn đầu/model ChatGPT ẩn danh theo HAR 2026-07-19.
        if getattr(_protocol_cfg, "CHATGPT_ANON_BOOTSTRAP_ENABLED", True):
            from core.chatgpt_bootstrap import anonymous_bootstrap
            anonymous_bootstrap(
                session,
                strict=bool(getattr(_protocol_cfg, "CHATGPT_BOOTSTRAP_STRICT", False)),
            )
            human_delay("navigate")

        # ==================== Giai đoạn 1: xác thực ChatGPT ====================
        # Bước 1: lấy providers
        providers = get_providers(session)
        human_delay("api")

        # Bước 2: lấy CSRF token
        csrf_token = get_csrf_token(session)
        human_delay("api")

        # Bước 3: khởi tạo OAuth signin
        authorize_url = signin_openai(session, csrf_token, email)
        human_delay("api")

        # Ghi mốc thời gian trước "kích hoạt OTP"; lấy thư tự động chỉ xem thư sau mốc này,
        # tránh lấy OTP cũ của lần đăng ký trước.
        otp_after_ts = time.time()

        # ==================== Giai đoạn 2: OpenAI Auth ====================
        # Bước 4: theo authorize URL (tạo cookie auth.openai.com)
        # Vì bước 3 đã mang login_hint + screen_hint=login_or_signup,
        # chuỗi redirect đi thẳng /email-verification và tự kích hoạt gửi OTP,
        # không cần /create-account/password, register_user, hay gọi send_email_otp riêng.
        follow_authorize(session, authorize_url)
        human_delay("navigate")

        # ==================== Giai đoạn 3: xác minh mã OTP ====================
        # Không sinh Sentinel Token sớm; sinh sát request validate sau khi có OTP,
        # tránh challenge hết hạn lúc chờ email hoặc lệch trạng thái sau khi gửi lại.

        # Chờ mã OTP: USE_EMAIL_SERVICE=True thì tự lấy từ Outlook, không thì nhập tay.
        # Mã sai/hết hạn thì tự gửi lại và lấy mã mới nhất.
        validate_result = None
        max_otp_attempts = 3
        current_otp = otp_code
        for otp_attempt in range(1, max_otp_attempts + 1):
            if current_otp is None:
                if _email_cfg.USE_EMAIL_SERVICE:
                    logger.info(f"[OTP] Chờ mã OTP: {email} (lần {otp_attempt}/{max_otp_attempts})")
                    current_otp = wait_for_otp(email, after_ts=otp_after_ts)
                else:
                    logger.info("")
                    logger.info(f"[OTP] Kiểm tra email, nhập mã OTP 6 số (lần {otp_attempt}/{max_otp_attempts}):")
                    current_otp = input(">>> Mã OTP: ").strip()

            human_delay("otp_input")
            try:
                # Khớp HAR: email-otp/validate trong bắt gói 2026-07-19 không mang Sentinel.
                # Giữ công tắc, cần thì cắt về logic cũ.
                sentinel_header_9 = None
                so_header_9 = None
                if getattr(_protocol_cfg, "SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", False):
                    sentinel_resp_9 = request_sentinel_token(session, "authorize_continue")
                    sentinel_header_9, so_header_9 = build_sentinel_header(session, sentinel_resp_9, "authorize_continue")
                    human_delay("challenge")

                # Bước 10: nộp mã OTP
                validate_result = validate_email_otp(session, current_otp, sentinel_header_9, so_header_9)
                break
            except EmailOtpInvalidError as exc:
                if otp_attempt >= max_otp_attempts:
                    raise
                logger.warning(f"[OTP] Mã OTP sai/hết hạn: {str(exc)[:180]}, chuẩn bị gửi lại và lấy mã mới")
                otp_after_ts = time.time()
                send_email_otp(session)
                human_delay("api")
                current_otp = None

        if validate_result is None:
            raise RuntimeError("Xác minh OTP chưa xong")
        human_delay("api")

        # Bước sau khi xác minh OTP do auth session server quyết định:
        #   - about_you: tài khoản mới, tiếp tục nộp tên/ngày sinh qua create_account.
        #   - external_url: server thường đã callback OAuth được (hay gặp tài khoản có sẵn / không cần trang hồ sơ),
        #                   gọi create_account lúc này sẽ gây invalid_auth_step.
        page = validate_result.get("page") if isinstance(validate_result, dict) else {}
        page = page if isinstance(page, dict) else {}
        page_type = str(page.get("type") or "")
        otp_continue_url = (
            validate_result.get("continue_url")
            or validate_result.get("external_url")
            or validate_result.get("url")
            or page.get("continue_url")
            or page.get("external_url")
            or page.get("url")
        )
        logger.info(
            f"[Bước 10] Nhánh tiếp theo: page_type={page_type or 'trống'}, "
            f"has_continue_url={bool(otp_continue_url)}"
        )

        # ==================== Giai đoạn 5/6: hoàn tất đăng ký hoặc callback OAuth thẳng ====================
        otp_continue_text = str(otp_continue_url or "")
        direct_oauth_after_otp = bool(
            otp_continue_text
            and "about-you" not in otp_continue_text
            and (
                "chatgpt.com/api/auth/callback" in otp_continue_text
                or "auth.openai.com/authorize/continue" in otp_continue_text
                or page_type == "external_url"
            )
        )
        if page_type == "external_url" or direct_oauth_after_otp:
            if not otp_continue_url:
                raise RuntimeError(f"Phản hồi OTP external_url thiếu URL để theo, không tiếp tục được: {validate_result}")
            logger.info(f"[Đăng ký] Sau OTP vào nhánh callback OAuth, bỏ create_account: {email}")
            create_acknowledged = True
            session_info, access_token = _finalize_registration_session(
                session,
                otp_continue_url,
                email,
                callback_referer="https://auth.openai.com/email-verification",
            )
            if getattr(_protocol_cfg, "CHATGPT_AUTH_BOOTSTRAP_ENABLED", True):
                from core.chatgpt_bootstrap import authenticated_bootstrap
                authenticated_bootstrap(
                    session,
                    access_token,
                    strict=bool(getattr(_protocol_cfg, "CHATGPT_BOOTSTRAP_STRICT", False)),
                )
            human_delay("post_auth")
        else:
            # Tương thích server chỉ trả continue_url=/about-you nhưng page.type trống/đổi.
            if page_type and page_type not in ("about_you", "about-you"):
                if otp_continue_url and "about-you" not in str(otp_continue_url):
                    raise RuntimeError(
                        f"Loại trang sau OTP không rõ, không được create_account mù: "
                        f"page_type={page_type}, resp={validate_result}"
                    )
                logger.warning(
                    f"[Bước 10] page_type={page_type} không rõ, nhưng continue_url trỏ about-you, tiếp tục create_account"
                )

            # Điều hướng thật tới about-you trước, để auth session/page state khớp create_account.
            about_url = str(otp_continue_url) if otp_continue_url and "about-you" in str(otp_continue_url) else None
            navigate_about_you(session, about_url)
            human_delay("navigate")

            # Bước 11: lấy Sentinel Token (oauth_create_account)
            sentinel_resp_11 = request_sentinel_token(session, "oauth_create_account")
            sentinel_header_11, so_header_11 = build_sentinel_header(session, sentinel_resp_11, "oauth_create_account")
            human_delay("challenge")

            human_delay("form")

            # Bước 12: nộp thông tin người dùng, hoàn tất đăng ký
            create_result = create_account(session, name, birthday, sentinel_header_11, so_header_11)
            create_acknowledged = True

            logger.info(f"[Đăng ký] API tạo đã qua: {email}, tiếp tục hoàn tất callback OAuth")
            human_delay("post_auth")

            # Bước 12.5: theo continue_url của create_account để hoàn tất callback OAuth
            continue_url = create_result.get("continue_url")
            if not continue_url:
                raise RuntimeError(
                    f"Phản hồi create_account thiếu continue_url, không tiếp tục được: {create_result}"
                )

            # Bước 13: kéo /api/auth/session để lấy accessToken
            session_info, access_token = _finalize_registration_session(session, continue_url, email)
            if getattr(_protocol_cfg, "CHATGPT_AUTH_BOOTSTRAP_ENABLED", True):
                from core.chatgpt_bootstrap import authenticated_bootstrap
                authenticated_bootstrap(
                    session,
                    access_token,
                    strict=bool(getattr(_protocol_cfg, "CHATGPT_BOOTSTRAP_STRICT", False)),
                )
            human_delay("post_auth")

        # ==================== Giai đoạn 7: đặt 2FA (theo config.ENABLE_2FA) ====================
        totp_secret = None
        if _twofa_cfg.ENABLE_2FA:
            # Bước 14-20: xác thực lại (nhận thêm một OTP email) → enroll TOTP → activate
            try:
                totp_secret = setup_2fa(session, email)
            except Exception as exc:
                logger.error(f"Đặt 2FA thất bại: {exc}")
                logger.debug("Chi tiết lỗi 2FA:", exc_info=True)
                logger.warning("Vẫn lưu thông tin tài khoản (không có TOTP secret), có thể đặt tay sau")
        else:
            logger.debug("Đã bỏ đặt 2FA (config.ENABLE_2FA=False)")

        # ==================== Giai đoạn 7.5: Codex OAuth (đăng ký xong → lấy callback/credential CPA) ====================
        # Dùng session sạch đăng nhập email từ đầu: OTP email → xác minh SMS (nhận OTP) → chọn workspace
        # → lấy code (không tái dùng session đăng ký, tránh kẹt choose-an-account).
        # Sản phẩm:
        #   1) codex_result["callback_url"]  Location trúng redirect_uri (mang code/state)
        #   2) codex_result["file_path"]     codex-{email}.json CPA nhập được
        codex_result = {"status": "skipped", "ok": False, "message": "chưa kích hoạt"}
        try:
            from core.codex_oauth import run_codex_oauth
            codex_result = run_codex_oauth(email)
        except Exception as exc:
            codex_result = {
                "status": "failed",
                "ok": False,
                "message": f"{type(exc).__name__}: {str(exc)[:180]}",
            }

        if codex_result.get("ok"):
            logger.info(
                f"[Codex] Thành công: {email}, file={codex_result.get('file_path')},"
                f"callback={codex_result.get('callback_url')}"
            )
        elif codex_result.get("status") == "skipped":
            logger.info(f"[Codex] Bỏ qua: {email}, lý do={codex_result.get('message')}")
        else:
            logger.warning(
                f"[Codex] Thất bại: {email}, lý do={codex_result.get('message')}"
            )

        # ==================== Giai đoạn 8: lưu tài khoản ====================
        from core.email_provider import resolve_email_source
        account_id = save_account_data(
            email=email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(email),
            proxy_used=session.proxy or None,
            batch_dir=batch_dir,
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "device_id": session.device_id,
                "sentinel_sid": getattr(session, "sentinel_sid", None),
                "browser_profile": getattr(session, "browser_profile", None),
                "codex": codex_result,
            },
        )

        logger.info(f"[Xong] {email}, ID tài khoản={account_id}, Token={access_token[:16]}...")

        # ==================== Giai đoạn 9: tự gọi flow sau ====================
        # Chỉ tài khoản đã callback, có token và lưu thành công mới gọi flow.
        # Request flow không đổi trạng thái đã lưu, nhưng ghi kết quả và vào thống kê hàng loạt.
        flow_result = {"status": "skipped", "ok": False, "message": "chưa kích hoạt"}
        try:
            from core.flow_trigger import trigger_flow
            flow_result = trigger_flow(access_token)
        except Exception as exc:
            flow_result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {exc}"}

        if flow_result.get("ok"):
            logger.info(
                f"[Flow] Thành công: {email}, HTTP={flow_result.get('http_status')}, "
                f"flow_id={flow_result.get('flow_id') or 'chưa parse'}"
            )
        elif flow_result.get("status") == "skipped":
            logger.info(f"[Flow] Bỏ qua: {email}, lý do={flow_result.get('message')}")
        else:
            logger.warning(
                f"[Flow] Thất bại: {email}, HTTP={flow_result.get('http_status') or 'không'}, "
                f"lý do={flow_result.get('message')}"
            )

        logger.debug(f"[Xong] TOTP Secret: {totp_secret or '(chưa đặt)'}")

        # Thành công tác vụ đăng ký: tài khoản (đăng ký+token) và uỷ quyền Codex đều thành công mới là success.
        # Codex thất bại thì tài khoản vẫn lưu (đã có token, còn cơ hội bổ chạy), nhưng tác vụ đánh thất bại,
        # để bảng tác vụ WebUI phân biệt "thành công đủ" và "thiếu Codex".
        codex_ok = codex_result.get("ok") or codex_result.get("status") == "skipped"
        task_success = codex_ok
        task_error = None
        if not task_success:
            task_error = f"Codex chưa xong: {codex_result.get('message', 'không rõ')}"
            logger.warning(f"[Kết quả tác vụ] {email} đã lưu tài khoản nhưng tác vụ thất bại, lý do: {task_error}")

        return {"success": task_success, "email": email, "account_id": account_id,
                "access_token": access_token, "totp_secret": totp_secret,
                "flow": flow_result, "codex": codex_result,
                "error": task_error}

    except Exception as e:
        logger.error(f"[Thất bại] {email}: {type(e).__name__}: {e}")
        logger.debug("Chi tiết lỗi:", exc_info=True)
        # Chiến lược thu hồi trạng thái email, ba trường hợp:
        #   1. Tài khoản đã hỏng (account_deactivated, v.v.): vật liệu email không dùng được, đánh failed và loại.
        #   2. Thất bại sau khi API tạo đã qua: remote đã tiêu email này, bỏ luôn, tránh đăng ký lại.
        #   3. Thất bại thường trước khi API tạo qua: email còn thử được lần sau, trả về available.
        from core.openai_auth import AccountUnusableError
        account_dead = isinstance(e, AccountUnusableError)
        try:
            if email:
                from core.email_provider import release_email
                if account_dead:
                    src = release_email(
                        email, status="failed",
                        note=f"Tài khoản đã bỏ, email không dùng được: {str(e)[:180]}",
                    )
                    logger.warning(f"[Email:{src}] {email} tài khoản đã bỏ, đánh failed, không đăng ký lại")
                elif create_acknowledged:
                    src = release_email(
                        email, status="failed",
                        note=f"API tạo đã qua nhưng bước sau thất bại, đã bỏ: {str(e)[:180]}",
                    )
                    logger.warning(f"[Email:{src}] {email} đã tạo nhưng bước sau thất bại, đánh failed, không đăng ký lại")
                else:
                    src = release_email(email, status="available", note=f"Lần trước thất bại: {str(e)[:180]}")
                    logger.info(f"[Email:{src}] {email} đã khôi phục available")
        except Exception:
            pass
        return {"success": False, "email": email, "error": str(e)}


def main():
    """Hàm chính"""
    parser = argparse.ArgumentParser(description="CLI đăng ký giao thức ChatGPT")
    parser.add_argument("-n", "--count", type=int, default=1, help="Số lần đăng ký liên tiếp, mặc định 1")
    parser.add_argument("--workers", type=int, default=1, help="Số luồng đăng ký đồng thời, mặc định 1 (tuần tự)")
    parser.add_argument("--delay", type=float, default=0, help="Số giây nghỉ sau mỗi lần đăng ký")
    parser.add_argument("--continue-on-fail", action="store_true", help="Một tài khoản thất bại vẫn đăng ký tài khoản tiếp theo")
    parser.add_argument("--verbose", action="store_true", help="Hiện log bước chi tiết và stack lỗi")
    args = parser.parse_args()
    configure_logging(args.verbose)

    if args.count < 1:
        logger.error("Số lượng đăng ký phải lớn hơn 0")
        sys.exit(1)

    if args.workers < 1:
        logger.error("Số luồng đồng thời phải lớn hơn 0")
        sys.exit(1)

    if args.count > 1 and REGISTER_EMAIL:
        logger.error("config.REGISTER_EMAIL đã cố định email, không hợp đăng ký hàng loạt; để trống rồi mới dùng --count")
        sys.exit(1)

    if args.workers > 1 and not _email_cfg.USE_EMAIL_SERVICE:
        logger.error("Đăng ký đa luồng cần bật lấy thư Outlook tự động; bật USE_EMAIL_SERVICE hoặc dùng --workers 1")
        sys.exit(1)

    if args.workers > args.count:
        logger.info(f"[Hàng loạt] Số luồng {args.workers} lớn hơn số mục tiêu, chạy theo {args.count} tác vụ")
        args.workers = args.count

    if args.workers > 1:
        batch_dir = create_batch_archive_dir(args.count, args.workers)
        logger.info("[Hàng loạt] Dữ liệu tài khoản ghi thẳng vào SQLite")
        results = run_parallel_batch(args.count, args.workers, args.delay, args.continue_on_fail, batch_dir)
    else:
        batch_dir = create_batch_archive_dir(args.count, args.workers)
        logger.info("[Hàng loạt] Dữ liệu tài khoản ghi thẳng vào SQLite")
        results = run_serial_batch(args.count, args.delay, args.continue_on_fail, batch_dir)

    success_count = sum(1 for r in results if _is_success(r))
    flow_success_count = sum(
        1 for r in results
        if _is_success(r) and isinstance(r.get("flow"), dict) and r["flow"].get("ok")
    )
    flow_failed_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("flow"), dict)
        and r["flow"].get("status") == "failed"
    )
    flow_skipped_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("flow"), dict)
        and r["flow"].get("status") == "skipped"
    )
    codex_success_count = sum(
        1 for r in results
        if _is_success(r) and isinstance(r.get("codex"), dict) and r["codex"].get("ok")
    )
    codex_failed_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("codex"), dict)
        and r["codex"].get("status") == "failed"
    )
    codex_skipped_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("codex"), dict)
        and r["codex"].get("status") == "skipped"
    )
    logger.info(f"[Hàng loạt] Xong: thành công {success_count} / thử {len(results)} / mục tiêu {args.count}")
    if success_count:
        logger.info(
            f"[Hàng loạt] Flow: thành công {flow_success_count} / thất bại {flow_failed_count} / bỏ qua {flow_skipped_count}"
        )
        logger.info(
            f"[Hàng loạt] Codex: thành công {codex_success_count} / thất bại {codex_failed_count} / bỏ qua {codex_skipped_count}"
        )
    sys.exit(0 if success_count == args.count else 1)


def run_one_batch_item(index: int, total: int, batch_dir=None) -> dict:
    """Chạy một tác vụ trong đăng ký hàng loạt, trả kết quả có cấu trúc."""
    logger.info(f"[Hàng loạt] Bắt đầu đăng ký {index + 1}/{total}")
    try:
        email, name, birthday = prepare_registration_inputs()
        return run_registration(
            email=email,
            name=name,
            birthday=birthday,
            batch_dir=batch_dir,
            # không truyền proxy → BrowserSession rút ngẫu nhiên từ PROXY_POOL
        )
    except Exception as exc:
        logger.error(f"[Hàng loạt] Đăng ký {index + 1} thất bại ở giai đoạn chuẩn bị: {type(exc).__name__}: {exc}")
        logger.debug("Chi tiết lỗi giai đoạn chuẩn bị:", exc_info=True)
        return {"success": False, "error": str(exc)}


def run_serial_batch(count: int, delay: float, continue_on_fail: bool, batch_dir=None) -> list[dict]:
    """Chạy đăng ký hàng loạt theo cách tuần tự cũ."""
    results = []
    for index in range(count):
        result = run_one_batch_item(index, count, batch_dir)
        results.append(result)
        if not _is_success(result) and not continue_on_fail:
            logger.error("[Hàng loạt] Tài khoản hiện tại thất bại, đã dừng. Muốn chạy tiếp thì thêm --continue-on-fail")
            break

        if delay > 0 and index < count - 1:
            logger.info(f"[Hàng loạt] Chờ {delay} giây rồi tiếp tục")
            time.sleep(delay)
    return results


def run_parallel_batch(
    count: int,
    workers: int,
    delay: float,
    continue_on_fail: bool,
    batch_dir=None,
) -> list[dict]:
    """Đăng ký hàng loạt đồng thời bằng thread pool."""
    logger.info(f"[Hàng loạt] Bật đăng ký đa luồng: mục tiêu {count}, đồng thời {workers}")
    if delay > 0:
        logger.info(f"[Hàng loạt] Ở chế độ đồng thời --delay={delay} là khoảng lệch pha giữa các lần nộp tác vụ")

    results: list[dict] = []
    future_to_index = {}
    next_index = 0
    stop_submitting = False

    def submit_next(executor: ThreadPoolExecutor) -> bool:
        nonlocal next_index
        if stop_submitting or next_index >= count:
            return False
        future = executor.submit(run_one_batch_item, next_index, count, batch_dir)
        future_to_index[future] = next_index
        next_index += 1
        if delay > 0 and next_index < count:
            time.sleep(delay)
        return True

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="reg-cli") as executor:
        while len(future_to_index) < workers and submit_next(executor):
            pass

        while future_to_index:
            done, _ = wait(future_to_index, return_when=FIRST_COMPLETED)
            for future in done:
                index = future_to_index.pop(future)
                try:
                    result = future.result()
                except Exception as exc:
                    logger.error(f"[Hàng loạt] Luồng đăng ký {index + 1}/{count} lỗi: {type(exc).__name__}: {exc}")
                    logger.debug("Chi tiết lỗi luồng:", exc_info=True)
                    result = {"success": False, "error": str(exc)}
                results.append(result)

                if not _is_success(result) and not continue_on_fail:
                    stop_submitting = True
                    logger.error("[Hàng loạt] Tài khoản hiện tại thất bại, đã ngừng nộp tác vụ mới. Tác vụ đã bắt đầu chạy nốt.")

            while len(future_to_index) < workers and submit_next(executor):
                pass

    return results


if __name__ == "__main__":
    main()
