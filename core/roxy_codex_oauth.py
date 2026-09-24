# -*- coding: utf-8 -*-
"""Thực hiện ủy quyền OAuth Codex qua trình duyệt vân tay RoxyBrowser."""
from __future__ import annotations

import logging
import random
import time
from contextvars import ContextVar
from urllib.parse import urlparse

from config import roxybrowser as _roxy_cfg
from core.email_provider import wait_for_otp
from core.humanize import delay as human_delay
from core import sms_provider
from core.openai_auth import AccountUnusableError, detect_account_unusable_response_body
from core.roxybrowser_client import RoxyBrowserClient
from core import codex_oauth as _codex_proto
from core.roxy_registration import (
    _build_driver,
    _center_browser_window,
    _click_any,
    _click_continue,
    _find_any,
    _maybe_accept,
    _human_click,
    _human_type_text,
    _type_any,
    _type_email_address,
    _submit_email_step,
    _click_email_entry_option,
    _type_otp,
    _clear_otp_inputs,
    _email_otp_page_state,
    _is_email_verification_page,
    _is_login_password_page,
    _click_passwordless_signup_if_present,
)

_base_logger = logging.getLogger(__name__)
_CODEX_BROWSER_KIND: ContextVar[str] = ContextVar("codex_browser_kind", default="Roxy")


def _codex_prefix() -> str:
    return f"[Codex][{_CODEX_BROWSER_KIND.get()}]"


def _codex_driver_name() -> str:
    return _CODEX_BROWSER_KIND.get()


def _detect_browser_kind(opened=None) -> str:
    try:
        raw = getattr(opened, "raw", None) or {}
        if isinstance(raw, dict) and str(raw.get("driver") or "").lower().startswith("cloak"):
            return "Cloak"
    except Exception:
        pass
    return "Roxy"


class _CodexLogger:
    """Thay tiền tố placeholder thống nhất trong quy trình bằng loại trình duyệt thực tế hiện tại."""
    def __init__(self, base):
        self._base = base

    def _msg(self, msg):
        return str(msg).replace("[Codex][Browser]", _codex_prefix())

    def debug(self, msg, *args, **kwargs):
        return self._base.debug(self._msg(msg), *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        return self._base.info(self._msg(msg), *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        return self._base.warning(self._msg(msg), *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        return self._base.error(self._msg(msg), *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        return self._base.exception(self._msg(msg), *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._base, name)


logger = _CodexLogger(_base_logger)


def _is_callback_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return (
        parsed.scheme in ("http", "https")
        and parsed.hostname in ("localhost", "127.0.0.1")
        and parsed.port == 1455
        and parsed.path == "/auth/callback"
    )


def _extract_callback_url_from_page(driver) -> str:
    """Trích xuất OAuth callback URL từ trang hiện tại.

    Khi trình duyệt chuyển tới http://localhost:1455/auth/callback?..., nếu local không có dịch vụ lắng nghe sẽ hiển thị
    chrome-error://chromewebdata/. Thanh địa chỉ có thể thành chrome-error, nhưng
    performance navigation entry của Chromium vẫn giữ callback URL gốc, có thể trích xuất trực tiếp rồi gửi CPA.
    """
    try:
        current = str(driver.current_url or "")
        if _is_callback_url(current):
            return current
    except Exception:
        pass
    try:
        urls = driver.execute_script(r"""
        const out = [];
        const push = v => { if (v && typeof v === 'string') out.push(v); };
        try { push(location.href); } catch (e) {}
        try { push(document.URL); } catch (e) {}
        try { push(document.documentURI); } catch (e) {}
        try { for (const e of performance.getEntriesByType('navigation')) push(e.name); } catch (e) {}
        try { for (const e of performance.getEntries()) push(e.name); } catch (e) {}
        return [...new Set(out)];
        """) or []
        for url in urls:
            if _is_callback_url(str(url)):
                logger.info("[Codex][Browser] đã trích xuất từ bản ghi hiệu năng trình duyệt callback URL: %s", str(url)[:160])
                return str(url)
    except Exception as exc:
        logger.debug("[Codex][Browser] Trích xuất từ trang callback URL Thất bại: %s", exc)
    return ""


def _extract_callback_url_from_any_window(driver) -> str:
    found = _extract_callback_url_from_page(driver)
    if found:
        return found
    try:
        for handle in list(getattr(driver, "window_handles", []) or []):
            try:
                driver.switch_to.window(handle)
                found = _extract_callback_url_from_page(driver)
                if found:
                    return found
            except Exception:
                continue
    except Exception:
        pass
    return ""


def _wait_for_callback(driver, timeout: int | None = None) -> str:
    end = time.time() + (timeout or int(_roxy_cfg.ROXY_CODEX_CALLBACK_TIMEOUT))
    last_url = ""
    while time.time() < end:
        try:
            current = str(driver.current_url or "")
            if current != last_url:
                logger.debug("[Codex][Browser] Hiện tại URL: %s", current)
                last_url = current
            callback = _extract_callback_url_from_any_window(driver)
            if callback:
                return callback
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"chờ Codex callback quá thời gian, cuối cùng URL={last_url}")


def _click_if_present(driver, selectors: list[str], timeout: int = 3) -> bool:
    try:
        _click_any(driver, selectors, timeout=timeout)
        return True
    except Exception:
        return False


def _maybe_click_passwordless_after_email(driver, email: str, timeout: int = 18) -> None:
    """
    Codex OAuth 提交邮箱后也可能跳到 /log-in/password 或 /create-account/password。
    优先点击“使用一次性验证码/one-time code”入口，进入邮箱验证码页。
    """
    end = time.time() + timeout
    last_url = ""
    clicked = False
    while time.time() < end:
        try:
            if _is_email_verification_page(driver):
                if clicked:
                    logger.info("[Codex][Browser] Lối vào mã một lần đã vào trang mã OTP email")
                return
            url = str(driver.current_url or "")
            if url != last_url:
                logger.info("[Codex][Browser] sau khi gửi email thì kiểm tra mật khẩu/OTP Chuyển hướng: url=%s", url or "-")
                last_url = url
            lower = url.lower()
            if any(x in lower for x in ("phone", "workspace", "consent", "authorize", "localhost:1455")):
                return
            if "/password" in lower or "auth.openai.com" in lower:
                result = _click_passwordless_signup_if_present(driver)
                if result.get("ok"):
                    clicked = True
                    logger.info("[Codex][Browser] Đã click lối vào mã OTP một lần: email=%s detail=%s", email, result)
                    human_delay("form")
                    continue
        except Exception as exc:
            logger.debug("[Codex][Browser] thăm dò lối vào mã OTP trên trang mật khẩu thất bại: %s", str(exc)[:140])
        time.sleep(0.5)
    if clicked:
        logger.info("[Codex][Browser] Đã click lối vào mã OTP một lần, Chưa phát hiện ngay OTP Trang, tiếp tục bước sau OTP polling")


def _wait_for_otp_input(driver, timeout: int = 30) -> None:
    """验证码已收到但 OTP 输入框可能尚未出现（点完一次性验证码后常有中间页/延迟渲染）。

    等待期间若仍停留在登录密码页，则补点一次性验证码入口（最多 2 次、间隔 6s）；
    超时仍未出现时打印页面状态便于定位。
    """
    end = time.time() + timeout
    passwordless_retries = 0
    while time.time() < end:
        if _is_email_verification_page(driver):
            return
        if _is_login_password_page(driver) and passwordless_retries < 2:
            passwordless_retries += 1
            result = _click_passwordless_signup_if_present(driver)
            if result.get("ok"):
                logger.info("[Codex][Browser] vẫn ở trang mật khẩu đăng nhập, bấm bù lối vào mã OTP: %s", result.get("reason"))
                human_delay("form")
            time.sleep(6)
            continue
        time.sleep(0.8)
    state = _email_otp_page_state(driver)
    logger.warning(
        "[Codex][Browser] chờ OTP ô nhập timeout, trang url=%s inputs=%s buttons=%s trước văn bản300ký tự=%s",
        str(state.get("url") or ""),
        len(state.get("inputs") or []),
        [(b.get("text") or "")[:24] for b in (state.get("buttons") or [])][:8],
        str(state.get("text") or "")[:300],
    )
    raise RuntimeError("chờ OTP ô nhập timeout, trang chưa hiện ô nhập mã OTP")


def _account_password_for_email(email: str) -> str:
    try:
        return _codex_proto._account_registration_password(email)
    except Exception:
        return ""


def _account_totp_code_for_email(email: str) -> str:
    try:
        return _codex_proto._account_totp_code(email)
    except Exception:
        return ""


def _is_mfa_challenge_page(driver) -> bool:
    try:
        url = str(driver.current_url or "").lower()
        if "/mfa-challenge/" in url or "/mfa-challenge" in url:
            return True
        state = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const form = [...document.querySelectorAll('form')].find(f => /\/mfa-challenge/i.test(f.getAttribute('action') || ''));
        const input = form ? [...form.querySelectorAll('input[name="code"], input[autocomplete="one-time-code"], input[maxlength="6"]')].find(visible) : null;
        return {ok: !!(form && input), url: location.href};
        """) or {}
        return bool(state.get("ok"))
    except Exception:
        return False


def _fill_mfa_challenge_if_present(driver, email: str, timeout: int = 15) -> bool:
    """Nếu hiện đang vào trang MFA challenge, tự động điền TOTP của tài khoản và gửi."""
    code = _account_totp_code_for_email(email)
    if not code:
        return False
    end = time.time() + timeout
    while time.time() < end:
        try:
            if not _is_mfa_challenge_page(driver):
                time.sleep(0.4)
                continue
            result = driver.execute_script(r"""
            const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
              && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
              && !el.disabled && !el.readOnly;
            const form = [...document.querySelectorAll('form')].find(f => /\/mfa-challenge/i.test(f.getAttribute('action') || ''));
            if (!form) return {ok:false, reason:'missing_form'};
            const input = [...form.querySelectorAll('input[name="code"], input[autocomplete="one-time-code"], input[maxlength="6"]')].find(visible);
            if (!input) return {ok:false, reason:'missing_code_input'};
            const button = [...form.querySelectorAll('button[type="submit"], button[data-dd-action-name="Continue"], button')].find(visible);
            if (!button) return {ok:false, reason:'missing_submit'};
            return {ok:true, input, button};
            """) or {}
            if not result.get("ok"):
                time.sleep(0.4)
                continue
            _human_type_text(driver, result.get("input"), code, clear=True)
            human_delay("otp_input")
            _human_click(driver, result.get("button"), label="codex_mfa_submit")
            logger.info("[Codex][Browser] Đã điền và gửi MFA mã OTP: %s", email)
            wait_end = time.time() + 12
            while time.time() < wait_end:
                if not _is_mfa_challenge_page(driver):
                    return True
                time.sleep(0.4)
            return True
        except Exception as exc:
            logger.debug("[Codex][Browser] MFA challenge xử lý thất bại: %s", str(exc)[:160])
            time.sleep(0.5)
    return False


def _fill_login_password_if_present(driver, email: str, timeout: int = 18) -> str | None:
    """Codex OAuth nếu tài khoản có mật khẩu, ưu tiên nhập mật khẩu tại trang mật khẩu đăng nhập. Trả về next_step / email_otp / None."""
    password = _account_password_for_email(email)
    if not password:
        return None
    end = time.time() + timeout
    while time.time() < end:
        if _is_email_verification_page(driver):
            return "email_otp"
        if not _is_login_password_page(driver):
            time.sleep(0.4)
            continue
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="current-password"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_password_input'};
        const form = input.closest('form');
        const scope = form || document;
        const buttons = [...scope.querySelectorAll('button,input[type="submit"]')]
          .filter(el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true')
          .map((el, idx) => {
            const r = el.getBoundingClientRect();
            const ir = input.getBoundingClientRect();
            return {el, idx, below: r.top >= ir.bottom - 10, dist: Math.max(0, r.top - ir.bottom) + Math.abs((r.left+r.right-ir.left-ir.right)/2)/10};
          })
          .filter(x => x.below)
          .sort((a,b) => a.dist - b.dist || a.idx - b.idx);
        if (!buttons.length) return {ok:false, reason:'missing_submit'};
        buttons[0].el.scrollIntoView({block:'center'});
        return {ok:true, reason:'password_targets', input, button: buttons[0].el};
        """) or {}
        if not result.get("ok"):
            logger.info("[Codex][Browser] Không thấy ô nhập trang mật khẩu đăng nhập/Nút gửi: %s", result)
            time.sleep(0.5)
            continue
        _human_type_text(driver, result.get("input"), password, clear=True)
        human_delay("form", minimum=2.0, maximum=3.6)
        _human_click(driver, result.get("button"), label="codex_password_submit")
        logger.info("[Codex][Browser] đã điền và gửi mật khẩu đăng nhập: %s", email)
        wait_end = time.time() + 12
        while time.time() < wait_end:
            if _is_mfa_challenge_page(driver):
                _fill_mfa_challenge_if_present(driver, email, timeout=15)
                return "next_step"
            if _is_email_verification_page(driver):
                return "email_otp"
            if not _is_login_password_page(driver):
                return "next_step"
            time.sleep(0.5)
        return "next_step"
    return None


def _fill_email_and_otp(driver, email: str, otp_provider, auth_url: str) -> None:
    otp_after_ts = time.time()
    logger.info("[Codex][Browser] mở URL uỷ quyền")
    logger.info("[Codex][Browser] URL uỷ quyền đầy đủ: %s", auth_url)
    driver.get(auth_url)
    human_delay("navigate")
    logger.info("[Codex][Browser] trang uỷ quyền tải xong, kiểm tra có cần đăng nhập email")
    _maybe_accept(driver)

    # Có thể đã ở trang chọn tài khoản/ủy quyền; nếu có ô nhập email thì đăng nhập đầy đủ.
    # Khi egress không phải Nhật, text/thứ tự nút đổi — đừng bấm nút Continue theo chữ hiển thị, dễ bấm nhầm Google.
    try:
        _type_email_address(driver, email, timeout=12)
        logger.info("[Codex][Browser] đã điền email: %s", email)
        human_delay("form")
        _submit_email_step(driver)
        logger.info("[Codex][Browser] Đã gửi email, chờ email OTP trang")
        pw_result = _fill_login_password_if_present(driver, email, timeout=18)
        if pw_result == "next_step":
            if _is_mfa_challenge_page(driver):
                _fill_mfa_challenge_if_present(driver, email, timeout=15)
            logger.info("[Codex][Browser] Tài khoản đã đăng nhập xong bằng mật khẩu, Vào thẳng bước tiếp theo")
            return
        if pw_result == "email_otp":
            logger.info("[Codex][Browser] Sau đăng nhập mật khẩu vẫn vào email OTP trang")
        else:
            _maybe_click_passwordless_after_email(driver, email, timeout=18)
    except Exception as exc:
        logger.info("[Codex][Browser] Không phát hiện ô nhập email, Có thể đã đăng nhập hoặc sang bước tiếp: %s", str(exc)[:120])
        return

    # Sau submit email không còn click fallback toàn cục “tiếp tục/ủy quyền/nhánh”; sau đó chỉ chờ trang mã xác minh.
    # Tránh nhầm nhấn nút ủy quyền khi trang đã vào OAuth consent.

    used_codes: set[str] = set()
    max_otp_attempts = 3

    def _restart_email_otp_flow(reason: str) -> None:
        """Bấm resend trực tiếp trên Codex Auth có thể gây lỗi 500 phía máy chủ; ở đây đổi thành mở lại địa chỉ ủy quyền và gửi email."""
        nonlocal otp_after_ts
        logger.info("[Codex][Browser] kích hoạt lại email OTP: %s", reason)
        otp_after_ts = time.time()
        driver.get(auth_url)
        human_delay("navigate")
        _maybe_accept(driver)
        try:
            _type_email_address(driver, email, timeout=12)
            human_delay("form")
            _submit_email_step(driver)
            logger.info("[Codex][Browser] Đã gửi lại email để kích hoạt OTP")
            pw_result = _fill_login_password_if_present(driver, email, timeout=12)
            if pw_result == "next_step":
                if _is_mfa_challenge_page(driver):
                    _fill_mfa_challenge_if_present(driver, email, timeout=15)
                logger.info("[Codex][Browser] sau khi gửi lại email đã đăng nhập xong bằng mật khẩu, vào bước tiếp theo")
                return
            if pw_result != "email_otp":
                _maybe_click_passwordless_after_email(driver, email, timeout=12)
        except Exception as exc:
            # Nếu sau khi vào lại địa chỉ ủy quyền đã dừng ở trang captcha/bước tiếp, đừng cưỡng ép submit nữa.
            if not _is_email_verification_page(driver):
                logger.warning("[Codex][Browser] gửi lại email thất bại, Tiếp tục poll theo trang hiện tại: %s", str(exc)[:180])
            else:
                logger.info("[Codex][Browser] Sau khi mở lại uỷ quyền đã ở email OTP trang")
        human_delay("api")

    for otp_attempt in range(1, max_otp_attempts + 1):
        logger.info("[Codex][Browser] chờ email OTP: %s (thứ %s/%s lần)", email, otp_attempt, max_otp_attempts)
        try:
            code = _wait_for_fresh_email_otp(
                otp_provider,
                email,
                after_ts=otp_after_ts,
                used_codes=used_codes,
                timeout=90,
            )
        except Exception as exc:
            if otp_attempt >= max_otp_attempts:
                raise
            logger.warning(
                "[Codex][Browser] mãi chưa nhận được email OTP, nhấp\"gửi lại email\"sau đó tiếp tục chờ (vòng tiếp theo %s/%s): %s: %s",
                otp_attempt + 1,
                max_otp_attempts,
                type(exc).__name__,
                str(exc)[:180],
            )
            _restart_email_otp_flow("chờ mã OTP quá thời gian, tránh bấm resend dẫn đến 500")
            continue
        used_codes.add(str(code))
        logger.info("[Codex][Browser] email OTP đã nhận: %s", code)
        _wait_for_otp_input(driver, timeout=30)
        _clear_otp_inputs(driver)
        _type_otp(driver, code)
        logger.info("[Codex][Browser] đã điền email OTP")
        human_delay("otp_input")
        _install_email_otp_validate_hook(driver)
        clicked = _click_if_present(driver, [
            "button[type='submit']",
            "//button[contains(., 'Continue')]",
            "//button[contains(., '继续')]",
            "//button[contains(., 'Verify')]",
            "//button[contains(., '验证')]",
        ], timeout=8)
        if clicked:
            logger.info("[Codex][Browser] Đã gửi email OTP, Chờ uỷ quyền tiếp theo/Trang số điện thoại")
        else:
            logger.info("[Codex][Browser] Không tìm thấy nút gửi rõ ràng, Tiếp tục chờ trạng thái trang")

        outcome = _wait_after_email_otp_submit(driver, timeout=45)
        logger.info("[Codex][Browser] email OTP trạng thái sau khi gửi: %s", outcome)
        if _is_mfa_challenge_page(driver):
            _fill_mfa_challenge_if_present(driver, email, timeout=15)
            return
        if outcome == "accepted":
            return
        if str(outcome).startswith("deactivated:"):
            error_code = str(outcome).split(":", 1)[1] or "account_deactivated"
            raise AccountUnusableError(f"Tài khoản đã chết ({error_code}）", error_code=error_code)

        if otp_attempt >= max_otp_attempts:
            raise RuntimeError("Codex Mã OTP email sai liên tiếp/Hết hạn, Đã đạt số lần thử lại tối đa")

        logger.warning(
            "[Codex][Browser] mã OTP email sai/hết hạn hoặc trang chưa chuyển hướng, chuẩn bị gửi lại và lấy lại mã OTP mới nhất (%s/%s)",
            otp_attempt + 1,
            max_otp_attempts,
        )
        _restart_email_otp_flow("Mã OTP sai/hết hạn hoặc trang chưa chuyển hướng, tránh bấm resend dẫn đến 500")



def _wait_for_fresh_email_otp(otp_provider, email: str, after_ts: float, used_codes: set[str] | None = None, timeout: int = 90) -> str:
    """获取一个未提交过的邮箱 OTP。

    通用 API 邮箱的取码接口有时会先返回缓存旧码；验证码错误后重发时，
    这里会拒绝复用已失败的 code，持续轮询直到出现新 code 或超时。
    """
    used_codes = {str(x) for x in (used_codes or set()) if x}
    end = time.time() + timeout
    last_code = ""
    while True:
        code = str(otp_provider(email, after_ts=after_ts) or "").strip()
        if code and code not in used_codes:
            return code
        last_code = code or last_code
        remaining = int(end - time.time())
        if remaining <= 0:
            raise RuntimeError(f"Chờ mã OTP email mới quá giờ, API lấy mã vẫn trả mã OTP đã thất bại: {last_code or '-'}")
        logger.warning(
            "[Codex][Browser] API lấy mã vẫn trả về mã cũ đã gửi OTP=%s, tiếp tục chờ mã OTP mới nhất (còn lại %ss)",
            last_code or "-",
            remaining,
        )
        time.sleep(min(5, max(1, remaining)))


def _install_email_otp_validate_hook(driver) -> None:
    """
    Hook fetch/XHR trong trang để bắt body phản hồi API email-otp/validate.

    Trình duyệt fingerprint không lấy trực tiếp requests.Response như chế độ thuần protocol, nên trước khi gửi OTP email
    inject hook này, sau đó chỉ đọc JSON error.code của API, không dựa chữ trên trang để phán hỏng số.
    """
    script = r"""
    (() => {
      window.__codexEmailOtpValidateResponses = [];
      if (window.__codexEmailOtpValidateHooked) return true;
      window.__codexEmailOtpValidateHooked = true;
      const hit = (url) => String(url || '').includes('/api/accounts/email-otp/validate');
      const save = (url, status, body) => {
        try {
          if (!hit(url)) return;
          window.__codexEmailOtpValidateResponses.push({
            url: String(url || ''),
            status: Number(status || 0),
            body: String(body || '').slice(0, 2000),
            ts: Date.now(),
          });
        } catch (e) {}
      };
      const origFetch = window.fetch;
      if (origFetch) {
        window.fetch = async function(input, init) {
          const resp = await origFetch.apply(this, arguments);
          try {
            const url = (typeof input === 'string') ? input : (input && input.url);
            if (hit(url)) {
              resp.clone().text().then(t => save(url, resp.status, t)).catch(() => {});
            }
          } catch (e) {}
          return resp;
        };
      }
      const origOpen = XMLHttpRequest.prototype.open;
      const origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(method, url) {
        this.__codexOtpValidateUrl = url;
        return origOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function() {
        try {
          this.addEventListener('loadend', function() {
            try {
              if (hit(this.__codexOtpValidateUrl)) save(this.__codexOtpValidateUrl, this.status, this.responseText);
            } catch (e) {}
          });
        } catch (e) {}
        return origSend.apply(this, arguments);
      };
      return true;
    })();
    """
    try:
        driver.execute_script(script)
    except Exception as exc:
        logger.debug("[Codex][Browser] Inject email-otp/validate Phản hồi hook Thất bại: %s", exc)


def _read_email_otp_validate_dead_code(driver) -> str:
    try:
        rows = driver.execute_script("return window.__codexEmailOtpValidateResponses || [];") or []
    except Exception:
        return ""
    if not isinstance(rows, list):
        return ""
    for row in reversed(rows):
        if not isinstance(row, dict):
            continue
        code = detect_account_unusable_response_body(str(row.get("body") or ""))
        if code:
            logger.warning(
                "[Codex][Browser] email-otp/validate Phản hồi nhận diện tài khoản đã chết: code=%s status=%s",
                code,
                row.get("status"),
            )
            return code
    return ""


# Nhận diện trang mã xác minh email tái sử dụng phiên bản mạnh của roxy_registration (nhận diện URL + thuộc tính ô nhập,
# và loại trừ rõ /log-in/password), không dùng bản suy yếu cục bộ, tránh sau khi nhấn mã xác minh một lần
# Trang đã render ô nhập OTP nhưng nhận diện thất bại vì URL không chứa email-verification.

def _wait_after_email_otp_submit(driver, timeout: int = 45) -> str:
    """
    提交邮箱 OTP 后等待页面离开 /email-verification。

    返回：
      - accepted：已离开邮箱验证码页 / 进入手机号页 / 进入 callback；
      - invalid：页面明确报错、输入框标红，或长时间停留验证码页。
    """
    end = time.time() + timeout
    last_url = ""
    last_log = 0.0
    while time.time() < end:
        try:
            dead_code = _read_email_otp_validate_dead_code(driver)
            if dead_code:
                return f"deactivated:{dead_code}"
            url = str(driver.current_url or "")
            if url != last_url:
                logger.info("[Codex][Browser] email OTP sau đó chờ chuyển trang: url=%s", url)
                last_url = url
            if _is_callback_url(url):
                return "accepted"
            if _has_strict_add_phone_form(driver) or _is_phone_code_page(driver):
                return "accepted"
            # Đã rời email-verification, giao cho luồng ủy quyền/số điện thoại/consent tiếp theo xử lý.
            if "email-verification" not in url.lower():
                return "accepted"

            state = _email_otp_page_state(driver)
            invalid = any(str(i.get("ariaInvalid") or "").lower() == "true" for i in (state.get("inputs") or []))
            errors = [str(x) for x in (state.get("errors") or []) if str(x).strip()]
            body_text = str(state.get("text") or "").lower()
            error_hit = any(x in body_text for x in (
                "invalid code", "incorrect code", "wrong code", "expired",
                "验证码错误", "验证码无效", "验证码已过期", "コードが正しく", "無効", "期限",
            ))
            if invalid or errors or error_hit:
                logger.warning(
                    "[Codex][Browser] email OTP sau khi gửi phát hiện lỗi/vẫn cần mã OTP: errors=%s invalid=%s url=%s",
                    errors[:3],
                    invalid,
                    url,
                )
                return "invalid"

            if time.time() - last_log > 6:
                logger.info("[Codex][Browser] email OTP sau đó vẫn ở email-verification, tiếp tục chờ trang tự động chuyển")
                last_log = time.time()
        except Exception:
            pass
        time.sleep(0.5)
    logger.warning("[Codex][Browser] email OTP sau đó chờ chuyển hướng timeout, Hiện tại url=%s, coi mã OTP không hợp lệ/xử lý hết hạn", getattr(driver, "current_url", ""))
    return "invalid"


def _phone_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const radios = [...document.querySelectorAll('input[type=radio]')].filter(visible).map(el => ({
          name: el.name || '', value: el.value || '', checked: !!el.checked, id: el.id || ''
        }));
        const inputs = [...document.querySelectorAll('input,select,textarea')].filter(visible).map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '',
          id: el.id || '', autocomplete: el.getAttribute('autocomplete') || '', placeholder: el.getAttribute('placeholder') || '',
          ariaInvalid: el.getAttribute('aria-invalid') || '', value: el.value || ''
        }));
        const forms = [...document.querySelectorAll('form')].map(f => ({action: f.getAttribute('action') || ''}));
        const bodyText = (document.body?.innerText || '').slice(0, 1200);
        return {url: location.href, radios, inputs, forms, bodyText};
        """) or {}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "url": getattr(driver, 'current_url', '')}


def _select_sms_channel_or_raise(driver) -> None:
    state = _phone_page_state(driver)
    radios = state.get('radios') or []
    # Nếu có WhatsApp và không có tùy chọn SMS/text, nền tảng nhận mã hiện tại không đọc được WhatsApp, đổi số ngay.
    has_whatsapp = any('whatsapp' in str(r.get('value','')).lower().replace(' ', '') for r in radios)
    has_sms = any(str(r.get('value','')).lower() in ('sms', 'text', 'text_message', 'text-message') for r in radios)
    if has_whatsapp and not has_sms:
        raise RuntimeError(f"whatsapp_channel: trang chỉ cung cấp WhatsApp kênh state={state}")
    # Chọn radio SMS/text. Khi không có radio có thể mặc định SMS.
    selected = driver.execute_script(r"""
    const radios = [...document.querySelectorAll('input[type=radio]')];
    const sms = radios.find(el => /^(sms|text|text_message|text-message)$/i.test(el.value || ''));
    if (!sms) return false;
    sms.click();
    sms.dispatchEvent(new Event('input', {bubbles:true}));
    sms.dispatchEvent(new Event('change', {bubbles:true}));
    return true;
    """)
    if selected:
        logger.info("[Codex][Browser] đã chọn SMS kênh SMS")


def _is_phone_code_state(state: dict) -> bool:
    url = str(state.get('url') or '').lower()
    if 'email-verification' in url:
        # Trang OTP email cũng có thể xuất hiện autocomplete=one-time-code, không được nhầm thành trang mã xác minh điện thoại.
        return False
    if 'phone-verification' in url:
        return True
    forms = state.get('forms') or []
    form_actions = ' '.join(str(f.get('action') or '') for f in forms).lower()
    if 'phone-verification' in form_actions:
        return True
    inputs = state.get('inputs') or []
    attrs = ' '.join(' '.join(str(i.get(k) or '') for k in ('type','name','id','autocomplete','placeholder')) for i in inputs).lower()
    body = str(state.get('bodyText') or '').lower()
    has_code_input = 'one-time-code' in attrs or 'otp' in attrs or 'code' in attrs
    phone_hint = (
        'phone' in url or 'phone' in form_actions
        or 'check your phone' in body
        or 'verification code we just sent' in body
        or 'enter the verification code' in body and ('text message' in body or 'phone' in body)
        or 'resend text message' in body
        or 'sent to +' in body
    )
    return bool(phone_hint and has_code_input)


def _is_phone_code_page(driver) -> bool:
    return _is_phone_code_state(_phone_page_state(driver))


def _is_add_phone_page(driver) -> bool:
    state = _phone_page_state(driver)
    url = str(state.get('url') or '').lower()
    inputs = state.get('inputs') or []
    attrs = ' '.join(' '.join(str(i.get(k) or '') for k in ('type','name','id','autocomplete')) for i in inputs).lower()
    return 'add-phone' in url or 'type tel' in attrs or 'phone' in attrs or 'tel' in attrs


_PHONE_INPUT_SELECTORS = [
    "input[type='tel']",
    "input[name='phone']",
    "input[name='phone_number']",
    "input[autocomplete='tel']",
    "input[id*='phone']",
    "input[placeholder*='Phone']",
    "input[placeholder*='phone']",
]


def _has_strict_add_phone_form(driver) -> bool:
    try:
        return bool(driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const form = document.querySelector('form[action*="/add-phone" i]')
          || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
        if (!form) return false;
        return !![...form.querySelectorAll('input[type="tel"], input[name="__reservedForPhoneNumberInput_tel"], input[autocomplete="tel"], input[name="phone"], input[name="phone_number"]')].find(visible);
        """))
    except Exception:
        return False


def _auth_origin(driver) -> str:
    try:
        parsed = urlparse(str(driver.current_url or ""))
        if parsed.scheme and parsed.netloc and parsed.hostname and parsed.hostname.endswith("openai.com"):
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass
    return "https://auth.openai.com"


def _ensure_add_phone_input(driver, *, reason: str = ""):
    """Đảm bảo trang hiện tại quay lại add-phone và trả về ô nhập số điện thoại.

    Khi đổi số, nếu vẫn đang ở trang phone-verification/OTP, phải quay lại trang số điện thoại trước,
    rồi ghi lại số mới vào trang và gửi lại.
    """
    if _has_strict_add_phone_form(driver):
        return _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=2)

    current = str(getattr(driver, "current_url", "") or "")
    if "email-verification" in current.lower():
        logger.info("[Codex][Browser] hiện vẫn ở email-verification, chờ luồng uỷ quyền tự chuyển trước, tránh invalid_auth_step")
        _wait_after_email_otp_submit(driver, timeout=45)
        if _has_strict_add_phone_form(driver):
            return _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=2)
        current = str(getattr(driver, "current_url", "") or "")

    target = _auth_origin(driver).rstrip("/") + "/add-phone"
    logger.info(
        "[Codex][Browser] hiện không ở trang nhập SĐT, chuẩn bị mở lại add-phone sau đó đổi số: reason=%s url=%s target=%s",
        reason or "retry", current, target,
    )
    try:
        driver.get(target)
        human_delay("navigate")
        return _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=10)
    except Exception as first_exc:
        # Một số quy trình không cho mở trực tiếp /add-phone, thử trình duyệt quay lại trang trước.
        logger.info("[Codex][Browser] Mở thẳng add-phone Chưa lấy được ô nhập, Thử history back: %s", str(first_exc)[:160])
        try:
            driver.back()
            human_delay("navigate")
            return _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=8)
        except Exception as back_exc:
            raise RuntimeError(
                f"Không thể quay lại trang nhập số điện thoại để đổi số lại: direct={type(first_exc).__name__}: {first_exc}; "
                f"back={type(back_exc).__name__}: {back_exc}; state={_phone_page_state(driver)}"
            )


def _set_phone_value(driver, phone: str, *, timeout: int = 10) -> dict:
    """Điền form add-phone theo logic bước 9 của FlowPilot.

    Điểm chính:
    - Mọi phần tử scoped vào form[action*="/add-phone"];
    - Ô nhập tel hiển thị ghi “số trang mong đợi hiển thị”;
    - Nếu trang có input ẩn [name="phoneNumber"], đồng bộ ghi số E.164 đầy đủ;
    - Kích hoạt input/change và blur để React/React-Aria hoàn tất kiểm tra.
    """
    if not _has_strict_add_phone_form(driver):
        raise RuntimeError(f"hiện không phải add-phone trang nhập SĐT, không điền được SĐT: state={_phone_page_state(driver)}")
    result = driver.execute_script(r"""
    const rawPhone = String(arguments[0] || '').trim();
    const e164 = rawPhone.startsWith('+') ? rawPhone : ('+' + rawPhone.replace(/\D+/g, ''));
    const digits = e164.replace(/\D+/g, '');
    const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
    const form = document.querySelector('form[action*="/add-phone" i]')
      || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
    if (!form) {
      return {ok:false, error:'missing_add_phone_form', url: location.href};
    }
    const phoneInput = [...form.querySelectorAll('input[type="tel"], input[name="__reservedForPhoneNumberInput_tel"], input[autocomplete="tel"], input[name="phone"], input[name="phone_number"]')]
      .find(visible);
    if (!phoneInput) {
      return {ok:false, error:'missing_phone_input', url: location.href};
    }

    const hiddenPhoneNumberInput = form.querySelector('input[name="phoneNumber"]');
    const select = form.querySelector('select');
    let dialCode = '';
    let selectedText = '';
    let selectedChanged = false;
    const optionDialCode = (opt) => {
      const text = String(opt?.textContent || opt?.label || opt?.value || '').replace(/\s+/g, ' ').trim();
      const m = text.match(/\+(\d{1,4})\b/);
      return m ? m[1] : '';
    };
    if (select) {
      // 参考 FlowPilot ensureCountrySelected：按号码前缀选择对应国家/区号，避免默认国家与号码不一致。
      const options = [...select.options];
      const matched = options
        .map(opt => ({opt, code: optionDialCode(opt)}))
        .filter(x => x.code && digits.startsWith(x.code))
        .sort((a, b) => b.code.length - a.code.length)[0];
      if (matched && select.value !== matched.opt.value) {
        select.value = matched.opt.value;
        select.dispatchEvent(new Event('input', {bubbles:true}));
        select.dispatchEvent(new Event('change', {bubbles:true}));
        selectedChanged = true;
      }
      if (select.selectedIndex >= 0 && select.options[select.selectedIndex]) {
        const opt = select.options[select.selectedIndex];
        selectedText = String(opt.textContent || opt.label || opt.value || '').replace(/\s+/g, ' ').trim();
        dialCode = optionDialCode(opt);
      }
    }

    // FlowPilot：可见框一般填 national number；隐藏 phoneNumber 填完整 E.164。
    // 若无法判断页面区号，则可见框填完整 +E164，避免丢国家码。
    let visibleValue = e164;
    if (dialCode && digits.startsWith(dialCode) && digits.length > dialCode.length + 3) {
      visibleValue = digits.slice(dialCode.length);
      if (!visibleValue) visibleValue = e164;
    }

    const setNativeValue = (el, value) => {
      const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      el.focus();
      if (setter) setter.call(el, ''); else el.value = '';
      el.dispatchEvent(new Event('input', {bubbles:true}));
      el.dispatchEvent(new Event('change', {bubbles:true}));
      if (setter) setter.call(el, value); else el.value = value;
      el.dispatchEvent(new Event('input', {bubbles:true}));
      el.dispatchEvent(new Event('change', {bubbles:true}));
    };

    phoneInput.scrollIntoView({block:'center'});
    setNativeValue(phoneInput, visibleValue);
    if (hiddenPhoneNumberInput) {
      hiddenPhoneNumberInput.value = e164;
      hiddenPhoneNumberInput.dispatchEvent(new Event('input', {bubbles:true}));
      hiddenPhoneNumberInput.dispatchEvent(new Event('change', {bubbles:true}));
    }
    phoneInput.blur();
    document.body?.focus?.();
    return {
      ok: true,
      e164,
      visibleValue,
      actualVisible: phoneInput.value || '',
      hiddenValue: hiddenPhoneNumberInput ? (hiddenPhoneNumberInput.value || '') : '',
      dialCode,
      selectedText,
      selectedChanged,
      inputName: phoneInput.getAttribute('name') || '',
      inputId: phoneInput.id || '',
      url: location.href,
    };
    """, phone)
    if not result or not result.get("ok"):
        raise RuntimeError(f"ghi SĐT thất bại result={result} state={_phone_page_state(driver)}")
    actual = str(result.get("actualVisible") or "").strip()
    visible_value = str(result.get("visibleValue") or "").strip()
    hidden_value = str(result.get("hiddenValue") or "").strip()
    e164 = str(result.get("e164") or "").strip()
    # Ô điện thoại OpenAI/React-Aria sẽ tự định dạng, ví dụ +84925154291 -> +84 925 154 291.
    # Không thể so sánh chính xác theo chuỗi giao diện, chỉ so sánh giá trị số sau khi chuẩn hóa.
    actual_digits = ''.join(ch for ch in actual if ch.isdigit())
    visible_digits = ''.join(ch for ch in visible_value if ch.isdigit())
    e164_digits = ''.join(ch for ch in e164 if ch.isdigit())
    hidden_digits = ''.join(ch for ch in hidden_value if ch.isdigit())
    expected_visible_ok = bool(actual_digits) and (actual_digits == visible_digits or actual_digits == e164_digits)
    if not expected_visible_ok:
        raise RuntimeError(f"kiểm tra ô nhập SĐT hiển thị thất bại expected_digits={visible_digits or e164_digits} actual={actual} result={result} state={_phone_page_state(driver)}")
    if hidden_value and hidden_digits != e164_digits:
        raise RuntimeError(f"kiểm tra trường ẩn SĐT thất bại expected={e164} actual={hidden_value} result={result} state={_phone_page_state(driver)}")
    return result


def _blur_active_input_and_wait(driver, *, label: str = "nhập xong") -> None:
    """Sau khi nhập số điện thoại thì bỏ focus, và dành thời gian xử lý cho kiểm tra/định dạng phía frontend."""
    try:
        driver.execute_script(r"""
        const active = document.activeElement;
        if (active && typeof active.blur === 'function') active.blur();
        document.body?.focus?.();
        document.dispatchEvent(new Event('change', {bubbles:true}));
        """)
    except Exception:
        pass
    seconds = random.uniform(1.8, 3.2)
    logger.info("[Codex][Browser] %s, đã rời focus, chờ trang xử lý %.1f giây", label, seconds)
    time.sleep(seconds)


def _verify_add_phone_value_before_submit(driver, expected_e164: str) -> dict:
    result = driver.execute_script(r"""
    const expected = String(arguments[0] || '').trim();
    const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
    const form = document.querySelector('form[action*="/add-phone" i]')
      || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
    if (!form) return {ok:false, error:'missing_add_phone_form', url: location.href};
    const input = [...form.querySelectorAll('input[type="tel"], input[name="__reservedForPhoneNumberInput_tel"], input[autocomplete="tel"], input[name="phone"], input[name="phone_number"]')].find(visible);
    const hidden = form.querySelector('input[name="phoneNumber"]');
    const visibleValue = String(input?.value || '').trim();
    const hiddenValue = String(hidden?.value || '').trim();
    const digits = value => String(value || '').replace(/\D+/g, '');
    const visibleDigits = digits(visibleValue);
    const hiddenDigits = digits(hiddenValue);
    const expectedDigits = digits(expected);
    // 输入框可能被自动格式化，按数字比较；隐藏字段如果存在必须等于完整 E.164。
    const ok = !!visibleDigits && visibleDigits === expectedDigits && (!hidden || hiddenDigits === expectedDigits);
    return {ok, visibleValue, hiddenValue, expected, visibleDigits, hiddenDigits, expectedDigits, url: location.href};
    """, expected_e164)
    if not result or not result.get("ok"):
        raise RuntimeError(f"kiểm tra SĐT trước khi gửi thất bại result={result} state={_phone_page_state(driver)}")
    return result


def _wait_page_settle_after_submit() -> None:
    """Sau khi nhấp gửi, đợi trang xử lý trước, rồi kiểm tra trạng thái gửi."""
    seconds = random.uniform(2.0, 4.0)
    logger.info("[Codex][Browser] đã nhấp gửi, chờ trang gửi/xử lý chuyển hướng %.1f giây sau kiểm tra trạng thái", seconds)
    time.sleep(seconds)


def _refresh_add_phone_for_retry(driver, *, reason: str = "") -> None:
    """Làm mới trang số điện thoại trước khi gửi thất bại/đổi số, tránh trạng thái lỗi cũ và số cũ còn sót."""
    try:
        logger.info("[Codex][Browser] gửi thất bại/chuẩn bị đổi SĐT, tải lại trang SĐT: %s", reason or "retry")
        driver.refresh()
        human_delay("navigate")
        try:
            _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=8)
            return
        except Exception:
            pass
        # Nếu sau khi làm mới vẫn không ở trang nhập, buộc quay về add-phone.
        target = _auth_origin(driver).rstrip("/") + "/add-phone"
        logger.info("[Codex][Browser] sau khi tải lại không thấy ô nhập SĐT, mở lại: %s", target)
        driver.get(target)
        human_delay("navigate")
        _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=8)
    except Exception as exc:
        logger.info("[Codex][Browser] Làm mới trang số điện thoại thất bại, Vòng sau sẽ thử quay lại lần nữa add-phone: %s", str(exc)[:180])


def _click_add_phone_continue_button(driver, *, timeout: int = 10) -> dict:
    """Nhấn nút Continue/続行 trong form add-phone.

    Tham khảo getAddPhoneSubmitButton + simulateClick của FlowPilot: ưu tiên tìm
    submit đang enabled trong form add-phone, nếu nhấn thất bại thì dùng form.requestSubmit(button) làm phương án dự phòng.
    """
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            btn = driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
            const enabled = el => {
              if (!el) return false;
              if (el.disabled) return false;
              if (String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true') return false;
              return true;
            };
            const form = document.querySelector('form[action*="/add-phone" i]')
              || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
            if (!form) return null;
            const buttons = [...form.querySelectorAll('button[type="submit"], input[type="submit"]')];
            return buttons.find(b => visible(b) && enabled(b) && (b.getAttribute('data-dd-action-name') || '').toLowerCase() === 'continue')
              || buttons.find(b => visible(b) && enabled(b))
              || buttons.find(b => visible(b))
              || null;
            """)
            if btn:
                driver.execute_script("arguments[0].scrollIntoView({block:'center'});", btn)
                time.sleep(random.uniform(0.3, 0.8))
                try:
                    text = str(getattr(btn, 'text', '') or btn.get_attribute('value') or btn.get_attribute('data-dd-action-name') or '').strip()
                except Exception:
                    text = ''
                try:
                    btn.click()
                    _wait_page_settle_after_submit()
                    return {"ok": True, "method": "click", "text": text}
                except Exception as click_exc:
                    last = click_exc
                    submitted = driver.execute_script(r"""
                    const btn = arguments[0];
                    const form = btn?.form || btn?.closest?.('form');
                    if (form && typeof form.requestSubmit === 'function') {
                      form.requestSubmit(btn);
                      return true;
                    }
                    if (btn && typeof btn.click === 'function') {
                      btn.click();
                      return true;
                    }
                    return false;
                    """, btn)
                    if submitted:
                        _wait_page_settle_after_submit()
                        return {"ok": True, "method": "requestSubmit", "text": text, "click_error": str(click_exc)[:160]}
        except Exception as exc:
            last = exc
        time.sleep(0.25)
    raise RuntimeError(f"submit_missing: add-phone Continue/tiếp tục submit button not found last={last} state={_phone_page_state(driver)}")


def _force_submit_add_phone_form(driver) -> dict:
    """Khi nhấn nút trên trang add-phone không có hiệu lực, gọi requestSubmit trực tiếp cho form hiện tại."""
    try:
        return driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const form = document.querySelector('form[action*="/add-phone" i]')
          || [...document.querySelectorAll('form')].find(f => /add-phone/i.test(f.getAttribute('action') || ''));
        if (!form) return {ok:false, reason:'missing_form', url: location.href};
        const btn = [...form.querySelectorAll('button[type="submit"],input[type="submit"]')]
          .find(el => visible(el) && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true')
          || form.querySelector('button[type="submit"],input[type="submit"]');
        if (btn) btn.scrollIntoView({block:'center'});
        if (typeof form.requestSubmit === 'function') form.requestSubmit(btn || undefined);
        else if (btn && typeof btn.click === 'function') btn.click();
        else form.submit();
        return {ok:true, method: btn ? 'requestSubmit(button)' : 'requestSubmit(form)', url: location.href};
        """) or {}
    except Exception as exc:
        return {ok:false, reason:f'{type(exc).__name__}: {exc}', url:getattr(driver, 'current_url', '')}


def _wait_after_phone_send(driver, timeout: int = 12) -> str:
    end = time.time() + timeout
    last = {}
    force_submitted = False
    while time.time() < end:
        time.sleep(1)
        last = _phone_page_state(driver)
        # Phải ưu tiên xác định trang mã xác minh: văn bản trang có thể chứa các từ send/limit/check, không được
        # “Check your phone / Enter the verification code...” bị nhận nhầm thành gửi thất bại.
        if _is_phone_code_state(last):
            return 'code_page'
        body = str(last.get('bodyText') or '')
        reason = _classify_phone_page_failure(last)
        if reason:
            raise RuntimeError(f"{reason}: {body[:240]}")
        # Vẫn ở add-phone và field có aria-invalid thì coi số bị từ chối.
        if _is_add_phone_page(driver):
            invalid = any(str(i.get('ariaInvalid') or '').lower() == 'true' for i in (last.get('inputs') or []))
            if invalid:
                raise RuntimeError(f"invalid_phone: add-phone input aria-invalid state={last}")
            # Trong ngữ cảnh Cloak/React-Aria, btn.click có thể chỉ focus mà không kích hoạt submit form; bổ sung một lần requestSubmit.
            if not force_submitted and time.time() > end - timeout + 3:
                info = _force_submit_add_phone_form(driver)
                logger.info("[Codex][Browser] add-phone sau khi bấm vẫn ở trang này, thực thi bù form.requestSubmit: %s", info)
                force_submitted = True
                time.sleep(2)
    if _is_phone_code_state(last) or _is_phone_code_page(driver):
        return 'code_page'
    if _is_add_phone_page(driver):
        raise RuntimeError(f"send_not_accepted: sau khi gửi vẫn dừng ở add-phone state={last}")
    return 'unknown'


def _wait_after_phone_otp_submit(driver, timeout: int = 20) -> str:
    """手机验证码提交后等待结果。

    成功时通常会跳出 phone-verification，进入 consent/workspace/callback；不能在提交后
    3 秒立刻读取旧页面文案并按 send_limited 判失败。只有明确仍在手机号流程且出现错误时
    才返回失败。
    """
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        time.sleep(1)
        current = str(getattr(driver, "current_url", "") or "")
        if _is_callback_url(current):
            return "callback"
        last = _phone_page_state(driver)
        # Đã rời trang mã xác minh điện thoại/thêm số điện thoại, nghĩa là mã đã được chấp nhận, phần sau giao cho luồng consent/callback.
        if not _is_phone_code_state(last) and not _is_add_phone_page(driver):
            return "left_phone_flow"
        # Khi vẫn ở trang mã xác minh, chỉ coi lỗi rõ ràng là thất bại; trang Check your phone thông thường tiếp tục chờ.
        if _is_phone_code_state(last):
            inputs = last.get('inputs') or []
            invalid = any(str(i.get('ariaInvalid') or '').lower() == 'true' for i in inputs)
            body = str(last.get('bodyText') or '').lower()
            if invalid or any(k in body for k in (
                'invalid code', 'incorrect code', 'wrong code', 'expired code',
                'code is invalid', 'code was invalid', '验证码无效', '验证码错误', '验证码已过期',
                '認証コードが無効', 'コードが正しく',
            )):
                raise RuntimeError(f"invalid_phone_code: {(last.get('bodyText') or '')[:240]}")
            continue
        reason = _classify_phone_page_failure(last)
        if reason:
            raise RuntimeError(f"{reason}: {(last.get('bodyText') or '')[:240]}")
    # Sau timeout xem lại một lần: nếu đã rời luồng số điện thoại thì coi như pass; nếu vẫn ở trang mã nhưng không có lỗi rõ, giao cho luồng sau tiếp tục thử.
    current = str(getattr(driver, "current_url", "") or "")
    if _is_callback_url(current):
        return "callback"
    last = _phone_page_state(driver)
    if not _is_phone_code_state(last) and not _is_add_phone_page(driver):
        return "left_phone_flow"
    if _is_phone_code_state(last):
        return "still_code_page"
    return "unknown"


def _classify_phone_page_failure(state: dict) -> str:
    if _is_phone_code_state(state):
        return ''
    # WhatsApp dùng DOM radio value để phán đoán; các lỗi gửi khác dùng text lỗi server/trang làm dự phòng.
    radios = state.get('radios') or []
    if any('whatsapp' in str(r.get('value','')).lower().replace(' ', '') and r.get('checked') for r in radios):
        return 'whatsapp_channel'
    text = str(state.get('bodyText') or '').lower()
    if 'invalid_auth_step' in text or 'invalid auth step' in text:
        return 'invalid_auth_step'
    if 'whatsapp' in text or 'whats app' in text:
        return 'whatsapp_channel'
    if any(k in text for k in ('invalid phone', 'not a valid phone', 'phone number is not valid', '号码无效', '手机号无效')):
        return 'invalid_phone'
    if any(k in text for k in (
        'cannot send', 'could not send', 'unable to send', 'failed to send', 'send failed',
        '发送失败', '发送失败了', '无法发送', '不能发送', '无法向',
        '送信できません', '送信に失敗', '送信できなかった',
    )):
        return 'delivery_refused'
    if any(k in text for k in ('too many', 'rate limit', 'throttle', '频繁', '限流')):
        return 'send_limited'
    return ''

def _sleep_before_phone_retry(attempt: int, max_retries: int, *, prefix: str = "[Codex][Browser]") -> None:
    """Chờ ngẫu nhiên trước khi đổi số, ít nhất 3 giây, tránh gửi số liên tục quá nhanh."""
    if attempt >= max_retries:
        return
    seconds = random.uniform(3.0, 8.0)
    logger.info("%s chờ ngẫu nhiên trước khi đổi số %.1f giây", prefix, seconds)
    time.sleep(seconds)


def _do_phone_verification_if_present(driver) -> None:
    """Nếu trang yêu cầu xác minh số điện thoại thì tự động hoàn thành bằng sms_provider hiện tại."""
    provider = str(getattr(sms_provider._cfg, "SMS_PROVIDER", "") or "").strip().lower() if hasattr(sms_provider, "_cfg") else ""
    http = sms_provider._http()
    max_retries = int(getattr(sms_provider._cfg, "SMS_MAX_RETRIES", 10) or 10) if hasattr(sms_provider, "_cfg") else 10
    try:
        # Nếu trang không có ô nhập số điện thoại, trả về trực tiếp.
        try:
            end_detect = time.time() + 8
            while time.time() < end_detect and not _has_strict_add_phone_form(driver):
                # Nếu đã ở trang mã xác minh, nghĩa là bước phone đã submit trước; tiếp tục xử lý trang mã, không được skip.
                if _is_phone_code_page(driver):
                    break
                time.sleep(0.5)
            if not (_has_strict_add_phone_form(driver) or _is_phone_code_page(driver)):
                raise RuntimeError("not_phone_flow")
        except Exception:
            logger.info("[Codex][Browser] chưa phát hiện trang xác minh số điện thoại, bỏ qua bước điện thoại")
            return

        last_err = None
        for attempt in range(1, max_retries + 1):
            activation_id = None
            try:
                activation_id, phone = sms_provider.acquire_number(http)
                logger.info("[Codex][Browser] lần thử xác minh điện thoại %s/%s, provider=%s, số=+%s", attempt, max_retries, provider, phone)
                logger.info("[Codex][Browser] chuẩn bị trang nhập số điện thoại, đặt lại số điện thoại mới")
                _ensure_add_phone_input(driver, reason=f"attempt-{attempt}")
                phone_fill = _set_phone_value(driver, f"+{phone}", timeout=10)
                logger.info(
                    "[Codex][Browser] đã đặt lại số điện thoại: e164=%s visible=%s hidden=%s dialCode=%s country=%s",
                    phone_fill.get("e164"), phone_fill.get("actualVisible"), phone_fill.get("hiddenValue") or "-",
                    phone_fill.get("dialCode") or "-", (str(phone_fill.get("selectedText") or "-") + (" [changed]" if phone_fill.get("selectedChanged") else "")),
                )
                _blur_active_input_and_wait(driver, label="Đã nhập xong số điện thoại")
                phone_verify = _verify_add_phone_value_before_submit(driver, str(phone_fill.get("e164") or f"+{phone}"))
                logger.info("[Codex][Browser] số điện thoại qua kiểm tra trước khi gửi: visible=%s hidden=%s", phone_verify.get("visibleValue"), phone_verify.get("hiddenValue") or "-")
                logger.info("[Codex][Browser] kiểm tra và chọn SMS kênh SMS")
                _select_sms_channel_or_raise(driver)
                _blur_active_input_and_wait(driver, label="Đã xác nhận xong kênh SMS")
                submit_info = _click_add_phone_continue_button(driver, timeout=10)
                logger.info("[Codex][Browser] đã bấm số điện thoại Continue/tiếp tục Nút: %s, chờ vào trang mã OTP SMS", submit_info)
                _wait_page_settle_after_submit()

                # Chờ trang vào phone-verification; nếu số không hợp lệ/không gửi được/kênh WhatsApp, đổi số ngay.
                _wait_after_phone_send(driver, timeout=15)
                logger.info("[Codex][Browser] đã vào trang mã OTP điện thoại")

                sms_provider.set_status(activation_id, 1, http=http)
                logger.info(
                    "[Codex][Browser] đã gửi SMS, bắt đầu polling mã OTP activation_id=%s wait=%ss interval=%ss",
                    activation_id, sms_provider._cfg.SMS_CODE_WAIT, sms_provider._cfg.SMS_POLL_INTERVAL
                )
                sms_code = sms_provider.wait_for_sms_code(activation_id, http)
                logger.info("[Codex][Browser] điện thoại OTP đã nhận: %s", sms_code)
                _type_otp(driver, sms_code)
                logger.info("[Codex][Browser] đã điền số điện thoại OTP")
                human_delay("otp_input")
                if not _click_if_present(driver, ["button[type='submit']", "input[type='submit']"], timeout=10):
                    raise RuntimeError(f"verify_submit_missing: phone verification submit not found state={_phone_page_state(driver)}")
                logger.info("[Codex][Browser] đã gửi số điện thoại OTP, chờ kết quả xác minh")
                otp_outcome = _wait_after_phone_otp_submit(driver, timeout=25)
                logger.info("[Codex][Browser] điện thoại OTP trạng thái sau khi gửi: %s", otp_outcome)
                sms_provider.complete(activation_id, http)
                return
            except Exception as exc:
                last_err = exc
                err_text = str(exc) or ""
                logger.warning("[Codex][Browser] Thử xác minh điện thoại thất bại, Đổi số: %s", err_text[:240])
                if activation_id:
                    try:
                        sms_provider.cancel(activation_id, http)
                    except Exception:
                        pass
                # Số dư không đủ / không có số khả dụng: thử lại bao nhiêu lần cũng không thành công, thất bại ngay để cắt lỗ,
                # Tránh chờ vô ích N vòng đổi số thử lại (mỗi vòng còn phải làm mới trang + chờ ngẫu nhiên).
                if any(k in err_text for k in (
                    "NO_BALANCE", "NO_NUMBERS", "BALANCE", "余额不足",
                    "暂无可用号码", "没有可用号码", "insufficient", "not enough balance",
                )):
                    raise RuntimeError(
                        f"Nền tảng nhận mã hết số dư hoặc không có số khả dụng, Đã dừng đổi số để cắt lỗ: {err_text[:180]}"
                    ) from exc
                if "invalid_auth_step" in str(exc):
                    raise RuntimeError(
                        "Luồng số điện thoại vào invalid_auth_step: trạng thái uỷ quyền chưa nhảy đúng từ email-verification hoặc đã hết hiệu lực; "
                        "đã dừng đổi số để tránh tiêu hao số"
                    ) from exc
                # Nếu đã rời trang liên quan số điện thoại/mã xác minh, coi như đã qua hoặc không còn cần;
                # Nếu vẫn còn ở phone-verification, thì vòng sau phải quay lại add-phone điền lại số mới rồi submit.
                try:
                    if _is_phone_code_page(driver):
                        logger.info("[Codex][Browser] Hiện vẫn ở trang mã OTP điện thoại, Vòng sau sẽ quay lại add-phone Đặt lại số mới")
                    else:
                        _find_any(driver, _PHONE_INPUT_SELECTORS, timeout=2)
                except Exception:
                    if _is_add_phone_page(driver) or _is_phone_code_page(driver):
                        logger.info("[Codex][Browser] Vẫn đang trong luồng số điện thoại, Tiếp tục đổi số thử lại")
                    else:
                        logger.info("[Codex][Browser] Trang nhập số điện thoại đã biến mất, tiếp tục quy trình sau")
                        return
                if attempt < max_retries:
                    _refresh_add_phone_for_retry(driver, reason=str(exc)[:120])
                _sleep_before_phone_retry(attempt, max_retries)
        raise RuntimeError(f"Roxy thử lại xác minh SĐT {max_retries} lần vẫn thất bại, Lỗi cuối: {last_err}")
    finally:
        try:
            http.close()
        except Exception:
            pass


def _finish_consent_workspace(driver) -> str:
    """Nhấp nút tiếp tục/cho phép trên trang Codex consent/workspace cho đến callback."""
    end = time.time() + int(_roxy_cfg.ROXY_CODEX_CALLBACK_TIMEOUT)
    while time.time() < end:
        callback = _extract_callback_url_from_any_window(driver)
        if callback:
            return callback
        current = str(driver.current_url or "")
        clicked = False
        for selectors in [
            ["//button[contains(., 'Allow')]", "//button[contains(., 'Authorize')]", "//button[contains(., 'Continue')]"],
            ["//button[contains(., 'Select')]", "//button[contains(., 'Use workspace')]", "//button[contains(., 'Confirm')]"],
            ["//button[contains(., '允许')]", "//button[contains(., '授权')]", "//button[contains(., '继续')]", "//button[contains(., '确认')]"],
            ["button[type='submit']"],
        ]:
            if _click_if_present(driver, selectors, timeout=2):
                clicked = True
                human_delay("form")
                break
        if not clicked:
            time.sleep(0.8)
    return _wait_for_callback(driver, timeout=5)




def clear_roxy_browser_auth_state(driver) -> None:
    """Xóa trạng thái đăng nhập và bộ nhớ đệm OpenAI/ChatGPT trong trình duyệt Roxy hiện tại, dùng để tái sử dụng cùng môi trường chạy Codex sau khi đăng ký."""
    origins = [
        "https://auth.openai.com",
        "https://chatgpt.com",
        "https://openai.com",
        "https://platform.openai.com",
    ]
    logger.info("[Codex][Browser] tái dùng cửa sổ đăng ký: bắt đầu dọn Cookie / localStorage / sessionStorage / cache")
    try:
        driver.execute_cdp_cmd("Network.enable", {})
    except Exception:
        pass
    try:
        driver.execute_cdp_cmd("Network.clearBrowserCookies", {})
        logger.info("[Codex][Browser] Đã dọn trình duyệt Cookie")
    except Exception as exc:
        logger.info("[Codex][Browser] Dọn Cookie Thất bại, Tiếp tục thử cache khác: %s", str(exc)[:160])
    try:
        driver.execute_cdp_cmd("Network.clearBrowserCache", {})
        logger.info("[Codex][Browser] Đã dọn trình duyệt Cache")
    except Exception as exc:
        logger.info("[Codex][Browser] Dọn Cache Thất bại, Tiếp tục: %s", str(exc)[:160])
    for origin in origins:
        try:
            driver.execute_cdp_cmd("Storage.clearDataForOrigin", {
                "origin": origin,
                "storageTypes": "all",
            })
            logger.info("[Codex][Browser] Đã dọn dữ liệu site: %s", origin)
        except Exception as exc:
            logger.debug("[Codex][Browser] xóa dữ liệu site thất bại %s: %s", origin, exc)
    try:
        driver.get("about:blank")
    except Exception:
        pass
    time.sleep(1.0)
    logger.info("[Codex][Browser] dọn xong session đăng nhập cửa sổ đăng ký, chuẩn bị bắt đầu Codex uỷ quyền")

def _run_roxy_codex_oauth_once(
    email: str,
    otp_provider=None,
    proxy: str | None = None,
    force: bool = False,
    existing_driver=None,
    existing_opened=None,
    reuse_existing_profile: bool = False,
    clear_existing_state: bool = True,
) -> dict:
    """Lối vào OAuth Codex của trình duyệt fingerprint.

    existing_driver/existing_opened dùng cho "chạy Codex ngay sau khi đăng ký thành công":
    tái sử dụng cửa sổ Roxy lúc đăng ký, không tạo môi trường mới, chỉ dọn trạng thái trình duyệt rồi bắt đầu ủy quyền.
    """
    from core import codex_oauth as proto

    if not force and not proto._cfg.ENABLE_CODEX_AUTO:
        return proto._codex_result(status="skipped", message="ENABLE_CODEX_AUTO=False")
    if not email:
        return proto._codex_result(status="skipped", message="email trống")
    if otp_provider is None:
        otp_provider = wait_for_otp

    client = None if reuse_existing_profile else RoxyBrowserClient()
    opened = existing_opened if reuse_existing_profile else client.open_profile()
    browser_kind_token = _CODEX_BROWSER_KIND.set(_detect_browser_kind(opened))
    driver = existing_driver if reuse_existing_profile else None
    owns_driver = not reuse_existing_profile
    try:
        auth_source = proto._codex_auth_url_source()
        code_verifier = None
        if auth_source == "cpa":
            cpa_auth = proto._request_cpa_authorize_url()
            state = cpa_auth["state"]
            auth_url = cpa_auth["auth_url"]
            logger.info("[Codex][Browser] Đang dùng CPA Địa chỉ uỷ quyền: %s", auth_url)
        elif auth_source == "sub2":
            sub2_auth = proto._request_sub2_authorize_url()
            state = sub2_auth["state"]
            auth_url = sub2_auth["auth_url"]
            logger.info("[Codex][Browser] Đang dùng sub2 Địa chỉ uỷ quyền: %s", auth_url)
        elif auth_source == "local":
            code_verifier, code_challenge = proto._generate_pkce()
            state = proto._generate_state()
            auth_url = proto._build_authorize_url(state, code_challenge, prompt="login")
            logger.info("[Codex][Browser] Hiện đang dùng local PKCE Địa chỉ uỷ quyền: %s", auth_url)
        else:
            raise RuntimeError(f"[Codex][Browser] Không hỗ trợ CODEX_AUTH_URL_SOURCE={auth_source!r}")

        if not driver:
            driver = _build_driver(opened)
            _center_browser_window(driver)
        driver.set_page_load_timeout(int(_roxy_cfg.ROXY_SELENIUM_TIMEOUT))
        logger.info("[Codex][Browser] Bắt đầu uỷ quyền: %s, profile=%s, reuse_existing_profile=%s", email, opened.profile_id, reuse_existing_profile)
        if reuse_existing_profile and clear_existing_state:
            clear_roxy_browser_auth_state(driver)

        _fill_email_and_otp(driver, email, otp_provider, auth_url)
        human_delay("api")
        logger.info("[Codex][Browser] Kiểm tra có cần xác minh số điện thoại không")
        _do_phone_verification_if_present(driver)
        logger.info("[Codex][Browser] Đã xử lý xong xác minh điện thoại/Không cần xử lý, Chờ xác nhận uỷ quyền và callback")
        callback_url = _finish_consent_workspace(driver)
        code = proto._extract_code(callback_url, state)
        logger.info("[Codex][Browser] Đã bắt được callback code: %s...", code[:24])

        if auth_source == "cpa":
            submit_payload = proto._submit_cpa_callback(callback_url)
            path = proto._save_cpa_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url,
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "CPA callback submitted"
            return proto._codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=f"{_codex_driver_name()}: {msg}",
            )

        if auth_source == "sub2":
            submit_payload = proto._submit_sub2_callback(
                callback_url,
                session_id=(sub2_auth or {}).get("session_id", ""),
                redirect_uri=(proto.parse_qs(proto.urlparse(auth_url or "").query).get("redirect_uri") or [""])[0],
            )
            path = proto._save_sub2_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url,
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "sub2 callback uploaded"
            return proto._codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=f"{_codex_driver_name()}: {msg}",
            )

        if not code_verifier:
            raise RuntimeError("[Codex][Browser] local Thiếu chế độ code_verifier")
        session = proto.BrowserSession(proxy=proxy, fingerprint_seed=f"account:{email.lower()}")
        token_resp = proto.exchange_codex_token(session, code, code_verifier)
        id_claims = proto._parse_id_token(token_resp.get("id_token", ""))
        effective_email = id_claims.get("email") or email
        storage = proto.build_codex_storage(token_resp, id_claims)
        path = proto.save_codex_credential(storage, effective_email, id_claims.get("plan_type", ""))
        return proto._codex_result(
            status="success",
            ok=True,
            email=effective_email,
            file_path=str(path),
            callback_url=callback_url,
            message=f"{_codex_driver_name()} plan={id_claims.get('plan_type') or 'unknown'}",
        )
    except AccountUnusableError as exc:
        logger.warning("[Codex][Browser] Tài khoản đã chết: %s, %s", email, exc.error_code)
        return proto._codex_result(
            status="deactivated",
            email=email,
            message=f"Tài khoản đã chết ({exc.error_code or 'account_deactivated'}）",
        )
    except Exception as exc:
        logger.warning("[Codex][Browser] Thất bại: %s, %s: %s", email, type(exc).__name__, str(exc)[:240])
        logger.debug("[Codex][Browser] Chi tiết thất bại", exc_info=True)
        return proto._codex_result(status="failed", email=email, message=f"{type(exc).__name__}: {str(exc)[:220]}")
    finally:
        # Khi tái dùng cửa sổ sau đăng ký, vòng đời driver/profile do flow đăng ký dọn thống nhất,
        # Ở đây không thể quit/delete, nếu không sẽ hủy sớm môi trường đăng ký.
        if owns_driver and driver and not bool(_roxy_cfg.ROXY_KEEP_BROWSER_OPEN):
            try:
                driver.quit()
            except Exception:
                pass
        if owns_driver and client and not bool(_roxy_cfg.ROXY_KEEP_BROWSER_OPEN):
            client.cleanup_profile(opened)
        try:
            _CODEX_BROWSER_KIND.reset(browser_kind_token)
        except Exception:
            pass


def run_roxy_codex_oauth(
    email: str,
    otp_provider=None,
    proxy: str | None = None,
    force: bool = False,
    existing_driver=None,
    existing_opened=None,
    reuse_existing_profile: bool = False,
    clear_existing_state: bool = True,
) -> dict:
    """Điểm vào OAuth Codex trên trình duyệt fingerprint; khi CPA callback 409 timeout thì mở lại một vòng ủy quyền."""
    from core import codex_oauth as proto

    max_rounds = 2
    last_result = None
    for round_no in range(1, max_rounds + 1):
        if round_no > 1:
            logger.warning(
                "[Codex][Browser] CPA callback trả về Timeout waiting for OAuth callback, bắt đầu lại lần thứ %s/%s vòng Codex uỷ quyền: %s",
                round_no, max_rounds, email,
            )
        result = _run_roxy_codex_oauth_once(
            email=email,
            otp_provider=otp_provider,
            proxy=proxy,
            force=force,
            existing_driver=existing_driver,
            existing_opened=existing_opened,
            reuse_existing_profile=reuse_existing_profile,
            clear_existing_state=clear_existing_state,
        )
        last_result = result
        if result.get("ok"):
            return result
        msg = result.get("message") or result.get("error") or ""
        if not proto._is_cpa_callback_reauth_error(msg):
            return result
    if last_result:
        last_result = dict(last_result)
        last_result["message"] = f"CPA callback quá thời gian, đã uỷ quyền lại {max_rounds} vòng vẫn thất bại: {last_result.get('message') or ''}"
        return last_result
    return proto._codex_result(status="failed", email=email, message="CPA callback quá thời gian, Uỷ quyền lại thất bại")
