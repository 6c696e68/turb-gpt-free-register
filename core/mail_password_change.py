# -*- coding: utf-8 -*-
"""
Module đổi mật khẩu email mail.com.

Trước phụ thuộc module ngoài mail_password_change (từ dự án chatgpt_mail_register_py),
nay tự viết và tích hợp vào dự án này, tránh phụ thuộc ngoài.

Nguồn: change_mailcom_password() trong gpt-mail/register_mailcom.py.
Luồng:
    1. Đăng nhập mail.com lightmailer bằng mật khẩu hiện tại (tạo session cookies)
    2. Vào trang cài đặt bảo mật account.mail.com (chưa đăng nhập thì đăng nhập bằng mật khẩu hiện tại)
    3. Rút srttkn token + action của form
    4. POST form đổi mật khẩu (currentPassword + newPassword + retypeNewPassword)
    5. Đổi mật khẩu thành công thì ghi lại DB (email_pool.password) + cache bộ nhớ

Trước đăng ký gọi maybe_change_mailcom_password_before_register(email) là đủ:
    - Kiểm tra nguồn email có phải mailcom
    - Đọc công tắc config.EMAIL_SOURCE / MAILCOM_CHANGE_PASSWORD_BEFORE_REGISTER
    - Đổi mật khẩu, ghi DB và cache, trả mật khẩu mới
"""

from __future__ import annotations

import logging
import re
import secrets
import string
from dataclasses import dataclass
from html import unescape
from urllib.parse import quote, urljoin

from bs4 import BeautifulSoup

from core.mailcom_client import (
    MailComError,
    MailComLightClient,
    _CONTEXT_CACHE,
    _http_session,
    _mailcom_proxy,
)

logger = logging.getLogger(__name__)

MAILCOM_ACCOUNT_BASE = "https://account.mail.com"
MAILCOM_ACCOUNT_PASSWORD_PATH = "/ciss/security/edit/passwordChange"
MAILCOM_DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9"

PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*_+="
PASSWORD_SYMBOLS = "!@#$%^&*_+="


@dataclass(frozen=True)
class Account:
    """Cấu trúc tài khoản tối thiểu tương thích Account của register_mailcom ngoài."""

    username: str
    password: str


# ============================================================
# 密码生成
# ============================================================


def generate_mailcom_password(length: int = 12) -> str:
    """Sinh mật khẩu mạnh gồm chữ hoa, chữ thường, số, ký hiệu (mặc định 12 ký tự).

    Cùng hành vi register_mailcom.generate_chatgpt_password.
    """
    if length < 12:
        length = 12
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(PASSWORD_SYMBOLS),
    ]
    remaining = [
        secrets.choice(PASSWORD_ALPHABET) for _ in range(length - len(required))
    ]
    chars = required + remaining
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ============================================================
# HTML 解析辅助
# ============================================================


def _extract_form(
    html_text: str, form_id: str | None = None
) -> tuple[str, dict[str, str]]:
    """Rút action của form chỉ định và mọi cặp tên/giá trị input từ HTML."""
    soup = BeautifulSoup(html_text, "html.parser")
    form = soup.find("form", id=form_id) if form_id else soup.find("form")
    if not form:
        raise MailComError(f"Trang mail.com không thấy form: {form_id or '(first)'}")
    action = form.get("action") or ""
    payload: dict[str, str] = {}
    for input_node in form.find_all("input"):
        name = input_node.get("name")
        if name:
            payload[name] = input_node.get("value", "")
    return action, payload


def _extract_srttkn(*values: str) -> str:
    """Rút srttkn token từ nhiều đoạn URL / HTML."""
    haystack = "\n".join(values)
    patterns = [
        r"[?&]srttkn=([A-Za-z0-9._:-]+)",
        r'name=["\']srttkn["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']srttkn["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, haystack)
        if match:
            return unescape(match.group(1))
    raise MailComError("Trang passwordChange của mail.com không thấy srttkn")


def _password_headers(
    referer: str,
    accept_language: str = MAILCOM_DEFAULT_ACCEPT_LANGUAGE,
) -> dict[str, str]:
    """Tạo headers chuẩn để mở trang passwordChange / gửi form."""
    return {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": accept_language,
        "Cache-Control": "no-cache",
        "Origin": MAILCOM_ACCOUNT_BASE,
        "Pragma": "no-cache",
        "Referer": referer,
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }


# ============================================================
# 改密核心：登录 account.mail.com + 提交 passwordChange 表单
# ============================================================


def ensure_mailcom_account_session(
    client: MailComLightClient, current_password: str
) -> None:
    """Đảm bảo client.session đã đăng nhập account.mail.com (khác domain lightmailer.mail.com).

    Nếu trang GET account.mail.com/ không còn loginForm thì coi là đã đăng nhập, trả ngay;
    không thì gửi loginForm bằng mật khẩu hiện tại để đăng nhập.
    """
    session = client.session
    page = session.get(
        f"{MAILCOM_ACCOUNT_BASE}/",
        headers={"Referer": "https://lightmailer.mail.com/settings"},
        timeout=30,
        allow_redirects=True,
    )
    page.raise_for_status()
    html = getattr(page, "text", "") or ""
    if (
        'id="loginForm"' not in html
        and 'name="loginForm"' not in html
        and "/ciss/login" not in getattr(page, "url", "")
    ):
        return

    action, payload = _extract_form(html, "loginForm")
    payload["username"] = client.username
    payload["password"] = current_password
    login = session.post(
        urljoin(getattr(page, "url", MAILCOM_ACCOUNT_BASE), action),
        data=payload,
        headers={
            "Origin": MAILCOM_ACCOUNT_BASE,
            "Referer": getattr(page, "url", MAILCOM_ACCOUNT_BASE),
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=30,
        allow_redirects=True,
    )
    login.raise_for_status()
    login_text = getattr(login, "text", "") or ""
    if 'id="loginForm"' in login_text or "login-failed" in getattr(login, "url", ""):
        raise MailComError("Đăng nhập account mail.com thất bại, không vào được trang đổi mật khẩu")


def change_mailcom_password(
    client: MailComLightClient,
    current_password: str,
    new_password: str,
) -> None:
    """Đổi mật khẩu tài khoản mail.com.

    Args:
        client: MailComLightClient đã đăng nhập lightmailer (cần client.login() trước)
        current_password: mật khẩu hiện tại
        new_password: mật khẩu mới
    """
    session = client.session
    accept_language = str(
        getattr(client, "accept_language", "") or MAILCOM_DEFAULT_ACCEPT_LANGUAGE
    )
    ensure_mailcom_account_session(client, current_password)

    get_url = urljoin(MAILCOM_ACCOUNT_BASE, f"{MAILCOM_ACCOUNT_PASSWORD_PATH}?1")
    page = session.get(
        get_url,
        headers=_password_headers(MAILCOM_ACCOUNT_BASE, accept_language),
        timeout=30,
        allow_redirects=True,
    )
    page.raise_for_status()

    token = _extract_srttkn(getattr(page, "url", ""), getattr(page, "text", ""))
    form_action = ""
    try:
        form_action, _ = _extract_form(getattr(page, "text", "") or "", "idb")
    except Exception:
        form_action = ""
    page_url = getattr(page, "url", "") or ""
    referer = (
        page_url
        if "srttkn=" in page_url
        else urljoin(
            MAILCOM_ACCOUNT_BASE,
            f"{MAILCOM_ACCOUNT_PASSWORD_PATH}?1&srttkn={quote(token)}",
        )
    )
    if form_action:
        post_url = urljoin(page_url or MAILCOM_ACCOUNT_BASE, form_action)
        if "saveChanges=" not in post_url:
            separator = "&" if "?" in post_url else "?"
            post_url = f"{post_url}{separator}saveChanges=x"
    else:
        post_url = urljoin(
            MAILCOM_ACCOUNT_BASE,
            f"{MAILCOM_ACCOUNT_PASSWORD_PATH}?1-1.-form&srttkn={quote(token)}&saveChanges=x",
        )
    payload = {
        "editPanel:username": client.username,
        "editPanel:currentPasswordPanel:topWrapper:inputWrapper:input": current_password,
        "editPanel:newPasswordFieldPanel:topWrapper:inputWrapper:input": new_password,
        "editPanel:retypeNewPasswordFieldPanel:topWrapper:inputWrapper:input": new_password,
    }
    headers = _password_headers(referer, accept_language)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    response = session.post(
        post_url,
        data=payload,
        headers=headers,
        timeout=30,
        allow_redirects=True,
    )
    response.raise_for_status()
    text = getattr(response, "text", "") or ""
    if re.search(
        r"(current password is incorrect|passwords do not match|invalid password|errorMessage)",
        text,
        re.I,
    ):
        raise MailComError("Đổi mật khẩu mail.com thất bại, trang trả thông báo lỗi")


# ============================================================
# 对外公共接口
# ============================================================


def change_account_password(
    account: Account,
    proxy: str = "",
    new_password: str = "",
) -> tuple[Account, str]:
    """Đổi mật khẩu tài khoản mail.com.

    Tương thích chữ ký mail_password_change.change_account_password ngoài,
    để scripts/batch_change_gpt_valid_mails.py / kho kiểm tra sống gọi đổi mật khẩu.

    Args:
        account: Account(username, password) dataclass
        proxy: URL proxy; để trống thì đi _mailcom_proxy()
        new_password: mật khẩu mới; để trống thì sinh ngẫu nhiên 12 ký tự

    Returns:
        (account, new_password)
    """
    generated = not bool((new_password or "").strip())
    new_password = (new_password or "").strip() or generate_mailcom_password(12)
    old_password = account.password
    # 发送变更前：明确打出旧密码与即将提交的随机/指定新密码（测活批量改密入口）
    logger.info(
        """[MailCom][kiểm tra sống/đổi mật khẩu hàng loạt] trước khi đổi email=%s old_password=%s new_password=%s generated=%s (sắp gửi passwordChange)""",
        account.username,
        old_password,
        new_password,
        generated,
    )
    proxy = proxy or _mailcom_proxy()
    try:
        client = MailComLightClient(
            account.username,
            account.password,
            session=_http_session(proxy=proxy),
        )
        client.login()
        change_mailcom_password(client, account.password, new_password)
    except Exception as exc:
        logger.error(
            """[MailCom][kiểm tra sống/đổi mật khẩu hàng loạt] đổi thất bại email=%s old_password=%s attempted_new_password=%s err=%s""",
            account.username,
            old_password,
            new_password,
            exc,
        )
        raise
    logger.info(
        """[MailCom][kiểm tra sống/đổi mật khẩu hàng loạt] sau khi đổi email=%s old_password=%s new_password=%s status=success""",
        account.username,
        old_password,
        new_password,
    )
    return account, new_password


def change_mailcom_password_for_email(
    email: str,
    new_password: str = "",
    proxy: str = "",
) -> str:
    """Đổi mật khẩu mail.com theo địa chỉ email, rồi ghi lại DB + cache bộ nhớ.

    Cho luồng đăng ký chính / task tự động gọi: đổi mật khẩu xong cập nhật ngay email_pool.password và
    mailcom_client._CONTEXT_CACHE, để wait_for_otp sau đó đăng nhập bằng mật khẩu mới.

    Args:
        email: địa chỉ email mail.com
        new_password: mật khẩu mới; để trống thì sinh ngẫu nhiên 12 ký tự
        proxy: URL proxy; để trống thì đi _mailcom_proxy()

    Returns:
        mật khẩu mới
    """
    generated = not bool((new_password or "").strip())
    new_password = (new_password or "").strip() or generate_mailcom_password(12)

    # 取当前账号上下文（内存缓存 → DB fallback）
    from core.mailcom_client import get_account_context

    account_ctx = get_account_context(email)
    if account_ctx is None:
        raise MailComError(
            f"Không tìm thấy ngữ cảnh tài khoản mail.com của {email} không có ngữ cảnh tài khoản mail.com, không đổi được mật khẩu. "
            f"Hãy xác nhận email này đã được pick_account lấy hoặc đã ghi vào kho email."
        )

    current_password = account_ctx.password
    if not current_password:
        raise MailComError(f"{email} mật khẩu hiện tại trống, không đổi mật khẩu được")

    # 发送变更前：先打出变更前密码与即将提交的随机/指定新密码（自动化注册前改密入口）
    logger.info(
        """[MailCom][đổi mật khẩu tự động] trước khi đổi email=%s old_password=%s new_password=%s generated=%s (sắp gửi passwordChange)""",
        email,
        current_password,
        new_password,
        generated,
    )

    # 改密
    _proxy = proxy or _mailcom_proxy()
    try:
        client = MailComLightClient(
            email,
            current_password,
            session=_http_session(proxy=_proxy),
        )
        client.login()
        change_mailcom_password(client, current_password, new_password)
    except Exception as exc:
        logger.error(
            """[MailCom][đổi mật khẩu tự động] đổi thất bại email=%s old_password=%s attempted_new_password=%s err=%s""",
            email,
            current_password,
            new_password,
            exc,
        )
        raise
    logger.info(
        """[MailCom][đổi mật khẩu tự động] sau khi đổi email=%s old_password=%s new_password=%s status=success""",
        email,
        current_password,
        new_password,
    )

    # 回写内存缓存，后续 fetch_latest_otp 会用新密码
    from core.mailcom_client import MailComAccount

    _CONTEXT_CACHE[email] = MailComAccount(email=email, password=new_password)

    # 回写 DB（email_pool.password）
    try:
        from core import db

        db.update_mailcom_email_password(email, new_password)
        logger.info(
            "[MailCom][đổi mật khẩu tự động] %s đã ghi mật khẩu mới vào DB email_pool.password new_password=%s",
            email,
            new_password,
        )
    except Exception as exc:
        logger.warning(
            "[MailCom][đổi mật khẩu tự động] %s ghi mật khẩu mới vào DB thất bại (không ảnh hưởng lấy thư lần đăng ký này, cache đã cập nhật): %s",
            email,
            exc,
        )

    return new_password


def maybe_change_mailcom_password_before_register(
    email: str,
    new_password: str = "",
) -> str | None:
    """Đổi mật khẩu mail.com trước đăng ký khi cần.

    Chỉ đổi khi đủ mọi điều kiện:
        1. config.email.MAILCOM_CHANGE_PASSWORD_BEFORE_REGISTER là True
        2. Nguồn email phân giải là mailcom

    Args:
        email: email đăng ký
        new_password: mật khẩu mới; để trống thì sinh ngẫu nhiên 12 ký tự

    Returns:
        mật khẩu mới; không đổi thì trả None
    """
    try:
        from config import email as _email_cfg
    except Exception:
        return None

    if not bool(getattr(_email_cfg, "MAILCOM_CHANGE_PASSWORD_BEFORE_REGISTER", False)):
        return None

    # 判断邮箱来源是否 mailcom
    try:
        from core.email_provider import resolve_email_source

        source = resolve_email_source(email)
    except Exception:
        source = ""
    if source != "mailcom":
        return None

    logger.info(
        "[MailCom][đổi mật khẩu tự động] kích hoạt đổi mật khẩu trước đăng ký email=%s (sẽ sinh/dùng mật khẩu mới ngẫu nhiên và ghi log trước/sau)",
        email,
    )
    return change_mailcom_password_for_email(email, new_password=new_password)


if __name__ == "__main__":
    # 独立调试：python -m core.mail_password_change 'email----password' [new_password]
    import sys as _sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )
    if len(_sys.argv) < 2:
        print(
            "usage: python -m core.mail_password_change 'email----password' [new_password]"
        )
        _sys.exit(2)
    parts = _sys.argv[1].split("----")
    if len(parts) != 2:
        print(f"Sai định dạng 2 đoạn: nhận được {len(parts)} đoạn")
        _sys.exit(2)
    _email, _old_pwd = parts
    _new_pwd = _sys.argv[2] if len(_sys.argv) > 2 else ""
    _CONTEXT_CACHE[_email] = Account(username=_email, password=_old_pwd)  # type: ignore[assignment]
    try:
        result = change_mailcom_password_for_email(_email, new_password=_new_pwd)
        print(f"Mật khẩu mới: {result}")
    except Exception as ex:
        print(f"ERR: {ex}")
        _sys.exit(1)
