# -*- coding: utf-8 -*-
"""không giao tương tác vòng môi trường dưới thủ công OTP thông đường （WebUI / nềntác vụdùng ）。

dùng cách ：
1. đăng kýtác vụđiều chỉnh dùng wait_for_manual_otp(email)
2. người dùngtại WebUI với tác vụgửi 6 sốmã OTP， hoặc điều chỉnh dùng submit_manual_otp(email, code)
3. chờphía lấy đến mã OTP sautiếp tục
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict

logger = logging.getLogger(__name__)

_lock = threading.Lock()
# email(lower) -> list[code]  支持同一邮箱多次验证码
_codes: dict[str, list[str]] = defaultdict(list)
# email(lower) -> Event
_events: dict[str, threading.Event] = {}
# email(lower) -> waiting meta
_waiting: dict[str, dict] = {}


def _norm(email: str) -> str:
    return str(email or "").strip().lower()


def _event_for(email: str) -> threading.Event:
    key = _norm(email)
    ev = _events.get(key)
    if ev is None:
        ev = threading.Event()
        _events[key] = ev
    return ev


def mark_waiting(email: str, job_id: int | None = None) -> None:
    key = _norm(email)
    with _lock:
        _waiting[key] = {
            "email": email,
            "job_id": job_id,
            "since": time.time(),
        }
        _event_for(key).clear()


def clear_waiting(email: str) -> None:
    key = _norm(email)
    with _lock:
        _waiting.pop(key, None)


def list_waiting() -> list[dict]:
    with _lock:
        return [dict(v) for v in _waiting.values()]


def submit_manual_otp(email: str, code: str) -> dict:
    key = _norm(email)
    code = str(code or "").strip().replace(" ", "")
    if not key:
        raise ValueError("email trống")
    if not code:
        raise ValueError("Mã OTP trống")
    if not code.isdigit() or len(code) not in (4, 5, 6, 7, 8):
        # OpenAI 通常 6 位；放宽一点兼容
        raise ValueError(f"Định dạng mã OTP có vẻ sai: {code!r}")
    with _lock:
        _codes[key].append(code)
        _event_for(key).set()
    logger.info("[ManualOTP] đã gửi mã OTP：email=%s code=%s", email, code)
    return {"ok": True, "email": email, "code": code}


def pop_manual_otp(email: str) -> str | None:
    key = _norm(email)
    with _lock:
        queue = _codes.get(key) or []
        if not queue:
            return None
        code = queue.pop(0)
        if not queue:
            _event_for(key).clear()
        return code


def wait_for_manual_otp(email: str, *, timeout: int = 180, job_id: int | None = None) -> str:
    """chặn nhét chờthủ côngmã OTP。ưu trước ăn đã gửi code，không thì vòng hỏi /việc mục chờ。"""
    key = _norm(email)
    if not key:
        raise RuntimeError("OTP thủ công: email trống")

    # 若已有预提交验证码，直接用
    existing = pop_manual_otp(email)
    if existing:
        clear_waiting(email)
        return existing

    mark_waiting(email, job_id=job_id)
    logger.info(
        "[ManualOTP] chờ nhập mã OTP thủ công：email=%s timeout=%ss job=%s",
        email,
        timeout,
        job_id or "-",
    )
    logger.info("[ManualOTP] hãy mở email %s，gửi mã OTP 6 số cạnh tác vụ trên WebUI", email)

    # CLI 交互兜底：如果有 TTY，也允许终端输入
    try:
        import sys
        has_tty = bool(getattr(sys, "stdin", None) and sys.stdin.isatty())
    except Exception:
        has_tty = False

    end = time.time() + max(10, int(timeout))
    ev = _event_for(key)
    try:
        while time.time() < end:
            code = pop_manual_otp(email)
            if code:
                return code

            if has_tty:
                # 非阻塞感：短暂等事件，再提示一次
                if ev.wait(timeout=1.0):
                    code = pop_manual_otp(email)
                    if code:
                        return code
                # 给 CLI 一次机会
                try:
                    typed = input(f">>> Nhập thủ công {email} mã OTP email: ").strip()
                except EOFError:
                    typed = ""
                if typed:
                    submit_manual_otp(email, typed)
                    code = pop_manual_otp(email)
                    if code:
                        return code
            else:
                ev.wait(timeout=1.0)

            # 支持任务被手动停止
            try:
                from core.registration_service import check_stop_requested
                check_stop_requested()
            except Exception:
                pass
        raise TimeoutError(f"Chờ mã OTP thủ công quá hạn ({timeout}s）：{email}")
    finally:
        clear_waiting(email)
