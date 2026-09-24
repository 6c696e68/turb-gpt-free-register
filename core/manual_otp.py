# -*- coding: utf-8 -*-
"không môi trường tương tác dưới thủ công OTP kênh(WebUI / sau nền tác vụ dùng). \n\ndùng cách: \n  1. đăng ký tác vụ gọi wait_for_manual_otp(email)\n  2. người dùng ở WebUI với tác vụ gửi 6 chữ số mã OTP, hoặc gọi submit_manual_otp(email, code)\n  3. chờ bên lấy đến mã OTP sau tiếp tục\n"
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict

logger = logging.getLogger(__name__)

_lock = threading.Lock()
# email(lower) -> list[code]  Hỗ trợ cùng một email nhiều mã xác minh
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
        # OpenAI thường 6 chữ số; nới lỏng một chút để tương thích
        raise ValueError(f"Định dạng mã OTP có vẻ không đúng: {code!r}")
    with _lock:
        _codes[key].append(code)
        _event_for(key).set()
    logger.info("[ManualOTP] đã gửi mã OTP: email=%s code=%s", email, code)
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
    "chặn chờ thủ công mã OTP. ưu tiên lấy đã gửi  code, nếu không thăm dò/sự kiện chờ. "
    key = _norm(email)
    if not key:
        raise RuntimeError("OTP thủ công: email trống")

    # Nếu đã có mã xác minh gửi trước, dùng trực tiếp
    existing = pop_manual_otp(email)
    if existing:
        clear_waiting(email)
        return existing

    mark_waiting(email, job_id=job_id)
    logger.info(
        "[ManualOTP] chờ nhập mã OTP thủ công: email=%s timeout=%ss job=%s",
        email,
        timeout,
        job_id or "-",
    )
    logger.info("[ManualOTP] hãy mở email %s, ở WebUI gửi cạnh tác vụ 6 chữ số mã OTP", email)

    # Dự phòng tương tác CLI: nếu có TTY, cũng cho phép nhập từ terminal
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
                # Cảm giác không chặn: đợi sự kiện ngắn, rồi nhắc lại một lần
                if ev.wait(timeout=1.0):
                    code = pop_manual_otp(email)
                    if code:
                        return code
                # Cho CLI một cơ hội
                try:
                    typed = input(f">>> Nhập thủ công mã OTP của {email}: ").strip()
                except EOFError:
                    typed = ""
                if typed:
                    submit_manual_otp(email, typed)
                    code = pop_manual_otp(email)
                    if code:
                        return code
            else:
                ev.wait(timeout=1.0)

            # Hỗ trợ nhiệm vụ bị dừng thủ công
            try:
                from core.registration_service import check_stop_requested
                check_stop_requested()
            except Exception:
                pass
        raise TimeoutError(f"Chờ mã OTP thủ công bị timeout ({timeout}s）：{email}")
    finally:
        clear_waiting(email)
