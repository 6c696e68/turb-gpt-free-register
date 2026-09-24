# -*- coding: utf-8 -*-
"""gói/Plus điều kiệntruy vấnnềnhàng đợi。"""
from __future__ import annotations

import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from config import proxy as proxy_cfg
from core import db
from core.chatgpt_plan import check_account_plan

logger = logging.getLogger(__name__)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(proxy_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _float_setting(name: str, default: float, lower: float, upper: float) -> float:
    try:
        value = float(getattr(proxy_cfg, name, default) or 0.0)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("PLAN_CHECK_WORKERS", 3, 1, 16)
_QUEUE_LIMIT = _int_setting("PLAN_CHECK_QUEUE_LIMIT", 500, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="plan-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RATE_LOCK = threading.Lock()
_NEXT_REQUEST_AT = 0.0


def _wait_for_rate_slot() -> None:
    """là nơi có truy vấnluồngcấpsai mở requestkhởi động khikhoảng 。"""
    global _NEXT_REQUEST_AT
    min_interval = _float_setting("PLAN_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0)
    jitter = _float_setting("PLAN_CHECK_JITTER", 0.3, 0.0, 30.0)
    with _RATE_LOCK:
        now = time.monotonic()
        scheduled = max(now, _NEXT_REQUEST_AT) + (random.uniform(0.0, jitter) if jitter else 0.0)
        _NEXT_REQUEST_AT = scheduled + min_interval
    wait_seconds = scheduled - now
    if wait_seconds > 0:
        time.sleep(wait_seconds)


def _registration_recheck_delay() -> float:
    return _float_setting("PLAN_CHECK_REGISTRATION_RECHECK_DELAY", 2.0, 0.0, 30.0)


def _run_plan_check(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None,
    timezone_offset_min: str,
) -> dict:
    try:
        if not db.mark_account_plan_check_running(account_id):
            return {"ok": False, "error": "Tài khoản đã xoá hoặc trạng thái truy vấn gói đã bị reset"}

        _wait_for_rate_slot()
        result = check_account_plan(
            access_token,
            proxy=proxy,
            timezone_offset_min=timezone_offset_min,
        )

        recheck_delay = _registration_recheck_delay()
        should_recheck = (
            trigger == "registration_auto"
            and recheck_delay > 0
            and bool(result.get("ok"))
            and str(result.get("current_plan_type") or "").lower() == "free"
            and not bool(result.get("plus_trial_eligible"))
        )
        if should_recheck:
            logger.info("[Plan] tài khoản mới chưa thấy quyền thử Plus, %.1fs rồi kiểm tra lại một lần: %s", recheck_delay, email)
            time.sleep(recheck_delay)
            _wait_for_rate_slot()
            recheck_result = check_account_plan(
                access_token,
                proxy=proxy,
                timezone_offset_min=timezone_offset_min,
                max_attempts=1,
            )
            if recheck_result.get("ok"):
                result = recheck_result
            else:
                logger.warning(
                    "[Plan] kiểm tra lại điều kiện tài khoản mới thất bại, giữ kết quả thành công lần đầu: %s, %s",
                    email,
                    recheck_result.get("error") or "Lỗi không rõ",
                )

        db.update_account_plan_check(acc_id=account_id, result=result)
        if result.get("ok"):
            logger.info(
                "[Plan] truy vấn nền thành công: %s, plan=%s, plus_trial=%s, trigger=%s",
                email,
                result.get("current_plan_type") or "unknown",
                bool(result.get("plus_trial_eligible")),
                trigger,
            )
        else:
            logger.warning(
                "[Plan] truy vấn nền thất bại: %s, trigger=%s, error=%s",
                email,
                trigger,
                result.get("error") or "Lỗi không rõ",
            )
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:180]}",
        }
        try:
            db.update_account_plan_check(acc_id=account_id, result=result)
        except Exception:
            logger.exception("[Plan] ghi trạng thái lỗi truy vấn nền thất bại: account_id=%s", account_id)
        logger.exception("[Plan] truy vấn nền lỗi: %s", email)
        return result
    finally:
        _QUEUE_SLOTS.release()


def enqueue_account_plan_check(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None = None,
    timezone_offset_min: str = "-",
) -> dict:
    """truy vấnđặt vào thống nhấtthread pool；lại lặp truy vấn hoặc hàng đợiđầy khikhông gửi。"""
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not access_token:
        return {"accepted": False, "busy": False, "error": "Tài khoản thiếu access_token"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "Hàng đợi truy vấn gói đã đầy, thử lại sau"}

    if not db.claim_account_plan_check(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "Tài khoản này đang truy vấn gói"}

    try:
        _EXECUTOR.submit(
            _run_plan_check,
            account_id=account_id,
            email=email,
            access_token=access_token,
            trigger=str(trigger or "manual"),
            proxy=proxy,
            timezone_offset_min=str(timezone_offset_min or "-"),
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"Vào hàng đợi truy vấn gói thất bại: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_plan_check(acc_id=account_id, result=result)
        return {"accepted": False, "busy": False, "error": result["error"]}

    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def queue_settings() -> dict:
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "min_interval": _float_setting("PLAN_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0),
        "jitter": _float_setting("PLAN_CHECK_JITTER", 0.3, 0.0, 30.0),
    }
