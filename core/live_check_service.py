# -*- coding: utf-8 -*-
"tài khoản kiểm tra sống sau nền hàng đợi: giao thức BrowserSession fingerprint môi trường + độc lập nhật ký. "
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from core import db
from core.account_liveness import check_account_liveness, log_path
from core.chatgpt_plan import _mask_proxy, open_plan_check_proxy, resolve_plan_check_route

logger = logging.getLogger(__name__)

_WORKERS = 3
_QUEUE_LIMIT = 500
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="live-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()


def is_checking(email: str) -> bool:
    acc = db.get_account_by_email(email)
    if not acc:
        return False
    return str(acc.get("live_check_status") or "") in {"queued", "running"}


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _run_live_check(*, account_id: int, email: str, proxy: str | None, trigger: str) -> dict:
    relay = None
    try:
        with _LOCK:
            _RUNNING.add(int(account_id))
        if not db.mark_account_live_check_running(account_id):
            _append_log(email, "[kiểm tra sống] Tài khoản đã xoá hoặc trạng thái kiểm tra sống đã bị đặt lại, huỷ thực thi")
            return {"ok": False, "status": "failed", "error": "Tài khoản đã xoá hoặc trạng thái kiểm tra sống đã bị đặt lại"}
        route = resolve_plan_check_route(explicit_proxy=proxy)
        selected_proxy = route.get("proxy")
        from config import proxy as proxy_cfg
        timeout = float(getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0) or 15.0)
        effective_proxy, relay = open_plan_check_proxy(
            route, selected_proxy, timeout=timeout,
        )
        # 查活必须沿用账号注册时记录的邮箱来源。不能只调用
        # resolve_email_source(email)：Remail 等临时邮箱的上下文只在领取进程
        # 内存中存在，服务重启后按当前 EMAIL_SOURCE 推断会把来源判错。
        try:
            account = db.get_account(account_id) or {}
        except Exception:
            account = {}
        email_source = str(account.get("email_source") or "").strip() or None
        if email_source:
            _append_log(email, f"[kiểm tra sống] dùng nguồn email đã lưu lúc đăng ký: {email_source}")
        _append_log(
            email,
            "[kiểm tra sống] bắt đầu thực thi nền "
            f"trigger={trigger} network_route={route.get('network_route')} "
            f"proxy_mode={route.get('proxy_mode')} proxy_used={route.get('proxy_used') or '-'} "
            f"fallback_reason={route.get('proxy_fallback_reason') or '-'}"
        )
        # 每个网络路由尝试拥有自己的任务级身份状态；同一路由的完整认证链及
        # 内部重试复用同一组 device/session 标识，不同账号绝不共享。
        fingerprint_state: dict = {}
        result = check_account_liveness(
            email,
            proxy=effective_proxy,
            clear_log=False,
            email_source=email_source,
            fingerprint_state=fingerprint_state,
        )
        # 认证链早期 403 通常是该出口被 CF 拦截，不代表账号死亡。
        # auto/proxy 模式下如果用了代理，额外直连兜底一次，便于和套餐查询的 auto 语义保持接近。
        err_text = str(result.get("error") or "")
        if (
            not result.get("ok")
            and result.get("status") == "failed"
            and "403" in err_text
            and selected_proxy
            and str(route.get("network_route") or "") == "proxy"
        ):
            _append_log(
                email,
                "[kiểm tra sống] phiên đầy đủ của tuyến proxy nhận 403, khởi chạy một lần dự phòng bằng phiên kết nối trực tiếp độc lập(không tái dùng hồ sơ proxy/Cookie/phiên ID)",
            )
            # BrowserSession 约定：None=从代理池抽取，""=明确直连。
            # 出口发生变化时必须重新按真实出口探测画像，不能把代理的 JP/VN
            # 语言时区伪装到直连；因此直连兜底使用独立的任务身份状态。
            result = check_account_liveness(
                email,
                proxy="",
                clear_log=False,
                email_source=email_source,
                fingerprint_state={},
            )
        db.update_account_liveness(account_id, result)
        if result.get("ok"):
            _append_log(email, "[kiểm tra sống] hoàn tất: tài khoản bình thường, đã làm mới bản mới nhất AT/accessToken")
        elif result.get("status") == "deactivated":
            _append_log(email, f"[kiểm tra sống] hoàn tất: tài khoản đã hỏng {result.get('error') or ''}")
        else:
            _append_log(email, f"[kiểm tra sống] hoàn tất: thất bại {result.get('error') or ''}")
        result.update({
            "network_route": route.get("network_route"),
            "proxy_used": _mask_proxy(selected_proxy) or None,
            "upstream_proxy_used": route.get("upstream_proxy_used"),
            "proxy_mode": route.get("proxy_mode"),
            "proxy_fallback_reason": route.get("proxy_fallback_reason"),
        })
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
        }
        try:
            db.update_account_liveness(account_id, result)
        except Exception:
            logger.exception("[kiểm tra sống] ghi trạng thái ngoại lệ thất bại: account_id=%s", account_id)
        logger.exception("[kiểm tra sống] ngoại lệ nền: %s", email)
        try:
            _append_log(email, f"[kiểm tra sống] ngoại lệ nền: {result['error']}")
        except Exception:
            pass
        return result
    finally:
        if relay is not None:
            relay.close()
        with _LOCK:
            _RUNNING.discard(int(account_id))
        _QUEUE_SLOTS.release()


def enqueue_account_live_check(*, account_id: int, email: str, trigger: str = "manual", proxy: str | None = None) -> dict:
    account_id = int(account_id)
    email = str(email or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email trống"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "Hàng đợi kiểm tra sống đã đầy, vui lòng thử lại sau"}
    if not db.claim_account_live_check(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "tài khoản này đang kiểm tra sống"}

    _append_log(email, f"[kiểm tra sống] đã xếp hàng account_id={account_id} trigger={trigger}", clear=True)
    try:
        _EXECUTOR.submit(
            _run_live_check,
            account_id=account_id,
            email=email,
            proxy=proxy,
            trigger=str(trigger or "manual"),
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "status": "failed",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"xếp hàng kiểm tra sống thất bại: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_liveness(account_id, result)
        _append_log(email, result["error"])
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
    return {"workers": _WORKERS, "queue_limit": _QUEUE_LIMIT}
