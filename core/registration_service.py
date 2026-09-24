# -*- coding: utf-8 -*-
"""
Lớp dịch vụ tác vụ đăng ký:
    - Thread pool thực thi đồng thời run_registration
    - Mỗi tác vụ có một bản ghi trong data/registration_jobs.json
    - Log mỗi tác vụ ghi vào data/logs/<job_uuid>.log, tiện Web UI tail realtime

Cách dùng:
    submit_registration(email_source="outlook", count=5)
    → Tạo 5 tác vụ, đưa vào thread pool, trả về ngay [job_dict, ...]
"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from core import codex_retry_service, db

logger = logging.getLogger(__name__)

# Thread pool toàn cục, số đồng thời tối đa (WebUI mỗi lần submit có thể rebuild theo workers mới nhất)
_DEFAULT_MAX_WORKERS = 4
_MIN_MAX_WORKERS = 1
_MAX_MAX_WORKERS = 16
_executor: ThreadPoolExecutor | None = None
_executor_workers = _DEFAULT_MAX_WORKERS
_executor_generation = 0
_retired_executors: list[ThreadPoolExecutor] = []
_executor_lock = threading.RLock()

_STOP_EVENTS: dict[int, threading.Event] = {}
_ACTIVE_JOBS: set[int] = set()
_STOP_LOCK = threading.Lock()
_THREAD_CTX = threading.local()


class StopRequested(RuntimeError):
    """Người dùng dừng thủ công tác vụ đăng ký."""


def _activate_job(job_id: int) -> None:
    _THREAD_CTX.job_id = int(job_id)
    with _STOP_LOCK:
        _STOP_EVENTS.setdefault(int(job_id), threading.Event())
        _ACTIVE_JOBS.add(int(job_id))


def _deactivate_job(job_id: int) -> None:
    with _STOP_LOCK:
        _STOP_EVENTS.pop(int(job_id), None)
        _ACTIVE_JOBS.discard(int(job_id))
    try:
        delattr(_THREAD_CTX, "job_id")
    except Exception:
        pass


def is_stop_requested(job_id: int | None = None) -> bool:
    if job_id is None:
        job_id = getattr(_THREAD_CTX, "job_id", None)
    if not job_id:
        return False
    with _STOP_LOCK:
        ev = _STOP_EVENTS.get(int(job_id))
        if ev and ev.is_set():
            return True
    job = db.get_job(int(job_id))
    return bool(job and job.get("status") in ("stopping", "stopped", "cancelled"))


def check_stop_requested() -> None:
    job_id = getattr(_THREAD_CTX, "job_id", None)
    if is_stop_requested(job_id):
        raise StopRequested(f"Tác vụ #{job_id} đã bị người dùng dừng thủ công")


def _append_job_log(job_id: int, message: str) -> None:
    try:
        job = db.get_job(job_id)
        log_file = job.get("log_file") if job else None
        if not log_file:
            return
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%H:%M:%S")
        with Path(log_file).open("a", encoding="utf-8") as f:
            f.write(f"{ts} [WARNING] [manual-stop] {message}\n")
    except Exception:
        pass


def _random_display_name() -> str:
    """Tạo display name chữ cái tiếng Anh theo giới hạn OpenAI."""
    from core.name_samples import random_display_name

    return random_display_name()


def _prepare_registration_args() -> tuple[str | None, str, str]:
    """Tái dùng rule mặc định CLI, bổ sung tham số đăng ký cho entry Web cũ."""
    # Đọc bằng thuộc tính module, hỗ trợ hot-load WebUI
    from config import register as _r, email as _e
    from core.profile_utils import generate_random_birthday

    email = str(getattr(_r, "REGISTER_EMAIL", "") or "").strip()
    name = str(getattr(_r, "REGISTER_NAME", "") or "").strip()
    # Trong WebUI/cấu hình đôi khi lưu giá trị rỗng thành "-", đây không phải tên hiển thị OpenAI hợp lệ, xử lý như rỗng và tự động tạo
    if name in {"-", "—", "无", "空", "none", "None", "null", "NULL"}:
        name = ""

    if not name:
        # Chế độ thủ công cũng tự động tạo tên hiển thị, giảm gánh nặng cấu hình
        name = _random_display_name()

    birthday = generate_random_birthday()

    # Email tự động không nhận ở giai đoạn chuẩn bị: driver trình duyệt đợi trang tìm thấy ô nhập email rồi mới nhận,
    # Điều khiển theo giao thức thì nhận khi run_registration sắp bắt đầu xác thực. Như vậy trang không mở được/không tìm thấy
    # Khi ở ô nhập sẽ không tiêu thụ sớm đơn email hoặc tài nguyên trong pool.
    if not email and not _e.USE_EMAIL_SERVICE:
        raise RuntimeError(
            "Chế độ thủ công chưa cấu hình email. Đặt REGISTER_EMAIL ở trang Cấu hình WebUI, "
            "hoặc bật USE_EMAIL_SERVICE và lấy từ kho email."
        )

    return email, name, birthday


def _release_unconsumed_job_email(email: str | None, reason: str) -> None:
    """Fallback khi tác vụ thất bại: chỉ thu hồi email used chưa tạo tài khoản."""
    if not email:
        return
    try:
        from core.email_provider import release_email_if_unconsumed

        release_email_if_unconsumed(email, note=f"Tác vụ chưa tiêu thụ, đã tự thu hồi: {reason[:180]}")
    except Exception:
        logger.exception("[Service] Thu hồi email chưa tiêu thụ thất bại: %s", email)


def _is_final_session_access_token_timeout(error: object) -> bool:
    """
    Nhận diện lỗi bước cuối đăng ký: /api/auth/session 200 nhưng không có accessToken.
    Email kiểu này nếu đăng ký tiếp thường kẹt cùng trạng thái; dừng luôn mục kho email.
    """
    text = str(error or "")
    if not text:
        return False
    return (
        "等待 /api/auth/session accessToken 超时" in text
        and "WARNING_BANNER" in text
        and "'_http_status': 200" in text
    )


def _should_disable_failed_registration_email(error: object) -> bool:
    """Loại thất bại đăng ký cần dừng email ngay."""
    text = str(error or "")
    if not text:
        return False
    return (
        _is_final_session_access_token_timeout(text)
        or "邮箱提交后进入登录密码页" in text
        or "auth.openai.com/log-in/password" in text
        or "/log-in/password" in text
    )


def _disable_job_email(email: str | None, reason: str) -> bool:
    """Dừng email của tác vụ này, tránh lấy lại sau."""
    if not email:
        return False
    try:
        from core.email_provider import release_email

        source = release_email(email, status="disabled", note=f"Tự dừng: {reason[:180]}")
        logger.warning("[Service] Đã tự dừng email: source=%s email=%s reason=%s", source, email, reason[:220])
        return True
    except Exception:
        logger.exception("[Service] Tự dừng email thất bại: %s", email)
        return False


def _normalize_workers(max_workers: int | None) -> int:
    if max_workers is None:
        return _DEFAULT_MAX_WORKERS
    try:
        value = int(max_workers)
    except (TypeError, ValueError):
        value = _DEFAULT_MAX_WORKERS
    return max(_MIN_MAX_WORKERS, min(_MAX_MAX_WORKERS, value))


def get_executor(max_workers: int | None = None) -> ThreadPoolExecutor:
    """Trả về thread pool đăng ký.

    Logic cũ chỉ dùng max_workers khi tạo thread pool lần đầu; sau đó WebUI đổi số luồng rồi submit vẫn tái sử dụng
    pool lần trước. Ở đây đổi thành: mỗi khi max_workers truyền vào khác với pool hiện tại, ngay lập tức tạo pool mới cho
    các task submit mới sử dụng; pool cũ không nhận task mới, nhưng sẽ tiếp tục chạy hết các task đã xếp hàng/đang chạy.
    """
    global _executor, _executor_workers, _executor_generation
    requested_workers = _normalize_workers(max_workers) if max_workers is not None else _executor_workers
    with _executor_lock:
        if _executor is None or requested_workers != _executor_workers:
            old_executor = _executor
            if old_executor is not None:
                # Không hủy các task đã gửi trong pool cũ, chỉ là không còn thêm task mới vào pool cũ.
                old_executor.shutdown(wait=False, cancel_futures=False)
                _retired_executors.append(old_executor)
                logger.info(
                    "[Service] Thread pool đăng ký đổi workers %s → %s; pool cũ tiếp tục task đã xếp hàng",
                    _executor_workers,
                    requested_workers,
                )
            _executor_workers = requested_workers
            _executor_generation += 1
            _executor = ThreadPoolExecutor(
                max_workers=requested_workers,
                thread_name_prefix=f"reg-worker-{_executor_generation}",
            )
    return _executor


def get_executor_workers() -> int:
    """Số luồng dùng cho tác vụ đăng ký mới submit."""
    with _executor_lock:
        return _executor_workers


def shutdown_executor(wait: bool = True) -> None:
    global _executor
    with _executor_lock:
        executors = []
        if _executor is not None:
            executors.append(_executor)
            _executor = None
        executors.extend(_retired_executors)
        _retired_executors.clear()
    for ex in executors:
        ex.shutdown(wait=wait, cancel_futures=False)


# ============================================================
# Thực thi đơn nhiệm vụ: chuyển hướng log sang file riêng của nhiệm vụ
# ============================================================

class _JobLogContext:
    """Thêm FileHandler vào root logger của thread này, gỡ khi xong."""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.handler: logging.FileHandler | None = None

    def __enter__(self):
        Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)
        self.handler = logging.FileHandler(self.log_path, encoding="utf-8")
        self.handler.setLevel(logging.INFO)
        self.handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        # Chỉ lọc cho luồng này —— dùng thread name để phân biệt, tránh làm bẩn log của các tác vụ khác
        thread_name = threading.current_thread().name
        self.handler.addFilter(lambda r: r.threadName == thread_name)
        logging.getLogger().addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handler is not None:
            self.handler.close()
            logging.getLogger().removeHandler(self.handler)


def _run_one_job(job_id: int, log_file: str) -> None:
    """Entry một tác vụ (thread pool chạy hàm này)."""
    log_logger = logging.getLogger(__name__)
    _activate_job(job_id)

    # Kiểm tra hủy: người dùng có thể đã bấm "hủy xếp hàng" trong lúc task đang xếp hàng, đổi status thành cancelled.
    # Vì Future đã submit vào thread pool không thể thu hồi, chỉ có thể tự kiểm tra trước khi thực thi thật, bỏ qua những cái đã cancelled.
    current = db.get_job(job_id)
    if not current:
        log_logger.info(f"[Job {job_id}] Bản ghi tác vụ đã xoá, bỏ qua thực thi")
        _deactivate_job(job_id)
        return
    if current.get("status") == "cancelled":
        log_logger.info(f"[Job {job_id}] Đã bị người dùng huỷ, bỏ qua thực thi")
        _deactivate_job(job_id)
        return

    db.update_job(job_id, status="running", started_at=datetime.now().isoformat(timespec="seconds"))

    email: str | None = None
    try:
        with _JobLogContext(log_file):
            from main import run_registration
            log_logger.info(f"[Job {job_id}] Bắt đầu tác vụ đăng ký")
            email, name, birthday = _prepare_registration_args()
            db.update_job(job_id, email=email)
            check_stop_requested()
            def _on_email_acquired(acquired_email: str) -> None:
                nonlocal email
                email = str(acquired_email or "").strip() or None
                if email:
                    db.update_job(job_id, email=email)
                    log_logger.info(f"[Job {job_id}] Trang đã có ô email, đã gán email: {email}")

            result = run_registration(
                email=email,
                name=name,
                birthday=birthday,
                on_email_acquired=_on_email_acquired,
            )
            if is_stop_requested(job_id):
                _release_unconsumed_job_email(email, "Người dùng dừng thủ công")
                db.update_job(
                    job_id,
                    status="stopped",
                    network_traffic=(result or {}).get("network_traffic") if isinstance(result, dict) else None,
                    error="Người dùng dừng thủ công",
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                log_logger.warning(f"[Job {job_id}] Đã dừng theo yêu cầu người dùng")
                return
            if isinstance(result, dict) and result.get("success"):
                db.update_job(
                    job_id,
                    status="success",
                    email=result.get("email"),
                    account_id=result.get("account_id"),
                    network_traffic=result.get("network_traffic"),
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                log_logger.info(f"[Job {job_id}] Thành công: {result.get('email')}")
            else:
                # Lưu ý: thất bại cũng có thể kèm account_id (ví dụ Codex thất bại nhưng tài khoản đã đăng ký thành công)
                err = (result or {}).get("error") if isinstance(result, dict) else "unknown"
                result_email = (result or {}).get("email") if isinstance(result, dict) else None
                db.update_job(
                    job_id,
                    status="failed",
                    email=result_email,
                    account_id=(result or {}).get("account_id") if isinstance(result, dict) else None,
                    network_traffic=(result or {}).get("network_traffic") if isinstance(result, dict) else None,
                    error=str(err)[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                email_to_handle = str(result_email or email or "").strip()
                if _should_disable_failed_registration_email(err):
                    _disable_job_email(email_to_handle, str(err))
                else:
                    _release_unconsumed_job_email(email_to_handle, str(err))
                log_logger.error(f"[Job {job_id}] Thất bại: {err}")
    except StopRequested as exc:
        _release_unconsumed_job_email(email, str(exc))
        log_logger.warning(f"[Job {job_id}] Đã dừng: {exc}")
        db.update_job(
            job_id,
            status="stopped",
            error="Người dùng dừng thủ công",
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
    except Exception as exc:
        err_text = f"{type(exc).__name__}: {exc}"
        if _should_disable_failed_registration_email(err_text):
            _disable_job_email(email, err_text)
        else:
            _release_unconsumed_job_email(email, err_text)
        if is_stop_requested(job_id):
            log_logger.warning(f"[Job {job_id}] Bắt exception lúc dừng, xử lý như đã dừng: {type(exc).__name__}: {exc}")
            db.update_job(
                job_id,
                status="stopped",
                error="Người dùng dừng thủ công",
                completed_at=datetime.now().isoformat(timespec="seconds"),
            )
            return
        log_logger.exception(f"[Job {job_id}] Ngoại lệ")
        db.update_job(
            job_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
    finally:
        _deactivate_job(job_id)


def _run_codex_retry_job(job_id: int, log_file: str, email: str, account_id: int) -> None:
    """Thực thi chạy bù Codex như tác vụ chuẩn, tái dùng trạng thái/log/cổng dừng."""
    _activate_job(job_id)
    current = db.get_job(job_id)
    if not current or current.get("status") == "cancelled":
        codex_retry_service.release(email)
        _deactivate_job(job_id)
        return

    db.update_job(job_id, status="running", started_at=datetime.now().isoformat(timespec="seconds"))
    try:
        result = codex_retry_service.run_worker(
            email,
            clear_log=False,
            target_log_path=log_file,
        )
        now_iso = datetime.now().isoformat(timespec="seconds")
        if is_stop_requested(job_id) or result.get("status") == "stopped":
            db.update_job(job_id, status="stopped", email=email, account_id=account_id, error=str(result.get("message") or "Người dùng dừng thủ công")[:500], completed_at=now_iso)
        elif result.get("ok"):
            db.update_job(
                job_id,
                status="success",
                email=email,
                account_id=account_id,
                completed_at=now_iso,
            )
        else:
            db.update_job(
                job_id,
                status="failed",
                email=email,
                account_id=account_id,
                error=str(result.get("message") or "Chạy bù Codex thất bại")[:500],
                completed_at=now_iso,
            )
    except Exception as exc:
        db.update_job(
            job_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        codex_retry_service.release(email)
        logger.exception("[Job %s] Ngoại lệ chạy bù Codex", job_id)
    finally:
        _deactivate_job(job_id)


# ============================================================
# Giao diện công cộng
# ============================================================

def submit_registration(count: int = 1, email_source: str | None = None, workers: int | None = None) -> list[dict]:
    """
    Tạo N nhiệm vụ đăng ký và gửi vào thread pool.
    email_source chỉ ghi vào DB; nguồn email thực tế cố định là pool tài khoản Outlook.

    Returns:
        N job dict mới tạo
    """
    if email_source is None:
        from config import email as _email_cfg
        email_source = _email_cfg.EMAIL_SOURCE

    # Tạo/chuyển thread pool và submit lô task này phải tuần tự hóa toàn bộ: nếu không request khác sẽ xen giữa lúc submit lô này
    # Chuyển workers và shutdown pool cũ sẽ khiến submit sau đó báo cannot schedule new futures after shutdown.
    with _executor_lock:
        executor = get_executor(max_workers=workers)
        effective_workers = get_executor_workers()
        jobs = []
        for _ in range(count):
            job = db.create_job(email_source=email_source)
            try:
                executor.submit(_run_one_job, job["id"], job["log_file"])
            except Exception as exc:
                db.update_job(
                    int(job["id"]),
                    status="failed",
                    error=f"Submit hàng đợi thất bại: {type(exc).__name__}: {exc}"[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                logger.exception("[Service] Gửi tác vụ đăng ký #%s vào thread pool thất bại", job["id"])
            jobs.append(db.get_job(int(job["id"])) or job)
    logger.info(f"[Service] Đã gửi {count} tác vụ đăng ký, nguồn={email_source}, workers={effective_workers}")
    return jobs


def _account_for_job(job: dict) -> dict | None:
    account_id = job.get("account_id")
    if account_id is not None:
        try:
            account = db.get_account(int(account_id))
            if account is not None:
                return account
        except (TypeError, ValueError):
            pass
    email = str(job.get("email") or "").strip()
    return db.get_account_by_email(email) if email else None


def get_retry_info(job: dict) -> dict:
    """Mô tả khả năng thử lại cho API/UI, không phụ thuộc FE đoán giai đoạn lỗi."""
    status = str(job.get("status") or "")
    info = {
        "retryable": False,
        "retry_action": None,
        "retry_label": None,
        "retry_reason": None,
        "display_status": status,
    }
    if status not in ("failed", "stopped", "cancelled"):
        return info

    successful_retry = db.get_successful_retry_for_job(int(job.get("id") or 0))
    if successful_retry is not None:
        info["retry_reason"] = f"Tác vụ thử lại tiếp theo #{successful_retry.get('id')} đã thành công"
        info["successful_retry_job_id"] = successful_retry.get("id")
        return info

    account = _account_for_job(job)
    if account and job.get("account_id") is not None and status in ("failed", "stopped"):
        info["display_status"] = "success" if (account.get("codex_status") or "") == "success" else "partial_success"

    if account:
        codex_status = str(account.get("codex_status") or "")
        if codex_status == "deactivated":
            info["retry_reason"] = "Tài khoản đã hỏng, không chạy bù Codex được"
            return info
        if codex_status == "success":
            info["retry_reason"] = "Tài khoản và uỷ quyền Codex đều đã xong"
            return info
        info.update({
            "retryable": True,
            "retry_action": "codex",
            "retry_label": "Chạy bù Codex",
        })
        return info

    info.update({
        "retryable": True,
        "retry_action": "registration",
        "retry_label": "Thử lại",
    })
    return info


def retry_job(job_id: int, workers: int | None = None) -> dict:
    """Thử lại thông minh tác vụ end-state: chưa tạo account thì đăng ký lại, đã có thì chỉ chạy bù Codex."""
    source = db.get_job(job_id)
    if source is None:
        return {"ok": False, "error": "Tác vụ không tồn tại", "status": 404}

    retry_info = get_retry_info(source)
    if not retry_info["retryable"]:
        reason = retry_info.get("retry_reason") or f"Trạng thái hiện tại không hỗ trợ thử lại: {source.get('status')}"
        return {"ok": False, "error": reason, "status": 409}

    action = str(retry_info["retry_action"])
    account = _account_for_job(source)
    email = str((account or {}).get("email") or source.get("email") or "").strip()
    account_id = int(account["id"]) if account and account.get("id") is not None else None
    reserved_codex = False
    if action == "codex":
        if not email or account_id is None:
            return {"ok": False, "error": "Thông tin tài khoản đã đăng ký không đủ, không chạy bù Codex được", "status": 409}
        if not codex_retry_service.reserve(email):
            return {"ok": False, "error": "Tài khoản đang chạy bù Codex, vui lòng chờ", "status": 409}
        reserved_codex = True

    try:
        job, created = db.create_retry_job(
            int(job_id),
            job_type="codex_retry" if action == "codex" else "registration",
            email_source=str(source.get("email_source") or "outlook"),
            email=email if action == "codex" else None,
            account_id=account_id if action == "codex" else None,
        )
    except LookupError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 404}
    except ValueError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 409}

    if not created:
        if reserved_codex:
            codex_retry_service.release(email)
        return {
            "ok": True,
            "created": False,
            "reused": True,
            "message": f"Đã có tác vụ thử lại #{job['id']} đang xếp hàng hoặc chạy",
            "source_job_id": int(job_id),
            "retry_action": action,
            "job": job,
        }

    try:
        if action == "codex":
            db.update_account_codex_status(email, "retrying", None)
        with _executor_lock:
            executor = get_executor(max_workers=workers)
            if action == "codex":
                executor.submit(_run_codex_retry_job, job["id"], job["log_file"], email, int(account_id))
            else:
                executor.submit(_run_one_job, job["id"], job["log_file"])
    except Exception as exc:
        if reserved_codex:
            codex_retry_service.release(email)
            db.update_account_codex_status(email, "failed", f"Submit hàng đợi thất bại: {type(exc).__name__}: {exc}"[:500])
        db.update_job(
            int(job["id"]),
            status="failed",
            error=f"Submit hàng đợi thất bại: {type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        logger.exception("[Service] Gửi tác vụ thử lại #%s vào thread pool thất bại", job["id"])
        return {"ok": False, "error": "Tạo tác vụ thử lại thành công nhưng submit chạy thất bại", "status": 500, "job": db.get_job(int(job["id"]))}

    return {
        "ok": True,
        "created": True,
        "reused": False,
        "message": f"Đã tạo tác vụ thử lại #{job['id']}（{'Chạy bù Codex' if action == 'codex' else 'Đăng ký đầy đủ'}）",
        "source_job_id": int(job_id),
        "retry_action": action,
        "job": job,
    }


def cancel_pending_jobs() -> int:
    """
    Đổi hàng loạt mọi task status=pending thành cancelled, tránh chúng bị thực thi.
    Task đang running không đụng tới (không thể ngắt giữa chừng trong thread pool).
    Trả về số lượng hủy thành công.

    Đảm bảo thực tế "không chạy" nằm ở đầu _run_one_job——khi thật sự sắp chạy nó sẽ xem status trước để quyết định có bỏ qua không.
    """
    jobs = db.list_jobs(limit=1000)
    cancelled = 0
    now_iso = datetime.now().isoformat(timespec="seconds")
    for job in jobs:
        if job.get("status") == "pending":
            db.update_job(
                int(job["id"]),
                status="cancelled",
                completed_at=now_iso,
                error="Người dùng huỷ thủ công",
            )
            cancelled += 1
    logger.info(f"[Service] Đã huỷ {cancelled} tác vụ đang xếp hàng")
    return cancelled


def request_stop_job(job_id: int) -> dict:
    """Dừng thủ công một tác vụ đăng ký. pending huỷ ngay; running đặt cờ dừng, thread thoát ở checkpoint."""
    job = db.get_job(job_id)
    if not job:
        return {"ok": False, "error": "Tác vụ không tồn tại", "status": 404}
    status = job.get("status")
    now_iso = datetime.now().isoformat(timespec="seconds")
    if status == "pending":
        db.update_job(job_id, status="cancelled", completed_at=now_iso, error="Người dùng dừng thủ công/huỷ hàng đợi")
        _append_job_log(job_id, "Người dùng dừng thủ công: tác vụ chưa chạy, đã huỷ hàng đợi.")
        return {"ok": True, "message": "Đã huỷ tác vụ đang xếp hàng", "job_id": job_id, "state": "cancelled"}
    if status in ("success", "failed", "cancelled", "stopped"):
        return {"ok": True, "message": f"Tác vụ đã kết thúc: {status}", "job_id": job_id, "state": status}
    if status in ("running", "stopping"):
        with _STOP_LOCK:
            active = int(job_id) in _ACTIVE_JOBS
            ev = _STOP_EVENTS.get(int(job_id)) if active else None
            if ev is not None:
                ev.set()
        if not active or ev is None:
            # Dịch vụ Web khởi động lại, thread thoát do ngoại lệ, stopping còn sót từ lịch sử, hoặc lần dừng thủ công trước chỉ tạo stop event
            # nhưng không có instance luồng thật: đặt thẳng thành stopped, tránh kẹt mãi ở “đang dừng”.
            with _STOP_LOCK:
                _STOP_EVENTS.pop(int(job_id), None)
                _ACTIVE_JOBS.discard(int(job_id))
            db.update_job(
                job_id,
                status="stopped",
                completed_at=now_iso,
                error="Người dùng dừng thủ công (instance tác vụ không tồn tại)",
            )
            _release_unconsumed_job_email(
                str(job.get("email") or "").strip() or None,
                "Instance tác vụ không tồn tại, xác nhận không chạy tiếp",
            )
            _append_job_log(job_id, "Người dùng dừng thủ công: không thấy instance đang chạy, đã đánh dấu đã dừng.")
            logger.warning("[Service] Người dùng dừng tác vụ #%s: instance không tồn tại, đã đánh dấu stopped", job_id)
            return {"ok": True, "message": "Instance tác vụ không tồn tại, đã đánh dấu đã dừng", "job_id": job_id, "state": "stopped"}
        db.update_job(job_id, status="stopping", error="Đang dừng theo người dùng")
        _append_job_log(job_id, "Người dùng dừng thủ công: đã gửi tín hiệu dừng, tác vụ sẽ thoát ở checkpoint bước hiện tại.")
        logger.warning("[Service] Người dùng yêu cầu dừng tác vụ #%s", job_id)
        return {"ok": True, "message": "Đã gửi tín hiệu dừng", "job_id": job_id, "state": "stopping"}
    return {"ok": False, "error": f"Trạng thái hiện tại không hỗ trợ dừng: {status}", "status": 409}


def read_job_log(job_id: int, max_bytes: int = 50_000) -> str:
    """Đọc max_bytes cuối file log tác vụ cho Web UI."""
    job = db.get_job(job_id)
    if not job or not job.get("log_file"):
        return ""
    p = Path(job["log_file"])
    if not p.exists():
        return ""
    size = p.stat().st_size
    with p.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        data = f.read()
    return data.decode("utf-8", errors="replace")
