# -*- coding: utf-8 -*-
"\nemail nguồn điều phối mức lớp. \n\nEMAIL_SOURCE hỗ trợ một hoặc nhiều nguồn: \n  \"outlook\"\n  \"cloudflare_domain\"  # tự có miền tên + QQ IMAP\n  \"cloudflare\"  # Cloudflare Worker tạm email\n  \"generic_api\"\n  \"imap\"\n  \"gptmail\"\n  \"mailnest\"\n  \"cloudmail\"\n  \"remail\"\n  \"outlook,generic_api,mailnest,cloudmail,remail\"  # theo thứ tự dự phòng\n  [\"outlook\", \"generic_api\", \"mailnest\", \"cloudmail\", \"remail\"]  # cũng tương thích cột bảng ghi cách\n"
import logging
from typing import Iterable

logger = logging.getLogger(__name__)

_VALID_SOURCES = ("outlook", "generic_api", "imap", "cloudflare_domain", "cloudflare", "gptmail", "mailnest", "cloudmail", "remail")


def parse_email_sources(value=None) -> list[str]:
    "  EMAIL_SOURCE phân tích là có thứ tự nguồn cột bảng, khử trùng và lọc trống giá trị. "
    if value is None:
        from config import email as _email_cfg
        value = _email_cfg.EMAIL_SOURCE
    if isinstance(value, str):
        raw = value.replace(";", ",").replace("|", ",").split(",")
    elif isinstance(value, Iterable):
        raw = list(value)
    else:
        raw = [value]

    out: list[str] = []
    for item in raw:
        s = str(item or "").strip().strip('"\'')
        if not s:
            continue
        if s not in _VALID_SOURCES:
            logger.warning(f"[EmailProvider] nguồn email không xác định {s!r}, đã bỏ qua")
            continue
        if s not in out:
            out.append(s)
    return out or ["outlook"]


def _pick_from_source(source: str) -> str:
    if source == "gptmail":
        from core.gptmail_client import pick_account
        return pick_account().email
    if source == "cloudflare":
        from core.cf_temp_mail_client import pick_account
        return pick_account().email
    if source == "cloudflare_domain":
        from core.qqmail_client import pick_domain_email
        return pick_domain_email()
    if source == "generic_api":
        from core.generic_api_mail_client import pick_account
        return pick_account().email
    if source == "imap":
        from core.imap_mail_client import pick_account
        return pick_account().email
    if source == "mailnest":
        from core.mailnest_client import pick_account
        return pick_account().email
    if source == "cloudmail":
        from core.cloudmail_client import pick_account
        return pick_account().email
    if source == "remail":
        from core.remail_client import pick_account
        return pick_account().email
    from core.outlook_client import pick_account
    return pick_account().email


def acquire_email() -> str:
    "theo EMAIL_SOURCE lấy một email dùng để đăng ký địa chỉ; nhiều nguồn khi theo thứ tự dự phòng. "
    sources = parse_email_sources()
    last_exc: Exception | None = None
    for source in sources:
        try:
            email = _pick_from_source(source)
            logger.info(f"[EmailProvider] dùng nguồn email: {source}, email={email}")
            return email
        except Exception as exc:
            last_exc = exc
            logger.warning(f"[EmailProvider] nguồn {source} lấy email thất bại: {type(exc).__name__}: {exc}")
            continue
    raise RuntimeError(f"mọi nguồn email đều lấy thất bại: {sources}; last={last_exc}")


def acquire_email_from_source(source: str) -> str:
    "từ gọi bên chỉ định đơn nguồn lấy email, không chịu EMAIL_SOURCE dự phòng ảnh hưởng thứ tự. "
    source = str(source or "").strip().lower()
    if source not in _VALID_SOURCES:
        raise ValueError(f"nguồn email không hỗ trợ: {source}")
    email = _pick_from_source(source)
    logger.info("[EmailProvider] lấy email từ nguồn chỉ định: source=%s, email=%s", source, email)
    return email


def acquire_email_after_input(email: str | None = None) -> str:
    "ở trình duyệt đã thấy ô nhập email sau lấy email. \n\n  driver trình duyệt \"tìm đến ô nhập\"và\"lấy email\"tách thành hai giai đoạn, tránh trang tải, kiểm soát rủi ro\n  hoặc nhận diện lối vào thất bại khi nêu trước tiêu thụ email. truyền vào đã có email khi không trùng lấy, tương thích cố định email mẫu kiểu. \n  "
    current = str(email or "").strip()
    if current:
        return current

    from config import email as _email_cfg

    if not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
        raise RuntimeError("trang đã thấy ô nhập email, nhưng tự lấy email chưa bật và chưa cấu hình REGISTER_EMAIL")
    allocated = str(acquire_email() or "").strip()
    if not allocated:
        raise RuntimeError("dịch vụ email trả về địa chỉ email trống")
    logger.info("[EmailProvider] đã thấy ô nhập email, bắt đầu cấp email: %s", allocated)
    return allocated


def resolve_email_source(email: str) -> str:
    "theo email xác định thực tế nguồn, đã đăng ký tài khoản ưu tiên dùng ghi kho nguồn. "
    # 已注册账号的 email_source 是注册时的最终来源。必须先读它，不能因为
    # 当前进程里恰好残留了其它邮箱池上下文，或邮箱池顺序发生变化，就把同一
    # 地址误判到另一个服务商。
    registered_source = _registered_email_source(email)
    if registered_source:
        return registered_source

    from core.gptmail_client import get_account_context as get_gptmail_context
    if get_gptmail_context(email):
        return "gptmail"
    from core.cf_temp_mail_client import get_account_context as get_cf_context
    if get_cf_context(email):
        return "cloudflare"
    from core.mailnest_client import get_account_context as get_mailnest_context
    if get_mailnest_context(email):
        return "mailnest"
    from core.cloudmail_client import get_account_context as get_cloudmail_context
    if get_cloudmail_context(email):
        return "cloudmail"
    from core.remail_client import get_account_context as get_remail_context
    if get_remail_context(email):
        return "remail"

    from core import db
    if db.get_imap_email_by_email(email):
        return "imap"
    if db.get_generic_api_email_by_email(email):
        return "generic_api"
    if db.get_outlook_by_email(email):
        return "outlook"
    if db._find_domain_email(db._load_domain_pool(), email):  # 内部轻量查询，仅本项目使用
        return "cloudflare_domain"
    # 兜底：如果域名匹配 EMAIL_DOMAIN，则按域名邮箱处理
    try:
        from config import email as _email_cfg
        domain = (_email_cfg.EMAIL_DOMAIN or "").lower().strip()
        if domain and domain != "-" and email.lower().endswith("@" + domain):
            return "cloudflare_domain"
    except Exception:
        pass
    return parse_email_sources()[0]


def _normalize_explicit_email_source(value: str | None) -> str | None:
    "chuẩn hoá gọi bên chỉ rõ chỉ định email nguồn. \n\n  đã đăng ký tài khoản  ``email_source`` là đăng ký khi ghi kho đơn nguồn, kiểm tra sống khi nên ưu tiên dùng\n  này giá trị, mà không là lại theo hiện tại tiến trình tạm email trên dưới văn hoặc toàn cục EMAIL_SOURCE đoán. \n  này trong cũng tương thích lịch sử số dữ liệu đôi khi trong lưu phẩy số/phút số phút cách giá trị, lấy trong đó lần một hợp lệ nguồn. \n  "
    if value is None:
        return None
    raw = str(value or "").strip()
    if not raw:
        return None
    for item in raw.replace(";", ",").replace("|", ",").split(","):
        source = str(item or "").strip().strip("\"'").lower()
        if source in _VALID_SOURCES:
            return source
    return None


def _registered_email_source(email: str) -> str | None:
    "đọc đã đăng ký tài khoản ghi kho email nguồn. "
    try:
        from core import db

        account = db.get_account_by_email(email)
    except Exception:
        return None
    return _normalize_explicit_email_source((account or {}).get("email_source"))


def wait_for_otp(
    email: str,
    after_ts: float,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    email_source: str | None = None,
    force_service: bool = False,
) -> str:
    "chờ và trả về này email mới nhất  ChatGPT OTP(6 chữ số số chuỗi ký tự). \n\n  USE_EMAIL_SERVICE=False khi đi thủ công mã OTP kênh(WebUI gửi / CLI nhập), \n  không lại ép yêu cầu Outlook clientId/refreshToken. \n  "
    try:
        from config import email as _email_cfg
        use_service = bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", True))
    except Exception:
        use_service = True

    if not use_service and not force_service:
        from core.manual_otp import wait_for_manual_otp
        from config import email as _email_cfg
        timeout = int(max_wait if max_wait is not None else (getattr(_email_cfg, "OTP_MAX_WAIT", 180) or 180))
        job_id = None
        try:
            from core import registration_service as svc
            job_id = getattr(svc._THREAD_CTX, "job_id", None)
        except Exception:
            job_id = None
        return wait_for_manual_otp(email, timeout=timeout, job_id=job_id)

    extra_kwargs = {}
    if max_wait is not None:
        extra_kwargs["max_wait"] = max_wait
    if poll_interval is not None:
        extra_kwargs["poll_interval"] = poll_interval
    if settle_seconds is not None:
        extra_kwargs["settle_seconds"] = settle_seconds

    # 查活等已注册账号会传入注册时保存的来源；即使调用方没有显式传入，
    # 这里也先读取账号落库来源，再按当前进程上下文/邮箱池/全局配置兜底。
    source = (
        _normalize_explicit_email_source(email_source)
        or _registered_email_source(email)
        or resolve_email_source(email)
    )
    if source == "gptmail":
        from core.gptmail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "cloudflare":
        from core.cf_temp_mail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "cloudflare_domain":
        from core.qqmail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "generic_api":
        from core.generic_api_mail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "imap":
        from core.imap_mail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "mailnest":
        from core.mailnest_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "cloudmail":
        from core.cloudmail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    if source == "remail":
        from core.remail_client import fetch_latest_otp
        return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)
    from core.outlook_client import fetch_latest_otp
    return fetch_latest_otp(email, after_ts=after_ts, **extra_kwargs)


def email_material_line(email: str, source: str | None = None) -> str:
    "trả về tài khoản đổi email sau nên lưu email nguyên liệu dòng. "
    source = _normalize_explicit_email_source(source) or resolve_email_source(email)
    from core import db
    row = None
    if source == "outlook":
        row = db.get_outlook_by_email(email)
    elif source == "generic_api":
        row = db.get_generic_api_email_by_email(email)
    elif source == "imap":
        row = db.get_imap_email_by_email(email)
    if row:
        return str(row.get("copy_line") or email)
    return str(email or "")


def release_email(email: str, status: str = "available", note: str | None = None) -> str:
    "theo email thực tế nguồn thu hồi trạng thái, trả về nguồn tên. "
    source = resolve_email_source(email)
    if source == "gptmail":
        from core.gptmail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "cloudflare":
        from core.cf_temp_mail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "cloudflare_domain":
        from core.qqmail_client import release_domain_email
        release_domain_email(email, status=status, note=note)
    elif source == "generic_api":
        from core.generic_api_mail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "imap":
        from core.imap_mail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "mailnest":
        from core.mailnest_client import release_account
        release_account(email, status=status, note=note)
    elif source == "cloudmail":
        from core.cloudmail_client import release_account
        release_account(email, status=status, note=note)
    elif source == "remail":
        from core.remail_client import release_account
        release_account(email, status=status, note=note)
    else:
        from core.outlook_client import release_account
        release_account(email, status=status, note=note)
    return source


def release_email_if_unconsumed(email: str, note: str | None = None) -> bool:
    "thu hồi vẫn ở lại ở used  tác vụ lấy, và tuyệt không ghi đè đã đăng ký/đã đánh hỏng trạng thái. "
    if not (email or "").strip():
        return False

    source = resolve_email_source(email)
    from core import db

    if source == "outlook":
        changed = db.release_unconsumed_outlook(email, note=note)
    elif source == "generic_api":
        changed = db.release_unconsumed_generic_api_email(email, note=note)
    elif source == "imap":
        changed = db.release_unconsumed_imap_email(email, note=note)
    elif source == "cloudflare_domain":
        changed = db.release_unconsumed_domain_email(email, note=note)
    else:
        # 临时邮箱不重新进入本地池，只清理进程上下文；已有本地账号时保留上下文。
        if db.get_account_by_email(email) is not None:
            return False
        release_email(email, status="available", note=note)
        changed = True

    if changed:
        logger.info("[EmailProvider] đã thu hồi email chưa tiêu thụ: source=%s, email=%s", source, email)
    return changed
